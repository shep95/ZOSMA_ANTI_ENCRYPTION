#!/usr/bin/env python3
"""
Live Shor's algorithm: quantum order-finding on IBM Quantum hardware.

Workflow:
  validate → connect once → preferred bases (bounded attempts) →
  transpile → SamplerV2 on real QPU → continued fractions → factors

Progress events go to stderr as JSON lines; final result is one JSON object on stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from fractions import Fraction
from math import floor, gcd, log
from typing import Any

import numpy as np
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit.circuit.library import UnitaryGate
from qiskit.synthesis.qft import synth_qft_full
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService
from qiskit_ibm_runtime import SamplerV2 as Sampler

MAX_N = 21

# Known-good bases first (IBM tutorial uses a=2 for N=15). Avoids O(|Z_N*|) QPU jobs.
PREFERRED_BASES: dict[int, tuple[int, ...]] = {
    15: (2, 7, 8, 11, 13, 4, 14),
    21: (2, 5, 8, 10, 11, 13, 17, 19),
}


def progress(stage: str, message: str, **fields: Any) -> None:
    """Emit a progress event on stderr (does not pollute stdout JSON)."""
    payload = {"type": "progress", "stage": stage, "message": message, **fields}
    print(json.dumps(payload, separators=(",", ":")), file=sys.stderr, flush=True)


def a2kmodN(a: int, k: int, modulus: int) -> int:
    for _ in range(k):
        a = int((a * a) % modulus)
    return a


def mod_mult_gate(b: int, n: int) -> UnitaryGate:
    if gcd(b, n) != 1:
        raise ValueError(f"gcd({b}, {n}) must be 1 for modular multiplication")
    width = floor(log(n - 1, 2)) + 1
    dim = 2**width
    matrix = np.zeros((dim, dim), dtype=complex)
    for x in range(n):
        matrix[(b * x) % n][x] = 1
    for x in range(n, dim):
        matrix[x][x] = 1
    gate = UnitaryGate(matrix)
    gate.name = f"M_{b}"
    return gate


def m2_mod15() -> QuantumCircuit:
    gate = QuantumCircuit(4)
    gate.swap(2, 3)
    gate.swap(1, 2)
    gate.swap(0, 1)
    return gate.to_gate(label="M_2")


def m4_mod15() -> QuantumCircuit:
    gate = QuantumCircuit(4)
    gate.swap(1, 3)
    gate.swap(0, 2)
    return gate.to_gate(label="M_4")


def controlled_multiplier(b: int, n: int):
    if n == 15 and b == 2:
        return m2_mod15().control()
    if n == 15 and b == 4:
        return m4_mod15().control()
    if b == 1:
        return None
    return mod_mult_gate(b, n).control()


def build_order_finding_circuit(a: int, n: int) -> QuantumCircuit:
    num_target = floor(log(n - 1, 2)) + 1
    num_control = 2 * num_target
    b_list = [a2kmodN(a, k, n) for k in range(num_control)]

    control = QuantumRegister(num_control, "phase")
    target = QuantumRegister(num_target, "work")
    output = ClassicalRegister(num_control, "out")
    circuit = QuantumCircuit(control, target, output, name=f"shor_order_{n}")

    circuit.x(num_control)

    for k, qubit in enumerate(control):
        circuit.h(qubit)
        gate = controlled_multiplier(b_list[k], n)
        if gate is None:
            continue
        circuit.compose(gate, qubits=[qubit, *target], inplace=True)

    circuit.compose(synth_qft_full(num_control, inverse=True), qubits=control, inplace=True)
    circuit.measure(control, output)
    return circuit


def factors_from_order(a: int, n: int, order: int) -> tuple[int, int] | None:
    if order <= 0 or order % 2 != 0:
        return None
    x = pow(a, order // 2, n)
    if x in (1, n - 1):
        return None
    for candidate in (gcd(x - 1, n), gcd(x + 1, n)):
        if 1 < candidate < n and n % candidate == 0:
            other = n // candidate
            return (min(candidate, other), max(candidate, other))
    return None


def recover_factors_from_counts(
    counts: dict[str, int],
    *,
    a: int,
    n: int,
    num_control: int,
) -> dict[str, Any]:
    total = sum(counts.values()) or 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    candidates: list[dict[str, Any]] = []

    for bitstring, count in ranked:
        phase = int(bitstring, 2) / (2**num_control)
        if phase == 0:
            continue
        rational = Fraction(phase).limit_denominator(n)
        order = rational.denominator
        factors = factors_from_order(a, n, order)
        entry = {
            "bitstring": bitstring,
            "count": int(count),
            "probability": count / total,
            "phase": phase,
            "rational_phase": f"{rational.numerator}/{rational.denominator}",
            "order": order,
            "factors": list(factors) if factors else None,
        }
        candidates.append(entry)
        if factors:
            return {
                "p": factors[0],
                "q": factors[1],
                "order": order,
                "base": a,
                "best_sample": entry,
                "top_candidates": candidates[:8],
            }

    raise RuntimeError(
        "Quantum run completed but no usable period was recovered from the phase histogram. "
        "Retry the job (Shor's algorithm is probabilistic)."
    )


def connect_service() -> QiskitRuntimeService:
    token = os.environ.get("IBM_QUANTUM_TOKEN") or os.environ.get("QISKIT_IBM_TOKEN")
    channel = os.environ.get("IBM_QUANTUM_CHANNEL", "ibm_quantum_platform")
    instance = os.environ.get("IBM_QUANTUM_INSTANCE")

    kwargs: dict[str, Any] = {"channel": channel}
    if token:
        kwargs["token"] = token
    if instance:
        kwargs["instance"] = instance

    try:
        return QiskitRuntimeService(**kwargs)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "Failed to connect to IBM Quantum. "
            "Set IBM_QUANTUM_TOKEN from https://quantum.cloud.ibm.com/ "
            f"Details: {exc}"
        ) from exc


def extract_counts(pub_result: Any) -> dict[str, int]:
    data = pub_result.data
    if hasattr(data, "out"):
        return dict(data.out.get_counts())
    if isinstance(data, dict) and "out" in data:
        return dict(data["out"].get_counts())
    register = next(iter(data.values()))
    return dict(register.get_counts())


def run_on_hardware(
    service: QiskitRuntimeService,
    a: int,
    n: int,
    *,
    shots: int,
    backend_name: str | None,
    optimization_level: int,
    attempt: int,
) -> dict[str, Any]:
    progress("build", f"Building order-finding circuit for a={a}, N={n}", attempt=attempt, base=a)
    circuit = build_order_finding_circuit(a, n)

    progress("backend", "Selecting real IBM Quantum backend", attempt=attempt)
    if backend_name:
        backend = service.backend(backend_name)
    else:
        backend = service.least_busy(
            operational=True,
            simulator=False,
            min_num_qubits=circuit.num_qubits,
        )

    progress(
        "transpile",
        f"Transpiling for {backend.name}",
        attempt=attempt,
        backend=backend.name,
    )
    pass_manager = generate_preset_pass_manager(
        backend=backend,
        optimization_level=optimization_level,
    )
    transpiled = pass_manager.run(circuit)

    progress(
        "submit",
        f"Submitting SamplerV2 job ({shots} shots)",
        attempt=attempt,
        backend=backend.name,
    )
    sampler = Sampler(mode=backend)
    sampler.options.dynamical_decoupling.enable = True
    sampler.options.dynamical_decoupling.sequence_type = "XpXm"
    sampler.options.twirling.enable_gates = True

    job = sampler.run([transpiled], shots=shots)
    job_id = job.job_id()
    progress(
        "queue",
        "Waiting for QPU result (queue time varies)",
        attempt=attempt,
        backend=backend.name,
        jobId=job_id,
    )

    pub_result = job.result()[0]
    counts = extract_counts(pub_result)

    progress("postprocess", "Recovering order via continued fractions", attempt=attempt, jobId=job_id)
    recovered = recover_factors_from_counts(
        counts,
        a=a,
        n=n,
        num_control=circuit.num_clbits,
    )

    return {
        "p": recovered["p"],
        "q": recovered["q"],
        "n": n,
        "base": a,
        "order": recovered["order"],
        "backend": backend.name,
        "job_id": job_id,
        "shots": shots,
        "mode": "ibm_quantum_hardware",
        "num_qubits": circuit.num_qubits,
        "transpiled_depth": transpiled.depth(),
        "best_sample": recovered["best_sample"],
        "top_candidates": recovered["top_candidates"],
        "counts": {k: int(v) for k, v in counts.items()},
        "attempt": attempt,
    }


def ordered_bases(n: int) -> list[int]:
    preferred = PREFERRED_BASES.get(n, ())
    seen: set[int] = set()
    ordered: list[int] = []
    for a in preferred:
        if 1 < a < n and gcd(a, n) == 1 and a not in seen:
            ordered.append(a)
            seen.add(a)
    for a in range(2, n):
        if gcd(a, n) == 1 and a not in seen:
            ordered.append(a)
            seen.add(a)
    return ordered


def is_auth_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return any(token in message for token in ("ibm quantum", "account", "token", "401", "403", "unauthorized"))


def is_transient(exc: BaseException) -> bool:
    message = str(exc).lower()
    return any(token in message for token in ("timeout", "temporar", "503", "429", "queue", "connection"))


def shors_factor(
    n: int,
    *,
    shots: int,
    backend_name: str | None,
    optimization_level: int,
    max_attempts: int,
) -> dict[str, Any]:
    # Cheap guards before any network I/O.
    if n <= 1:
        raise ValueError("n must be > 1")
    if n % 2 == 0:
        return {
            "p": 2,
            "q": n // 2,
            "n": n,
            "base": None,
            "order": None,
            "backend": None,
            "job_id": None,
            "shots": 0,
            "mode": "trivial_even",
            "note": "Even modulus factored classically (Shor step 0).",
        }
    if n > MAX_N:
        raise ValueError(
            f"N={n} exceeds live-hardware limit ({MAX_N}). "
            "Current IBM Quantum order-finding demos target tiny moduli (e.g. 15)."
        )
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    bases = ordered_bases(n)[:max_attempts]
    if not bases:
        raise ValueError(f"No coprime bases found for n={n}")

    progress("auth", "Connecting to IBM Quantum (once)")
    service = connect_service()

    last_error: Exception | None = None
    for attempt, a in enumerate(bases, start=1):
        try:
            result = run_on_hardware(
                service,
                a,
                n,
                shots=shots,
                backend_name=backend_name,
                optimization_level=optimization_level,
                attempt=attempt,
            )
            if result["p"] * result["q"] == n:
                progress("done", f"Factored N={n} into ({result['p']}, {result['q']})", attempt=attempt)
                return result
        except Exception as exc:  # noqa: BLE001
            if is_auth_error(exc):
                raise
            last_error = exc
            progress(
                "retry",
                f"Attempt {attempt}/{len(bases)} failed: {exc}",
                attempt=attempt,
                retryable=is_transient(exc),
            )
            # Brief backoff only for transient fleet errors (idempotent resubmit of a new job).
            if is_transient(exc) and attempt < len(bases):
                time.sleep(min(2**attempt, 8))
            continue

    raise RuntimeError(
        f"Failed to factor {n} on live hardware after {len(bases)} attempt(s)."
        + (f" Last error: {last_error}" if last_error else "")
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Factor N with live Shor's algorithm on IBM Quantum.")
    parser.add_argument("--n", type=int, required=True, help="Odd composite modulus to factor")
    parser.add_argument("--shots", type=int, default=1024, help="Sampler shots (default 1024)")
    parser.add_argument("--backend", default=None, help="IBM backend name (default: least busy real QPU)")
    parser.add_argument("--optimization-level", type=int, default=2, choices=(0, 1, 2, 3))
    parser.add_argument("--max-attempts", type=int, default=2, help="Max QPU base attempts (default 2)")
    parser.add_argument("--correlation-id", default=None, help="Correlation id from the control plane")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only on stdout")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.correlation_id:
        progress("start", "Quantum engine started", correlationId=args.correlation_id)

    try:
        result = shors_factor(
            args.n,
            shots=args.shots,
            backend_name=args.backend,
            optimization_level=args.optimization_level,
            max_attempts=args.max_attempts,
        )
        if args.correlation_id:
            result["correlation_id"] = args.correlation_id
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1) from exc

    print(json.dumps(result))


if __name__ == "__main__":
    main()
