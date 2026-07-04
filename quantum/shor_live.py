#!/usr/bin/env python3
"""
Live Shor's algorithm: quantum order-finding on IBM Quantum hardware.

Builds a real phase-estimation circuit with modular-multiplication unitaries,
transpiles to a physical backend, runs SamplerV2 on hardware, then recovers
factors classically from the measured phase (continued fractions).

Requires IBM Quantum credentials:
  export IBM_QUANTUM_TOKEN=<token>
  # optional: IBM_QUANTUM_CHANNEL (default: ibm_quantum_platform)
  # optional: IBM_QUANTUM_INSTANCE
"""

from __future__ import annotations

import argparse
import json
import os
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

# NISQ-era order-finding is only practical for tiny moduli.
MAX_N = 21


def a2kmodN(a: int, k: int, modulus: int) -> int:
    for _ in range(k):
        a = int((a * a) % modulus)
    return a


def mod_mult_gate(b: int, n: int) -> UnitaryGate:
    """Unitary for |x> -> |b*x mod N> on ceil(log2(N)) qubits."""
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
    """Hardware-friendly compiled gates for N=15; unitary synthesis otherwise."""
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

    # Work register starts in |1>, the standard order-finding input.
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
    total = sum(counts.values())
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    candidates: list[dict[str, Any]] = []

    for bitstring, count in ranked:
        phase = int(bitstring, 2) / (2**num_control)
        if phase == 0:
            continue
        rational = Fraction(phase).limit_denominator(n)
        order = rational.denominator
        factors = factors_from_order(a, n, order)
        candidates.append(
            {
                "bitstring": bitstring,
                "count": int(count),
                "probability": count / total,
                "phase": phase,
                "rational_phase": f"{rational.numerator}/{rational.denominator}",
                "order": order,
                "factors": list(factors) if factors else None,
            }
        )
        if factors:
            return {
                "p": factors[0],
                "q": factors[1],
                "order": order,
                "base": a,
                "best_sample": candidates[-1],
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
    except Exception as exc:  # noqa: BLE001 - surface auth errors to CLI
        raise RuntimeError(
            "Failed to connect to IBM Quantum. "
            "Set IBM_QUANTUM_TOKEN to your API token from https://quantum.cloud.ibm.com/ "
            f"Details: {exc}"
        ) from exc


def run_on_hardware(
    a: int,
    n: int,
    *,
    shots: int,
    backend_name: str | None,
    optimization_level: int,
) -> dict[str, Any]:
    circuit = build_order_finding_circuit(a, n)
    service = connect_service()

    if backend_name:
        backend = service.backend(backend_name)
    else:
        backend = service.least_busy(
            operational=True,
            simulator=False,
            min_num_qubits=circuit.num_qubits,
        )

    pass_manager = generate_preset_pass_manager(
        backend=backend,
        optimization_level=optimization_level,
    )
    transpiled = pass_manager.run(circuit)

    sampler = Sampler(mode=backend)
    sampler.options.dynamical_decoupling.enable = True
    sampler.options.dynamical_decoupling.sequence_type = "XpXm"
    sampler.options.twirling.enable_gates = True

    job = sampler.run([transpiled], shots=shots)
    pub_result = job.result()[0]

    # SamplerV2 stores classical register data by name.
    data = pub_result.data
    if hasattr(data, "out"):
        counts = dict(data.out.get_counts())
    elif "out" in data:
        counts = dict(data["out"].get_counts())
    else:
        # Fallback: first available register
        register = next(iter(data.values()))
        counts = dict(register.get_counts())

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
        "job_id": job.job_id(),
        "shots": shots,
        "mode": "ibm_quantum_hardware",
        "num_qubits": circuit.num_qubits,
        "transpiled_depth": transpiled.depth(),
        "best_sample": recovered["best_sample"],
        "top_candidates": recovered["top_candidates"],
        "counts": {k: int(v) for k, v in counts.items()},
    }


def shors_factor(n: int, *, shots: int, backend_name: str | None, optimization_level: int) -> dict[str, Any]:
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

    # Prefer coprime bases so the live QPU order-finding circuit always runs.
    # (A random gcd hit is a valid Shor branch, but skips the quantum step.)
    bases = [a for a in range(2, n) if gcd(a, n) == 1]
    np.random.default_rng().shuffle(bases)
    if not bases:
        raise ValueError(f"No coprime bases found for n={n}")

    last_error: Exception | None = None
    for a in bases:
        try:
            result = run_on_hardware(
                a,
                n,
                shots=shots,
                backend_name=backend_name,
                optimization_level=optimization_level,
            )
            if result["p"] * result["q"] == n:
                return result
        except Exception as exc:  # noqa: BLE001 - try next base / surface later
            message = str(exc).lower()
            # Auth / account problems will not improve with another base.
            if "ibm quantum" in message or "account" in message or "token" in message:
                raise
            last_error = exc
            continue

    raise RuntimeError(
        f"Failed to factor {n} on live hardware after trying coprime bases."
        + (f" Last error: {last_error}" if last_error else "")
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Factor N with live Shor's algorithm on IBM Quantum.")
    parser.add_argument("--n", type=int, required=True, help="Odd composite modulus to factor")
    parser.add_argument("--shots", type=int, default=4096, help="Sampler shots")
    parser.add_argument("--backend", default=None, help="IBM backend name (default: least busy)")
    parser.add_argument("--optimization-level", type=int, default=2, choices=(0, 1, 2, 3))
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        result = shors_factor(
            args.n,
            shots=args.shots,
            backend_name=args.backend,
            optimization_level=args.optimization_level,
        )
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1) from exc

    print(json.dumps(result))


if __name__ == "__main__":
    main()
