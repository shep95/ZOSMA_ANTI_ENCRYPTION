# Narrative: Live RSA break with Shor’s algorithm

This project is a **live** cryptanalysis lab. It uses real RSA arithmetic and a real Shor order-finding circuit submitted to **IBM Quantum hardware**. Nothing in the attack path is classical period-finding theater or a fake quantum stub.

## Act 1 — Build a hardware-scale RSA lock

Current public QPUs can run order-finding only for **tiny** moduli (IBM’s reference demo factors **15**). The lab therefore uses live-capable RSA moduli:

- `N = 15 = 3 × 5`
- `N = 21 = 3 × 7`

The key holder picks secret primes `p` and `q`, forms `N = p × q`, chooses public `e` coprime to `φ(N)`, and computes private `d = e⁻¹ mod φ(N)`.

The public key `(e, N)` is published. The private key `(d, N)` is not.

## Act 2 — Lock a message with real RSA

Messages are encoded as base-`N` digits (so any UTF-8 text works even when `N = 15`), then each digit `m` is encrypted with real modular exponentiation:

```text
c = m^e mod N
```

Decryption with the legitimate key is the inverse:

```text
m = c^d mod N
```

## Act 3 — Factor `N` on a live QPU

An attacker sees only `(e, N)` and the ciphertext. They run **Shor’s algorithm**:

1. Pick a base `a` coprime to `N`.
2. Build a **quantum phase-estimation** circuit whose unitary is modular multiplication by powers of `a` modulo `N`.
3. Apply the inverse QFT and measure the phase register.
4. Submit that circuit to an **IBM Quantum** backend via Qiskit Runtime `SamplerV2` (dynamical decoupling + gate twirling enabled).
5. Classically post-process the measured phases with continued fractions to recover the order `r`.
6. Compute `gcd(a^(r/2) ± 1, N)` to obtain nontrivial factors `p` and `q`.

The quantum engine lives in `quantum/shor_live.py`. TypeScript orchestrates the attack and never substitutes classical order-finding for the QPU step.

## Act 4 — Forge `d` and read the message

From the factors:

```text
φ(N) = (p − 1)(q − 1)
d = e⁻¹ mod φ(N)
```

Decrypt the ciphertext with the forged private key. The plaintext is recovered without the original `d`.

## What “live” means here

| Component | Implementation |
| --- | --- |
| RSA math | Real modular exponentiation over integers |
| Order finding | Real QPE circuit (compiled gates for `N=15`, unitary modular multiply otherwise) |
| Execution | IBM Quantum hardware through Qiskit Runtime |
| Post-processing | Continued fractions + gcd (classical, as in Shor’s paper) |

This is still a **lab-scale** demonstration. Fault-tolerant machines large enough to break production RSA do not exist yet; the algorithm and the hardware path are real, the modulus is necessarily tiny.
