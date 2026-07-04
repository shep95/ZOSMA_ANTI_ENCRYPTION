# AES-256-GCM — bypasses beyond algorithm scope

When GCM is implemented perfectly, **classical cryptanalysis of the algorithm is considered infeasible**. This lab tests the theory that data can still be lost through **context outside** AES-256-GCM.

| Vector | Class | Demo |
| --- | --- | --- |
| `0.control-public-blob-only` | Control | Public `(nonce,AAD,C,T)` alone cannot open |
| `1.side-channel-cache-timing` | Side channel | Key recovered via secret-dependent access oracle |
| `1b.side-channel-power-em-model` | Side channel | Key recovered via leakage model |
| `2.quantum-grover-keyspace` | Quantum | Effective search 2^256 → 2^128 |
| `3a/b/c.compromised-env-*` | Hostile host | Pre-encrypt scrape, key-in-RAM, post-decrypt exfil |
| `4a/b.weak-rng-*` | Bad entropy | Predictable nonce → Forbidden Attack; predictable key |
| `5a/b.human-*` | Human | Insider key export; key stored beside ciphertext |

```bash
npm run gcm-beyond
```

Power/EM/cache are **software models** of the attack class (not lab oscilloscopes). Grover is a **keyspace model**, not a live cryptographically relevant quantum computer.
