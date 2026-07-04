# AES-256-GCM bypass vectors (implemented)

Maps the protection narrative’s failure modes to runnable demos in `src/crypto/high-asset/gcm-bypass.ts`.

| # | Vector | What the code does |
| --- | --- | --- |
| 1 | Nonce reuse (Forbidden Attack) | Same key+nonce for beacon + secret; recover secret via `C⊕P` keystream cancel |
| 2 | Compromised key | Exfiltrated key opens GCM box (all guarantees collapse) |
| 3a | Release-before-verify | Vulnerable open returns bytes despite invalid tag; hardened blocks |
| 3b | Non-constant-time tag compare | Early-return compare leaks matching prefix length |
| 3c | Stale buffer after tag fail | Plaintext left in memory; hardened zeroizes |
| 4 | Tag truncation | 8-bit tag forged in few random tries |
| 5 | Data limits | Flag >64 GiB under one nonce; within-bounds is not a bypass |
| 6 | AAD mismanagement | Seal without AAD bind ⇒ validates in any context |
| 7 | Library misuse | Hardcoded IV reuse recovers second plaintext |

```bash
npm run gcm-bypass
```

Hardened AES-256-GCM (unique nonce, secret key, full tag, verify-then-decrypt, AAD bind) is **not** broken by these demos unless a narrative rule is violated first.
