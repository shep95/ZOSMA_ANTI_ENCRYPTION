# AES-256-GCM security narrative (why blind break fails)

This matches NIST SP 800-38D / AEAD practice for high-asset data protection.

## Promise

Under a **uniform random 256-bit key** and a **never-reused 96-bit nonce** (per key):

1. **Confidentiality** — ciphertext does not reveal plaintext (IND-CPA style goal for the mode).
2. **Integrity / authenticity** — any change to ciphertext, nonce, AAD, or tag fails verification (INT-CTXT).
3. **Verify-then-decrypt** — implementations must not release plaintext if the tag check fails.

## Required workflow

```text
key ← random 256-bit (HSM/KMS)
nonce ← unique per seal under that key
AAD ← bind tenant/object identity
(C, T) ← AES-GCM-Encrypt(key, nonce, AAD, P)
store/transmit (nonce, AAD, C, T) — never the key

On open:
  if AES-GCM-Decrypt(key, nonce, AAD, C, T) fails → reject
  else → return P
```

## What a blind attacker has

Only public fields: `nonce`, `AAD`, `C`, `T`. **Not** the key.

## Attack surface vs narrative (why each fails)

| Attack | Needs | Outcome when narrative holds |
| --- | --- | --- |
| Exhaustive key search | Try 2^256 keys | Infeasible classically (and ~2^128 with Grover — still infeasible) |
| Nonce-reuse keystream cancel | Two ciphertexts, same key+nonce, known plaintext for one | **Blocked** if every nonce is unique |
| Tag forgery / bit-flip | Accept tampered `(C,T)` | **Blocked** by 128-bit tag verify |
| Decrypt with wrong/zero/random key | Any incorrect key | Tag check fails; plaintext withheld |
| Padding oracle | Distinct error channels | GCM has no padding; fail-closed single error |
| Shor / factoring | RSA/ECC modulus | **N/A** — AES is symmetric, not factoring-based |

## Code mapping

`src/blind/gcm-narrative.ts` encodes this narrative and runs each check against public challenge blobs. Status `failed` with per-check evidence means the **security narrative held**.
