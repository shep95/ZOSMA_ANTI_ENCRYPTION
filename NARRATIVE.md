# Narrative: Breaking Toy RSA with Shor’s Algorithm

This project is an educational walkthrough of how public-key RSA can be broken once you can factor its modulus. The original notebooks told that story with Python, Jupyter, and a Qiskit circuit. This document is that story in plain language; the TypeScript code is the same story made runnable.

## Act 1 — Build a small RSA lock

RSA security rests on a product of two secret primes, `N = p × q`.

1. Choose a small bit length (the notebooks used values like 4, which yields a tiny modulus suitable for demos only).
2. Pick two primes `p` and `q` in the right size range and form `N = p × q`.
3. Compute Euler’s totient `φ(N) = (p − 1)(q − 1)`.
4. Choose a public exponent `e` that is coprime to `φ(N)`.
5. Compute the private exponent `d` as the modular inverse of `e` modulo `φ(N)`.

The public key is `(e, N)`. The private key is `(d, N)`. Anyone may encrypt with the public key; only someone who knows `d` (or who can recover `p` and `q`) can decrypt.

## Act 2 — Lock a message

Encryption is character-wise modular exponentiation:

- For each character `c` in the plaintext, compute `c^e mod N`.
- The list of those numbers is the ciphertext.

With the legitimate private key, decryption is the inverse:

- For each ciphertext number `x`, compute `x^d mod N` and turn it back into a character.

At this point the system works as intended: encrypt with public, decrypt with private.

## Act 3 — Attack the lock by factoring `N`

An attacker does not have `d`. They only see the public key `(e, N)` and the ciphertext.

Shor’s algorithm attacks RSA by factoring `N`:

1. Pick a random base `a` in `1 … N − 1`.
2. If `gcd(a, N)` is not 1, that gcd is already a nontrivial factor — done.
3. Otherwise find the **period** (order) `r` of `a` modulo `N`: the smallest positive `r` such that `a^r ≡ 1 (mod N)`.
4. If `r` is even and `a^(r/2) ≢ −1 (mod N)`, then:
   - `p = gcd(a^(r/2) + 1, N)`
   - `q = gcd(a^(r/2) − 1, N)`
   are nontrivial factors of `N`.
5. Retry with a new `a` when the period is unusable.

On a large quantum computer, period finding is the quantum step. For this educational codebase we implement the **same classical control flow**, with period finding done classically. That is correct for small demo moduli and keeps the project runnable without a quantum backend.

## Act 4 — Forge the private key and read the message

Once `p` and `q` are known:

1. Recompute `φ(N) = (p − 1)(q − 1)`.
2. Recover `d = e⁻¹ mod φ(N)` from the public exponent alone.
3. Decrypt the ciphertext with `(d, N)` exactly as the legitimate owner would.

The message is recovered without ever seeing the original private key.

## What the TypeScript program does

The CLI follows the notebook path end to end:

1. Generate a toy RSA keypair.
2. Encrypt a message.
3. Decrypt it with the real private key (sanity check).
4. Factor `N` with Shor’s factoring procedure.
5. Recover `d` from the factors and the public `e`.
6. Decrypt the same ciphertext with the recovered key (the “crack”).

This is a teaching demo, not a cryptanalytic tool. Real RSA uses moduli far larger than anything classical period finding can handle here.
