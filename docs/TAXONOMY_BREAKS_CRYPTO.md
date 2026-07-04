# How the flaw taxonomy breaks encryption narratives

Encryption algorithms assume a **correct surrounding workflow**. The CODE_NARRATIVE_PROTOCOL taxonomy does not “solve AES”; it finds the **implementation and orchestration failures** that void cryptographic promises.

Below: for each encryption layer narrative, which taxonomy micro-domains **break the security story**.

---

## Break narrative (meta)

1. Crypto paper promises security under assumptions (secret key, unique nonce, trusted RNG, correct padding, verified identity).
2. Software implements a **workflow** around that math (APIs, state machines, caches, JWTs, DB rows, UI).
3. Taxonomy flaws corrupt the workflow → assumptions fail → ciphertext is readable, forgeable, or replayable **without** breaking the mathematical primitive.

That is the attack surface ZOSMA’s audit engine encodes.

---

## Layer-by-layer breaks

### OTP / perfect secrecy

| Taxonomy | Break |
| --- | --- |
| 4.6 Secrets & crypto | Key from `Math.random`, key logged, key in URL |
| 1.2 Idempotency | “Retry” reuses the same pad |
| 9.1 Realism | Demo pad presented as production OTP |

### Block/stream ciphers & AEAD

| Taxonomy | Break |
| --- | --- |
| 4.6 AEAD only / IV never reused | CTR/GCM nonce reuse → total break |
| 2.4 Numbers | Counter overflow, 32-bit IV space |
| 3 Async / races | Two requests mint the same nonce |
| 5.2 Cache | Cached plaintext after failed tag verify |
| 7.1 Timeout/retry | Non-idempotent encrypt retried → nonce reuse |
| 4.5 Rendering | Decrypt error messages leak padding (oracle) |

### Hashes / MACs / KDFs

| Taxonomy | Break |
| --- | --- |
| 4.6 argon2id | MD5 password “hash” |
| 2.3 Immutability | Salt overwritten in shared buffer |
| 3 Timing | Early-exit tag compare |
| 9.3 Logging | Password or MAC key in logs |

### RSA / ECC / classical PKI

| Taxonomy | Break |
| --- | --- |
| 4.6 Weak crypto | Textbook RSA, PKCS#1 v1.5 oracles |
| 4.3 IDOR / RLS | Private key row readable cross-tenant |
| 1.1 State machines | Handshake skips cert verify state |
| **Quantum (Shor)** | Factors `N` or solves DL — ZOSMA live path for toy RSA |
| 7.2 JWT | `alg` confusion, missing `aud`/`iss`/`exp` |

### KEM + hybrid (TLS 1.3 / PQ migration)

| Taxonomy | Break |
| --- | --- |
| 1.1 Missing error/cancel edges | Downgrade continues on PQ failure |
| 1.2 Compensation | Failed handshake leaves session keys in memory |
| 4.4 SSRF | Cert/OCSP fetch to metadata IP |
| 7.1 Missing timeout | Hang on handshake = availability DoS |
| 9.4 No degradation flag | Hard fail vs safe classical-only policy misconfigured |

### Password & tokens

| Taxonomy | Break |
| --- | --- |
| 4.6 | JWT secret = weak string; `alg=none` accepted |
| 4.3 AuthZ | `has_role` via email allow-list |
| 5.1 Lost updates | Token revocation race |
| 7.5 Rate limit | Online password spray unbounded |

---

## Taxonomy dimensions as crypto-break tools

### (1) Workflow & orchestration

Incomplete handshake state machines, missing timeout→abort, non-idempotent key-delivery retries, no compensation for partial key rotation → **sessions without FS, keys left on disk, downgrade**.

### (2) Code logic

Off-by-one in ciphertext length, coercion of key material to number, mutation of shared IV buffer, wrong timezone on `exp` checks → **auth bypass or reject-all**.

### (3) Bug-class

Null key handle, unhandled rejection skipping verify, race minting nonces, integer overflow on counter → **AEAD collapse**.

### (4) Security

Injection into key stores, prompt injection into agents that export keys, IDOR on `/keys/:id`, SSRF on JWKS URL, XSS stealing tokens, missing AEAD, no argon2id, bad JWT claims, unsafe pickle of key blobs.

### (5) Concurrency & data

Lost updates on key rotation, cache serving old public keys after revoke, schema drift on key tables, N+1 on ACL checks skipped under load.

### (6) Performance

Skipping verify “to go faster”, batching that drops MAC checks, main-thread crypto with truncated iterations.

### (7) API/network

No TLS timeout, retry POST `/encrypt` (nonce reuse), ignore non-2xx from KMS, no schema validate on JWK, CORS `*`, no rate limit on `/login`.

### (8) UI/UX

Error text as padding oracle, no focus trap on secret modal, clipboard leaks; palette catalog is **orthogonal** (only activates on explicit style cues — never part of crypto breaks).

### (9) Realism & observability

Mocks labeled “live KMS”, no correlation id on key ops, secrets in logs, no alarm on verify-fail spikes.

---

## New narrative (ZOSMA audit engine)

ZOSMA is not “all crypto is broken.” ZOSMA is:

1. **Catalog** every operational encryption level and its required workflow.
2. **Map** taxonomy micro-domains onto breaks of that workflow.
3. **Audit** a target profile (algorithm, mode, key lifecycle claims) and emit **findings or explicit n/a**.
4. **Live demonstrate** only the quantum-breakable class (toy RSA via Shor) where hardware allows.

Silence is not evidence: every check emits `finding` or `n/a — reason`.
