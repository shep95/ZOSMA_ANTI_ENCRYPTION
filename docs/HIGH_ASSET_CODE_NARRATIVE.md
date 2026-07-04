# Code narrative — high-asset flaw lab (post-check)

## Intent

Implement **workable** demonstrations that the CODE_NARRATIVE_PROTOCOL taxonomy breaks **high-asset encryption workflows**, without claiming a mathematical break of AES-256.

## Components

| Module | Role |
| --- | --- |
| `levels.ts` | HA-1…HA-9 tiers, promises, workflows |
| `breaks.ts` | Taxonomy micro-domain → control id edges |
| `aead.ts` | Real AES-256-GCM; `NonceVault`; fail-closed open |
| `flaw-lab.ts` | Broken vs hardened labs + self-test |
| `audit.ts` | Profile audit (`broken` / `hardened`) |
| `high-asset-cli.ts` | Operator surface |

## Hardened controls (new narrative)

1. **nonce_vault** — counter + actor/op domain separation; exhaustion throws; no random-UUID-only nonces.
2. **aead_only** — only `aes-256-gcm` seal/open paths.
3. **verify_then_decrypt** — auth failure throws `aead_verify`; no plaintext return.
4. **aad_tenant_bind** — AAD mismatch fails closed.
5. **idempotent_seal** — `idempotencyKey(actor, op, input hash)`.
6. **secret_scrub** — logger never receives key material.
7. **fail_closed** — errors do not disable encryption.

## Broken demonstrations (taxonomy attack narrative)

1. **Nonce reuse** — AES-CTR family under same key+nonce yields `C1⊕C2 = P1⊕P2`.
2. **Shared counter reset** — `BrokenSharedNonceVault` collides nonces.
3. **Tampered tag** — hardened open withholds plaintext.

## Self-test gate

`npm run high-asset -- self-test` must PASS all labs before release. Silence is not evidence.

## Explicit non-goals

- Recovering AES-256 keys
- Breaking ML-KEM/ML-DSA mathematics
- Treating toy RSA Shor demo as HA-1 compromise
