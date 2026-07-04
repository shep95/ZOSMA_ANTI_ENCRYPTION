# Hardest encryption levels protecting high-value assets

These are the stacks used for **banks, governments, critical infrastructure, payments, and sovereign systems**. Mathematical break cost is astronomical when workflows are correct. Real compromise almost always comes from **taxonomy flaws in the surrounding workflow**, not from inverting AES-256.

---

## Tier HA-1 — AES-256-GCM in an HSM (data at rest / in use)

**Where:** Payment cores, government archives, cloud KMS customer master keys, database TDE.

**Promise:** Confidentiality + authenticity; key never leaves hardware boundary (FIPS 140-3 L3/L4).

**Workflow:**
1. Generate AES-256 inside HSM / KMS.
2. Enforce roles (crypto officer vs user).
3. Unique 96-bit nonce per seal (or AES-GCM-SIV misuse resistance).
4. AAD binds ciphertext to tenant/object id.
5. Tag verified before plaintext release.
6. Key rotation with dual-control; old key decrypt-only window.
7. Audit every use; zeroize on decommission.

**Hardness:** Brute force 2^256 (Grover → ~2^128 quantum — still infeasible). No practical classical cryptanalysis of AES-256.

---

## Tier HA-2 — ChaCha20-Poly1305 (high-speed AEAD)

**Where:** WireGuard, QUIC stacks, mobile VPNs, CDN edges.

**Promise:** Same AEAD goals; software-friendly on CPUs without AES-NI.

**Workflow:** Key + unique 96-bit nonce → ChaCha20 keystream → Poly1305 tag over AAD+ciphertext → verify-then-decrypt.

**Hardness:** Same class as AES-GCM when nonces are unique.

---

## Tier HA-3 — Hybrid TLS 1.3 (X25519 + ML-KEM) traffic protection

**Where:** Banking APIs, government portals, “harvest-now-decrypt-later” resistant links.

**Promise:** Authenticated key exchange with forward secrecy; classical + post-quantum KEM.

**Workflow:**
1. ClientHello offers hybrid groups.
2. Server authenticates (RSA-PSS/ECDSA today, ML-DSA in migration).
3. Shared secrets from ECDH **and** ML-KEM combined via transcript KDF.
4. Traffic keys drive AEAD records.
5. Session tickets short-lived; ticket keys in HSM.

**Hardness:** Attacker must break **both** ECDH and ML-KEM (or implementation). Shor alone is insufficient if hybrid is enforced.

---

## Tier HA-4 — ML-DSA / SLH-DSA code & document signing

**Where:** Firmware, court documents, software updates, PKI roots in migration.

**Promise:** Unforgeable signatures against quantum adversaries (design goal).

**Workflow:** KeyGen in HSM → sign hash → distribute public key via cert chain → verify before install/trust.

---

## Tier HA-5 — Payment HSM / PIN security (PCI)

**Where:** Card PIN translation, CVV, key injection.

**Promise:** PIN and key blocks never appear in host memory in clear.

**Workflow:** Encrypted PIN block → HSM translate under LMK/ZMK hierarchy → response MACed → dual control for key load.

---

## Tier HA-6 — Secure element / smart card / TPM-bound keys

**Where:** Passkeys, disk encryption (BitLocker/LUKS+TPM), national ID cards.

**Promise:** Private keys non-exportable; unlock requires PCR policy / PIN / biometrics.

**Workflow:** Generate in SE → seal data to PCR state → unseal only if measurements match → rate-limited auth.

---

## Tier HA-7 — Multi-party / threshold keys (MPC, Shamir, multi-sig)

**Where:** Crypto asset custody, root CA ceremonies, nuclear/command continuity analogs in civilian form (split control).

**Promise:** No single operator can use the key alone.

**Workflow:** DKG → threshold sign/decrypt → audit each share use → revoke share without rotating full key when possible.

---

## Tier HA-8 — CNSA 2.0 / national algorithm suites

**Where:** Classified and national-security systems (policy allow-lists).

**Promise:** Only approved PQ-ready algorithms and key sizes.

**Workflow:** Configuration baseline → continuous compliance scan → block non-suite algs.

---

## Tier HA-9 — Double Ratchet / messaging (Signal protocol class)

**Where:** High-risk human communications.

**Promise:** Forward secrecy + post-compromise security for messages.

**Workflow:** X3DH/PQXDH session → per-message chain keys → AEAD → ratchet on send/receive.

---

## Universal high-asset narrative

```text
hardware root of trust
  → non-exportable keys
  → AEAD or KEM+AEAD (hybrid PQ)
  → identity binding (certs / PQ signatures)
  → dual control + rotation
  → continuous audit
```

Break the **workflow** (taxonomy), and HA-1…HA-9 collapse even though AES-256 remains unbroken.
