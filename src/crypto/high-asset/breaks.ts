/**
 * Taxonomy edges that break high-asset encryption narratives.
 * These do not invert AES-256; they void the operational promise.
 */

export type HighAssetBreak = {
  tierId: string;
  microDomainId: string;
  narrative: string;
  severity: "critical" | "high" | "medium";
  /** Control id implemented in code when hardened. */
  controlId: string;
};

export const HIGH_ASSET_BREAKS: readonly HighAssetBreak[] = [
  // HA-1 AES-256-GCM HSM
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "4.6.2", narrative: "Nonce reuse under CMK voids GCM confidentiality/integrity narrative.", severity: "critical", controlId: "nonce_vault" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "4.6.1", narrative: "Fallback to unauthenticated CBC/CTR on HSM error.", severity: "critical", controlId: "aead_only" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "3.2.1", narrative: "Tag failure ignored; partial plaintext returned to host.", severity: "critical", controlId: "verify_then_decrypt" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "3.3.1", narrative: "Parallel sealers share counter → nonce collision.", severity: "critical", controlId: "nonce_vault" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "4.3.1", narrative: "IDOR on KMS key id decrypts another tenant's blob.", severity: "critical", controlId: "aad_tenant_bind" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "4.6.5", narrative: "CMK material logged or exported to app logs.", severity: "critical", controlId: "secret_scrub" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "7.1.2", narrative: "Retry seal without new nonce (non-idempotent retry).", severity: "critical", controlId: "idempotent_seal" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "1.1.3", narrative: "HSM timeout fallback disables encryption.", severity: "critical", controlId: "fail_closed" },
  { tierId: "ha.aes256_gcm_hsm", microDomainId: "9.3.1", narrative: "Structured logs omit scrubbing of key bytes.", severity: "critical", controlId: "secret_scrub" },

  // HA-2 ChaCha
  { tierId: "ha.chacha20_poly1305", microDomainId: "4.6.2", narrative: "Nonce reuse on WireGuard-style AEAD.", severity: "critical", controlId: "nonce_vault" },
  { tierId: "ha.chacha20_poly1305", microDomainId: "1.3.1", narrative: "Unbounded parallel encryptors collide nonces.", severity: "critical", controlId: "nonce_vault" },

  // HA-3 Hybrid TLS
  { tierId: "ha.tls13_hybrid_pq", microDomainId: "1.1.2", narrative: "Illegal jump to classical-only when ML-KEM fails.", severity: "critical", controlId: "hybrid_enforce" },
  { tierId: "ha.tls13_hybrid_pq", microDomainId: "1.1.3", narrative: "Timeout fallback skips certificate validation.", severity: "critical", controlId: "fail_closed" },
  { tierId: "ha.tls13_hybrid_pq", microDomainId: "4.4.1", narrative: "JWKS/OCSP SSRF during handshake.", severity: "high", controlId: "ssrf_block" },
  { tierId: "ha.tls13_hybrid_pq", microDomainId: "5.2.1", narrative: "Revoked cert still cached as trusted.", severity: "high", controlId: "cache_invalidate" },
  { tierId: "ha.tls13_hybrid_pq", microDomainId: "7.1.1", narrative: "No handshake timeout → hung sessions.", severity: "medium", controlId: "timeout_abort" },

  // HA-4 PQ signatures
  { tierId: "ha.mldsa_signing", microDomainId: "4.3.1", narrative: "Signing key row readable cross-tenant.", severity: "critical", controlId: "rls_keys" },
  { tierId: "ha.mldsa_signing", microDomainId: "4.7.1", narrative: "Unsafe deserialization of secret key blob.", severity: "critical", controlId: "safe_key_import" },

  // HA-5 Payment HSM
  { tierId: "ha.payment_hsm", microDomainId: "4.6.5", narrative: "PIN block logged in application tier.", severity: "critical", controlId: "secret_scrub" },
  { tierId: "ha.payment_hsm", microDomainId: "1.2.2", narrative: "Failed translate leaves clear PIN in memory without wipe.", severity: "critical", controlId: "compensation_wipe" },

  // HA-6 TPM/SE
  { tierId: "ha.tpm_secure_element", microDomainId: "1.1.2", narrative: "Unseal allowed without PCR policy check state.", severity: "critical", controlId: "policy_gate" },
  { tierId: "ha.tpm_secure_element", microDomainId: "7.5.1", narrative: "No rate limit on unlock attempts.", severity: "high", controlId: "rate_limit" },

  // HA-7 Threshold
  { tierId: "ha.threshold_mpc", microDomainId: "5.1.1", narrative: "Lost update on share revocation.", severity: "high", controlId: "optimistic_lock" },
  { tierId: "ha.threshold_mpc", microDomainId: "1.3.2", narrative: "One share node hang blocks signing without timeout.", severity: "high", controlId: "timeout_abort" },

  // HA-8 CNSA
  { tierId: "ha.cnsa2", microDomainId: "2.2.1", narrative: "Unknown alg enum falls through to legacy RSA-2048.", severity: "critical", controlId: "assert_never_alg" },
  { tierId: "ha.cnsa2", microDomainId: "9.1.1", narrative: "Compliance UI claims CNSA while suite not enforced.", severity: "high", controlId: "provenance" },

  // HA-9 Double ratchet
  { tierId: "ha.double_ratchet", microDomainId: "4.6.2", narrative: "Message key/nonce reuse across send attempts.", severity: "critical", controlId: "nonce_vault" },
  { tierId: "ha.double_ratchet", microDomainId: "1.1.4", narrative: "Replay of send step reuses chain key.", severity: "critical", controlId: "replay_safe_ratchet" },
];

export type ControlClaimMap = Record<string, boolean>;

export type HighAssetProfile = {
  name: string;
  /** controlId → present */
  controls: ControlClaimMap;
};

/** Old / broken high-asset posture (taxonomy failures present). */
export const BROKEN_HIGH_ASSET_PROFILE: HighAssetProfile = {
  name: "broken",
  controls: {
    nonce_vault: false,
    aead_only: false,
    verify_then_decrypt: false,
    aad_tenant_bind: false,
    secret_scrub: false,
    idempotent_seal: false,
    fail_closed: false,
    hybrid_enforce: false,
    ssrf_block: false,
    cache_invalidate: false,
    timeout_abort: false,
    rls_keys: false,
    safe_key_import: false,
    compensation_wipe: false,
    policy_gate: false,
    rate_limit: false,
    optimistic_lock: false,
    assert_never_alg: false,
    provenance: false,
    replay_safe_ratchet: false,
  },
};

/** New / hardened posture — controls implemented in this codebase where applicable. */
export const HARDENED_HIGH_ASSET_PROFILE: HighAssetProfile = {
  name: "hardened",
  controls: {
    nonce_vault: true,
    aead_only: true,
    verify_then_decrypt: true,
    aad_tenant_bind: true,
    secret_scrub: true,
    idempotent_seal: true,
    fail_closed: true,
    hybrid_enforce: true,
    ssrf_block: true,
    cache_invalidate: true,
    timeout_abort: true,
    rls_keys: true,
    safe_key_import: true,
    compensation_wipe: true,
    policy_gate: true,
    rate_limit: true,
    optimistic_lock: true,
    assert_never_alg: true,
    provenance: true,
    replay_safe_ratchet: true,
  },
};
