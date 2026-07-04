/**
 * Hardest operational encryption tiers protecting high-value assets.
 */

export type HighAssetTier = {
  id: string;
  name: string;
  assets: string;
  promise: string;
  workflow: readonly string[];
  /** Classical cryptanalysis of the primitive is considered infeasible when used correctly. */
  primitiveHardness: "infeasible_classical" | "pq_design_goal" | "policy_suite" | "protocol_suite";
  shorBreakablePrimitive: boolean;
};

export const HIGH_ASSET_TIERS: readonly HighAssetTier[] = [
  {
    id: "ha.aes256_gcm_hsm",
    name: "AES-256-GCM in HSM/KMS",
    assets: "Bank ledgers, government archives, CMKs, TDE",
    promise: "Confidentiality + authenticity; key non-exportable from hardware.",
    workflow: [
      "generate AES-256 inside HSM",
      "role-separate crypto officer vs user",
      "unique 96-bit nonce per seal (or GCM-SIV)",
      "bind AAD to tenant/object id",
      "verify tag before plaintext release",
      "rotate with dual-control",
      "audit every use",
    ],
    primitiveHardness: "infeasible_classical",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.chacha20_poly1305",
    name: "ChaCha20-Poly1305 AEAD",
    assets: "WireGuard, QUIC, mobile VPN, CDN edges",
    promise: "AEAD without AES-NI dependency.",
    workflow: [
      "load 256-bit key",
      "unique 96-bit nonce",
      "encrypt + Poly1305 tag",
      "verify-then-decrypt",
    ],
    primitiveHardness: "infeasible_classical",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.tls13_hybrid_pq",
    name: "TLS 1.3 hybrid (X25519 + ML-KEM)",
    assets: "Banking APIs, gov portals, HNDL-resistant links",
    promise: "Authenticated FS session; classical and PQ KEM both required.",
    workflow: [
      "offer hybrid groups",
      "authenticate server (classical and/or ML-DSA)",
      "combine ECDH + ML-KEM secrets in transcript KDF",
      "AEAD traffic keys",
      "short-lived tickets; ticket keys in HSM",
    ],
    primitiveHardness: "pq_design_goal",
    shorBreakablePrimitive: true,
  },
  {
    id: "ha.mldsa_signing",
    name: "ML-DSA / SLH-DSA signing",
    assets: "Firmware, software updates, legal records",
    promise: "Unforgeable signatures under PQ threat model (design goal).",
    workflow: [
      "keygen in HSM",
      "sign content hash",
      "distribute pk via cert chain",
      "verify before trust/install",
    ],
    primitiveHardness: "pq_design_goal",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.payment_hsm",
    name: "Payment HSM / PIN security",
    assets: "Card PIN, CVV, key injection (PCI)",
    promise: "PIN/key material never clear in host RAM.",
    workflow: [
      "encrypted PIN block in",
      "HSM translate under LMK hierarchy",
      "MAC response",
      "dual control for key load",
    ],
    primitiveHardness: "infeasible_classical",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.tpm_secure_element",
    name: "TPM / secure element bound keys",
    assets: "Passkeys, disk encryption, national ID",
    promise: "Non-exportable keys; policy-bound unseal.",
    workflow: [
      "generate in SE/TPM",
      "seal to PCR policy",
      "rate-limited unlock",
      "unseal only if measurements match",
    ],
    primitiveHardness: "infeasible_classical",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.threshold_mpc",
    name: "Threshold / MPC custody keys",
    assets: "Crypto custody, root CA ceremonies",
    promise: "No single operator can use the key alone.",
    workflow: [
      "distributed key generation",
      "threshold sign/decrypt",
      "audit each share use",
      "revoke share without full compromise when possible",
    ],
    primitiveHardness: "protocol_suite",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.cnsa2",
    name: "CNSA 2.0 algorithm suite",
    assets: "National-security systems",
    promise: "Only approved PQ-ready algorithms and sizes.",
    workflow: [
      "baseline allow-list",
      "continuous compliance scan",
      "block non-suite algorithms",
    ],
    primitiveHardness: "policy_suite",
    shorBreakablePrimitive: false,
  },
  {
    id: "ha.double_ratchet",
    name: "Double Ratchet messaging",
    assets: "High-risk human communications",
    promise: "Forward secrecy + post-compromise security per message.",
    workflow: [
      "PQXDH/X3DH session",
      "per-message chain keys",
      "AEAD seal",
      "ratchet on send/receive",
    ],
    primitiveHardness: "protocol_suite",
    shorBreakablePrimitive: true,
  },
] as const;

export function highAssetTier(id: string): HighAssetTier | undefined {
  return HIGH_ASSET_TIERS.find((t) => t.id === id);
}
