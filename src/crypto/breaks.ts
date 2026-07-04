/**
 * Maps encryption levels → taxonomy micro-domains that break their narratives.
 */

import { ENCRYPTION_LEVELS, type EncryptionLevel } from "./levels.js";

export type BreakEdge = {
  levelId: string;
  microDomainId: string;
  /** Concrete break story for this pair. */
  narrative: string;
  /** Severity for prioritization. */
  severity: "critical" | "high" | "medium" | "low";
};

/** Curated edges: taxonomy flaw → how it voids the crypto promise. */
export const BREAK_EDGES: readonly BreakEdge[] = [
  // OTP
  { levelId: "it.otp", microDomainId: "4.6.5", narrative: "Pad key logged or committed → perfect secrecy void.", severity: "critical" },
  { levelId: "it.otp", microDomainId: "1.1.4", narrative: "Replay of send step reuses pad.", severity: "critical" },
  { levelId: "it.otp", microDomainId: "9.1.1", narrative: "PRNG stream marketed as OTP.", severity: "high" },

  // ECB / CBC / stream
  { levelId: "sym.block.ecb", microDomainId: "4.6.1", narrative: "ECB without integrity; patterns leak.", severity: "high" },
  { levelId: "sym.block.cbc", microDomainId: "8.1.1", narrative: "Padding error strings become oracles.", severity: "critical" },
  { levelId: "sym.block.cbc", microDomainId: "4.6.2", narrative: "IV reuse under same key.", severity: "high" },
  { levelId: "sym.stream.chacha", microDomainId: "4.6.2", narrative: "Nonce reuse leaks plaintext via keystream cancel.", severity: "critical" },
  { levelId: "sym.stream.chacha", microDomainId: "3.3.1", narrative: "Concurrent requests share nonce counter.", severity: "critical" },

  // AEAD
  { levelId: "sym.aead.gcm", microDomainId: "4.6.1", narrative: "Fallback to unauthenticated mode on error.", severity: "critical" },
  { levelId: "sym.aead.gcm", microDomainId: "4.6.2", narrative: "GCM nonce reuse forges and decrypts.", severity: "critical" },
  { levelId: "sym.aead.gcm", microDomainId: "3.2.1", narrative: "Tag verify rejection ignored; plaintext returned.", severity: "critical" },
  { levelId: "sym.aead.gcm", microDomainId: "7.1.2", narrative: "Retrying encrypt without new nonce.", severity: "critical" },
  { levelId: "sym.aead.gcm", microDomainId: "2.3.1", narrative: "Shared nonce buffer mutated across jobs.", severity: "critical" },
  { levelId: "sym.aead.chacha_poly", microDomainId: "4.6.2", narrative: "Nonce reuse breaks ChaCha20-Poly1305.", severity: "critical" },
  { levelId: "sym.aead.chacha_poly", microDomainId: "1.3.1", narrative: "Unbounded parallel sealers collide nonces.", severity: "critical" },

  // Hash / MAC / KDF
  { levelId: "hash.sha2", microDomainId: "4.6.3", narrative: "SHA-256 used as password hash.", severity: "high" },
  { levelId: "mac.hmac", microDomainId: "3.2.1", narrative: "Non-constant-time compare via early return bugs.", severity: "high" },
  { levelId: "mac.hmac", microDomainId: "9.3.1", narrative: "MAC key printed in debug logs.", severity: "critical" },
  { levelId: "kdf.argon2id", microDomainId: "4.6.3", narrative: "PBKDF2/MD5 substituted under 'performance' flag.", severity: "high" },
  { levelId: "kdf.hkdf", microDomainId: "2.2.1", narrative: "Missing info-label arm derives wrong key purpose.", severity: "high" },

  // RSA
  { levelId: "asymm.rsa_oaep", microDomainId: "4.6.1", narrative: "OAEP stripped; textbook RSA deployed.", severity: "critical" },
  { levelId: "asymm.rsa_oaep", microDomainId: "4.3.1", narrative: "Private key object IDOR.", severity: "critical" },
  { levelId: "asymm.rsa_oaep", microDomainId: "4.6.5", narrative: "PEM in repo or client bundle.", severity: "critical" },
  { levelId: "asymm.rsa_oaep", microDomainId: "2.2.2", narrative: "Factoring/QPU attempted before authz.", severity: "medium" },
  { levelId: "asymm.rsa_textbook", microDomainId: "4.6.1", narrative: "No padding — malleable and leaky by design.", severity: "critical" },
  { levelId: "asymm.rsa_textbook", microDomainId: "9.2.1", narrative: "UI claims 'RSA-2048 security' for toy N.", severity: "high" },

  // PQ KEM
  { levelId: "asymm.mlkem", microDomainId: "1.1.2", narrative: "On PQ failure, illegal jump to classical-only without policy.", severity: "high" },
  { levelId: "asymm.mlkem", microDomainId: "7.2.1", narrative: "Unvalidated KEM ciphertext blob.", severity: "high" },
  { levelId: "asymm.mlkem", microDomainId: "1.2.2", narrative: "Failed hybrid handshake leaves classical keys live.", severity: "high" },

  // Signatures
  { levelId: "sig.ecdsa", microDomainId: "3.3.1", narrative: "Ephemeral nonce reuse leaks private key.", severity: "critical" },
  { levelId: "sig.ecdsa", microDomainId: "4.6.4", narrative: "Signature accepted without audience binding at app layer.", severity: "high" },
  { levelId: "sig.ed25519", microDomainId: "4.3.1", narrative: "Signing key readable cross-tenant.", severity: "critical" },
  { levelId: "sig.mldsa", microDomainId: "4.7.1", narrative: "Unsafe load of secret key blob.", severity: "critical" },

  // KX / TLS
  { levelId: "kx.ecdh", microDomainId: "1.1.2", narrative: "Missing authentication state → MITM.", severity: "critical" },
  { levelId: "kx.tls13", microDomainId: "4.4.1", narrative: "JWKS/OCSP SSRF during handshake.", severity: "high" },
  { levelId: "kx.tls13", microDomainId: "7.1.1", narrative: "No handshake timeout.", severity: "medium" },
  { levelId: "kx.tls13", microDomainId: "1.1.3", narrative: "Timeout fallback disables certificate validation.", severity: "critical" },
  { levelId: "kx.tls13", microDomainId: "5.2.1", narrative: "Cached intermediate certs after revoke.", severity: "high" },

  // App tokens
  { levelId: "app.jwt", microDomainId: "4.6.4", narrative: "Missing aud/iss/exp.", severity: "critical" },
  { levelId: "app.jwt", microDomainId: "4.6.1", narrative: "alg=none or HS/RS confusion.", severity: "critical" },
  { levelId: "app.jwt", microDomainId: "7.5.1", narrative: "Unbounded /login and /refresh.", severity: "high" },
  { levelId: "app.jwt", microDomainId: "4.5.1", narrative: "Token in localStorage stolen via XSS.", severity: "critical" },
  { levelId: "app.password_store", microDomainId: "4.6.3", narrative: "Passwords stored as SHA-1/MD5.", severity: "critical" },
  { levelId: "app.password_store", microDomainId: "9.3.1", narrative: "Password logged on auth failure.", severity: "critical" },

  // Policy
  { levelId: "policy.fips140", microDomainId: "9.1.1", narrative: "FIPS badge claimed while app uses non-approved mode.", severity: "high" },
  { levelId: "policy.fips140", microDomainId: "9.2.1", narrative: "No provenance from module to API call.", severity: "medium" },

  // Quantum / Shor narrative (ZOSMA live)
  { levelId: "quantum.shor_rsa", microDomainId: "1.1.1", narrative: "Attack saga missing cancel/timeout edges wastes QPU jobs.", severity: "medium" },
  { levelId: "quantum.shor_rsa", microDomainId: "1.2.1", narrative: "Non-stable idempotency causes duplicate hardware jobs.", severity: "medium" },
  { levelId: "quantum.shor_rsa", microDomainId: "7.1.1", narrative: "No wall-clock budget on QPU wait.", severity: "high" },
  { levelId: "quantum.shor_rsa", microDomainId: "7.2.1", narrative: "Unvalidated factor JSON accepted.", severity: "high" },
  { levelId: "quantum.shor_rsa", microDomainId: "9.3.1", narrative: "IBM token leaked in error strings.", severity: "critical" },
  { levelId: "quantum.shor_rsa", microDomainId: "9.1.1", narrative: "Classical period-finding presented as live QPU.", severity: "critical" },
];

export type ProfileClaim = {
  /** Encryption level id from the catalog. */
  levelId: string;
  /** Implementation claims to evaluate (true = claimed present). */
  claims: Partial<Record<string, boolean>>;
};

/**
 * Default insecure profile: common real-world foot-guns.
 * Used to demonstrate taxonomy breaks against encryption narratives.
 */
export const INSECURE_DEMO_PROFILE: ProfileClaim[] = [
  {
    levelId: "sym.aead.gcm",
    claims: {
      "4.6.1": false,
      "4.6.2": false,
      "3.2.1": false,
      "7.1.2": false,
    },
  },
  {
    levelId: "asymm.rsa_textbook",
    claims: {
      "4.6.1": false,
      "9.2.1": false,
    },
  },
  {
    levelId: "app.jwt",
    claims: {
      "4.6.4": false,
      "4.6.1": false,
      "7.5.1": false,
    },
  },
  {
    levelId: "app.password_store",
    claims: {
      "4.6.3": false,
      "9.3.1": false,
    },
  },
  {
    // Pre-hardening ZOSMA quantum path (classical period-finding era).
    levelId: "quantum.shor_rsa",
    claims: {
      "1.1.1": false,
      "1.2.1": false,
      "7.1.1": false,
      "7.2.1": false,
      "9.3.1": false,
      "9.1.1": false,
    },
  },
];

/**
 * Hardened profile: claims that controls are in place.
 */
export const HARDENED_DEMO_PROFILE: ProfileClaim[] = ENCRYPTION_LEVELS.filter((l) =>
  ["sym.aead.gcm", "asymm.rsa_oaep", "app.jwt", "app.password_store", "kx.tls13", "quantum.shor_rsa"].includes(
    l.id,
  ),
).map((level) => ({
  levelId: level.id,
  claims: Object.fromEntries(
    BREAK_EDGES.filter((e) => e.levelId === level.id).map((e) => [e.microDomainId, true]),
  ),
}));

export function edgesForLevel(levelId: string): BreakEdge[] {
  return BREAK_EDGES.filter((e) => e.levelId === levelId);
}

export function levelOrThrow(levelId: string): EncryptionLevel {
  const level = ENCRYPTION_LEVELS.find((l) => l.id === levelId);
  if (!level) throw new Error(`Unknown encryption level: ${levelId}`);
  return level;
}
