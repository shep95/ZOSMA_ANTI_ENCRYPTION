/**
 * Operational encryption levels of the world.
 * Each level is a security narrative: promise + required workflow steps.
 */

export type CryptoLayer =
  | "classical"
  | "information_theoretic"
  | "symmetric"
  | "hash_mac_kdf"
  | "asymmetric"
  | "signatures"
  | "key_exchange"
  | "application_tokens"
  | "assurance_policy"
  | "quantum_threat";

export type EncryptionLevel = {
  id: string;
  layer: CryptoLayer;
  name: string;
  /** What the algorithm/class promises when used correctly. */
  promise: string;
  /** Ordered workflow steps that must hold. */
  workflow: readonly string[];
  /** Hardness / assumption (informal). */
  assumption: string;
  /** True if large-scale Shor-class quantum breaks the primitive. */
  shorBreakable: boolean;
  /** True if Grover only (symmetric key length advice). */
  groverRelevant: boolean;
};

export const ENCRYPTION_LEVELS: readonly EncryptionLevel[] = [
  {
    id: "classical.substitution",
    layer: "classical",
    name: "Classical substitution / transposition",
    promise: "Obscurity of symbols under a small key.",
    workflow: ["choose alphabet map or key", "transform symbols", "transmit ciphertext"],
    assumption: "Attacker lacks frequency analysis and known plaintext.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "it.otp",
    layer: "information_theoretic",
    name: "One-time pad",
    promise: "Perfect secrecy.",
    workflow: [
      "sample key bits uniformly",
      "key length >= message length",
      "XOR once",
      "never reuse key",
      "destroy key",
    ],
    assumption: "True randomness, single use, secure key distribution.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "sym.block.ecb",
    layer: "symmetric",
    name: "Block cipher ECB (AES/DES family)",
    promise: "Block confidentiality only (weak mode).",
    workflow: ["load key", "encrypt each block independently"],
    assumption: "Secret key; accepts pattern leakage.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "sym.block.cbc",
    layer: "symmetric",
    name: "Block cipher CBC",
    promise: "Confidentiality with random IV (no integrity).",
    workflow: ["sample IV", "chain blocks", "never reuse IV with same key for related messages carelessly"],
    assumption: "Secret key; no padding oracle; integrity handled elsewhere.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "sym.stream.chacha",
    layer: "symmetric",
    name: "Stream cipher ChaCha20",
    promise: "Confidentiality under unique nonce.",
    workflow: ["key + unique nonce", "keystream", "XOR", "never reuse nonce"],
    assumption: "Secret key; nonce uniqueness.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "sym.aead.gcm",
    layer: "symmetric",
    name: "AEAD AES-GCM",
    promise: "Confidentiality + authenticity of ciphertext and AAD.",
    workflow: [
      "unique 96-bit nonce (or misuse-resistant variant)",
      "encrypt",
      "emit tag",
      "verify tag before plaintext release",
    ],
    assumption: "Secret key; nonce never reused; full tag verified in constant time.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "sym.aead.chacha_poly",
    layer: "symmetric",
    name: "AEAD ChaCha20-Poly1305",
    promise: "Confidentiality + authenticity.",
    workflow: ["unique nonce", "encrypt", "Poly1305 tag", "verify-then-decrypt"],
    assumption: "Secret key; nonce uniqueness.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "hash.sha2",
    layer: "hash_mac_kdf",
    name: "SHA-2 family",
    promise: "Collision / preimage resistance (not encryption).",
    workflow: ["absorb message", "output digest"],
    assumption: "Not used alone for passwords or authenticity.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "mac.hmac",
    layer: "hash_mac_kdf",
    name: "HMAC",
    promise: "Keyed integrity and authenticity.",
    workflow: ["shared MAC key", "compute tag", "constant-time compare"],
    assumption: "Secret MAC key; no timing oracle.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "kdf.argon2id",
    layer: "hash_mac_kdf",
    name: "argon2id password KDF",
    promise: "Password-derived keys resist offline GPU/ASIC cracking at chosen cost.",
    workflow: ["unique salt", "memory/time/parallelism params", "store hash", "verify"],
    assumption: "Adequate parameters; salt per password.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "kdf.hkdf",
    layer: "hash_mac_kdf",
    name: "HKDF",
    promise: "Extract-then-expand key hierarchy from IKM.",
    workflow: ["extract with salt", "expand with info labels", "domain-separate keys"],
    assumption: "IKM has sufficient entropy; labels prevent key confusion.",
    shorBreakable: false,
    groverRelevant: true,
  },
  {
    id: "asymm.rsa_oaep",
    layer: "asymmetric",
    name: "RSA-OAEP",
    promise: "Public-key encryption under factoring hardness.",
    workflow: ["OAEP pad", "modexp encrypt", "modexp decrypt", "unpad"],
    assumption: "Large N; OAEP; private key secret; no side channels.",
    shorBreakable: true,
    groverRelevant: false,
  },
  {
    id: "asymm.rsa_textbook",
    layer: "asymmetric",
    name: "Textbook RSA (no padding)",
    promise: "None in modern threat models — educational only.",
    workflow: ["c = m^e mod N", "m = c^d mod N"],
    assumption: "Broken by design for real messages.",
    shorBreakable: true,
    groverRelevant: false,
  },
  {
    id: "asymm.mlkem",
    layer: "asymmetric",
    name: "ML-KEM (Kyber) key encapsulation",
    promise: "Post-quantum IND-CCA KEM (design goal).",
    workflow: ["KeyGen", "Encaps(pk)->(ct,ss)", "Decaps(sk,ct)->ss", "AEAD with ss"],
    assumption: "Correct implementation; hybrid transcript binding recommended.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "sig.ecdsa",
    layer: "signatures",
    name: "ECDSA",
    promise: "Unforgeable signatures under ECDLP.",
    workflow: ["hash message", "sign with fresh nonce", "verify"],
    assumption: "Secure curve; unique ephemeral nonce; private key secret.",
    shorBreakable: true,
    groverRelevant: false,
  },
  {
    id: "sig.ed25519",
    layer: "signatures",
    name: "Ed25519",
    promise: "Unforgeable signatures (Edwards curve).",
    workflow: ["sign", "verify"],
    assumption: "Private key secret; standard verification.",
    shorBreakable: true,
    groverRelevant: false,
  },
  {
    id: "sig.mldsa",
    layer: "signatures",
    name: "ML-DSA (Dilithium)",
    promise: "Post-quantum signatures (design goal).",
    workflow: ["sign", "verify"],
    assumption: "Correct parameter set; side-channel resistance.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "kx.ecdh",
    layer: "key_exchange",
    name: "ECDH",
    promise: "Shared secret against passive network adversary.",
    workflow: ["ephemeral keys", "shared secret", "KDF", "AEAD"],
    assumption: "Authenticated channel or MITM-resistant handshake; valid points.",
    shorBreakable: true,
    groverRelevant: false,
  },
  {
    id: "kx.tls13",
    layer: "key_exchange",
    name: "TLS 1.3 record protection",
    promise: "Authenticated key exchange + AEAD traffic keys + forward secrecy.",
    workflow: [
      "handshake",
      "certificate/PQ identity",
      "derive traffic keys",
      "AEAD records",
      "rekey",
    ],
    assumption: "Correct cert validation; no downgrade; AEAD nonces correct.",
    shorBreakable: true,
    groverRelevant: true,
  },
  {
    id: "app.jwt",
    layer: "application_tokens",
    name: "JWT bearer tokens",
    promise: "Stateless authenticated claims.",
    workflow: ["sign/encrypt token", "verify alg+aud+iss+exp", "authorize"],
    assumption: "Strong alg; claim binding; short TTL; secret hygiene.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "app.password_store",
    layer: "application_tokens",
    name: "Password storage",
    promise: "Offline cracking is expensive.",
    workflow: ["argon2id", "unique salt", "constant-time verify"],
    assumption: "No plaintext/fast-hash storage.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "policy.fips140",
    layer: "assurance_policy",
    name: "FIPS 140-3 module assurance",
    promise: "Validated cryptographic module controls.",
    workflow: ["approved algorithms", "roles", "key entry", "zeroization"],
    assumption: "Application uses the module correctly.",
    shorBreakable: false,
    groverRelevant: false,
  },
  {
    id: "quantum.shor_rsa",
    layer: "quantum_threat",
    name: "Shor vs RSA moduli",
    promise: "Attacker narrative: factor N → forge d → read RSA ciphertext.",
    workflow: [
      "obtain (e,N) and ciphertext",
      "order-finding on QPU or classical for tiny N",
      "recover factors",
      "compute d",
      "decrypt",
    ],
    assumption: "Sufficient qubits / toy N for demos; harvest-now-decrypt-later for large N.",
    shorBreakable: true,
    groverRelevant: false,
  },
] as const;

export function getLevel(id: string): EncryptionLevel | undefined {
  return ENCRYPTION_LEVELS.find((level) => level.id === id);
}

export function levelsByLayer(layer: CryptoLayer): EncryptionLevel[] {
  return ENCRYPTION_LEVELS.filter((level) => level.layer === layer);
}
