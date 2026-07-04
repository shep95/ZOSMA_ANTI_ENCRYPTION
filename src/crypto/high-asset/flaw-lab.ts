/**
 * Workable demonstrations: taxonomy flaws void high-asset AEAD narratives.
 * Does not recover AES-256 keys. Shows operational breaks + hardened path.
 */

import { AttackError } from "../../errors.js";
import { createLogger } from "../../log.js";
import {
  BrokenSharedNonceVault,
  NonceVault,
  detectNonceReuse,
  demonstrateKeystreamReuseBreak,
  generateDataKey,
  openAes256Gcm,
  sealAes256Gcm,
  type SealedBox,
} from "./aead.js";

export type LabResult = {
  name: string;
  ok: boolean;
  detail: string;
};

/**
 * Broken path: reused nonce → keystream relationship (CTR family).
 * This is how taxonomy 4.6.2 breaks HA-1/HA-2 confidentiality narrative.
 */
export function runBrokenNonceReuseLab(): LabResult {
  const key = generateDataKey();
  const nonce = BrokenSharedNonceVault.nextNonce();
  // Force reuse (attacker/operator mistake).
  const p1 = Buffer.from("HIGH_ASSET_LEDGER_ROW_001");
  const p2 = Buffer.from("HIGH_ASSET_LEDGER_ROW_002");
  const demo = demonstrateKeystreamReuseBreak(key, nonce, p1, p2);

  return {
    name: "broken_nonce_reuse_keystream",
    ok: demo.matches,
    detail: demo.matches
      ? "C1⊕C2 equals P1⊕P2 under nonce reuse — confidentiality narrative broken (AES key not recovered)."
      : "Expected keystream relationship not observed.",
  };
}

/**
 * Broken path: ignore auth failure (3.2.1) — we refuse to implement returning
 * plaintext on failure; instead we prove fail-closed throws.
 */
export function runBrokenIgnoreTagLab(): LabResult {
  const key = generateDataKey();
  const vault = new NonceVault("tenant-a", "seal");
  const box = sealAes256Gcm(
    { key, plaintext: Buffer.from("secret-balance"), aad: Buffer.from("tenant-a") },
    vault.nextNonce(),
  );
  const tampered: SealedBox = {
    ...box,
    tag: Buffer.from(box.tag),
  };
  tampered.tag[0] = tampered.tag[0]! ^ 0xff;

  try {
    openAes256Gcm(key, tampered);
    return {
      name: "fail_closed_on_bad_tag",
      ok: false,
      detail: "Tampered tag was accepted — critical flaw.",
    };
  } catch (err) {
    const msg = err instanceof AttackError ? err.message : String(err);
    return {
      name: "fail_closed_on_bad_tag",
      ok: true,
      detail: `Fail-closed withheld plaintext: ${msg}`,
    };
  }
}

/**
 * Hardened path: unique nonces, AAD tenant bind, verify-then-decrypt, idempotency key.
 */
export function runHardenedSealLab(): LabResult {
  const log = createLogger("high-asset-lab");
  const key = generateDataKey();
  const vault = new NonceVault("tenant-a", "seal");
  const plaintext = Buffer.from("sovereign-record-v1");
  const aad = Buffer.from("tenant-a|object-42");
  const idem = vault.idempotencyKey(Buffer.concat([aad, plaintext]));

  const n1 = vault.nextNonce();
  const n2 = vault.nextNonce();
  if (detectNonceReuse([n1, n2])) {
    return { name: "hardened_seal", ok: false, detail: "NonceVault produced reuse." };
  }

  const box = sealAes256Gcm({ key, plaintext, aad }, n1);
  const opened = openAes256Gcm(key, box);
  if (!opened.equals(plaintext)) {
    return { name: "hardened_seal", ok: false, detail: "Round-trip mismatch." };
  }

  // Wrong tenant AAD must fail closed.
  try {
    openAes256Gcm(key, { ...box, aad: Buffer.from("tenant-b|object-42") });
    return { name: "hardened_seal", ok: false, detail: "AAD mismatch accepted." };
  } catch {
    // expected
  }

  log.info("hardened_seal_ok", {
    idempotencyKey: idem.slice(0, 16),
    ciphertextBytes: box.ciphertext.length,
    // never log key
  });

  return {
    name: "hardened_seal",
    ok: true,
    detail: "Unique nonces, AAD bind, verify-then-decrypt, idempotency key present.",
  };
}

/**
 * Detect broken shared vault collisions under sequential misuse.
 */
export function runSharedVaultCollisionLab(): LabResult {
  BrokenSharedNonceVault.counter = 0;
  const a = BrokenSharedNonceVault.nextNonce();
  BrokenSharedNonceVault.counter = 0; // reset — simulates lost state / race restart
  const b = BrokenSharedNonceVault.nextNonce();
  const reused = detectNonceReuse([a, b]);
  return {
    name: "shared_vault_collision",
    ok: reused,
    detail: reused
      ? "BrokenSharedNonceVault reused nonce after counter reset — taxonomy 3.3.1/2.3.1."
      : "Expected collision not detected.",
  };
}

export function runAllLabs(): LabResult[] {
  return [
    runBrokenNonceReuseLab(),
    runBrokenIgnoreTagLab(),
    runSharedVaultCollisionLab(),
    runHardenedSealLab(),
  ];
}

/** Self-test: every lab must report ok=true (demonstrations and controls hold). */
export function selfTestHighAsset(): { passed: boolean; results: LabResult[] } {
  const results = runAllLabs();
  return { passed: results.every((r) => r.ok), results };
}
