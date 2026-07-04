/**
 * AES-256-GCM bypass vectors from the protection narrative.
 * Each vector demonstrates how violating a narrative rule voids GCM guarantees.
 * Uses real Node crypto AES-GCM where applicable.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { AttackError } from "../../errors.js";
import {
  generateDataKey,
  openAes256Gcm,
  sealAes256Gcm,
  type SealedBox,
} from "./aead.js";

export type BypassResult = {
  vector: string;
  bypassed: boolean;
  detail: string;
  recovered?: string;
};

const MAX_BYTES_PER_NONCE = 64 * 1024 * 1024 * 1024; // 64 GiB (NIST guidance class)

// ---------------------------------------------------------------------------
// 1. Nonce Reuse — Forbidden Attack (confidentiality via keystream cancel)
// ---------------------------------------------------------------------------

export function bypassNonceReuseForbiddenAttack(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const known = Buffer.from("ZOSMA|BEACON-000000000");
  const secret = Buffer.from("ZOSMA|beta-ledger-9902");
  if (known.length !== secret.length) {
    throw new Error("known and secret must be equal length");
  }

  // Same key + same nonce for two messages (narrative violation).
  const boxKnown = sealAes256Gcm({ key, plaintext: known }, nonce);
  const boxSecret = sealAes256Gcm({ key, plaintext: secret }, nonce);

  // C = P ⊕ keystream ⇒ C_known ⊕ P_known = keystream = C_secret ⊕ P_secret
  const keystream = xor(boxKnown.ciphertext, known);
  const recovered = xor(boxSecret.ciphertext, keystream).toString("utf8");
  const ok = recovered === secret.toString("utf8");

  return {
    vector: "1.nonce-reuse-forbidden-attack",
    bypassed: ok,
    recovered,
    detail: ok
      ? "Nonce reuse: keystream cancel recovered secret without the AES key (Forbidden Attack confidentiality break)."
      : "Nonce-reuse recovery failed.",
  };
}

// ---------------------------------------------------------------------------
// 2. Compromised key management
// ---------------------------------------------------------------------------

export function bypassCompromisedKey(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = "ZOSMA|alpha-vault-7741";
  const box = sealAes256Gcm(
    { key, plaintext: Buffer.from(plaintext), aad: Buffer.from("tenant-a") },
    nonce,
  );

  // Attacker obtains key via leak (hardcoded, log, sidecar file) — not by breaking AES.
  const leakedKey = Buffer.from(key); // simulates exfiltration
  const opened = openAes256Gcm(leakedKey, box).toString("utf8");

  return {
    vector: "2.compromised-key-management",
    bypassed: opened === plaintext,
    recovered: opened,
    detail:
      opened === plaintext
        ? "Leaked 256-bit key decrypts ciphertext and validates tag — all GCM guarantees collapse."
        : "Key compromise path failed.",
  };
}

// ---------------------------------------------------------------------------
// 3a. Release-before-verify (decryption oracle)
// ---------------------------------------------------------------------------

/** Vulnerable open: returns plaintext even when tag is wrong. */
export function openReleaseBeforeVerify(key: Buffer, box: SealedBox): {
  plaintext: Buffer;
  tagValid: boolean;
} {
  const decipher = createDecipheriv("aes-256-gcm", key, box.nonce);
  if (box.aad.length > 0) decipher.setAAD(box.aad);
  // Intentionally set a WRONG tag path: decrypt CTR-style without verifying first.
  // Node's GCM API verifies on final(); we simulate release-before-verify by
  // decrypting with aes-256-ctr using the GCM counter layout, ignoring the tag.
  const iv = Buffer.alloc(16);
  box.nonce.copy(iv, 0, 0, 12);
  iv.writeUInt32BE(2, 12); // GCM encrypts plaintext starting at counter=2
  const ctr = createDecipheriv("aes-256-ctr", key, iv);
  const plaintext = Buffer.concat([ctr.update(box.ciphertext), ctr.final()]);

  let tagValid = false;
  try {
    const check = createDecipheriv("aes-256-gcm", key, box.nonce);
    if (box.aad.length > 0) check.setAAD(box.aad);
    check.setAuthTag(box.tag);
    check.update(box.ciphertext);
    check.final();
    tagValid = true;
  } catch {
    tagValid = false;
  }

  return { plaintext, tagValid };
}

export function bypassReleaseBeforeVerify(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = "ZOSMA|oracle-secret-01";
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext) }, nonce);

  // Tamper ciphertext but vulnerable impl still releases bytes.
  const tampered: SealedBox = {
    ...box,
    ciphertext: Buffer.from(box.ciphertext),
  };
  tampered.ciphertext[0] = tampered.ciphertext[0]! ^ 0x01;

  const vulnerable = openReleaseBeforeVerify(key, tampered);
  let hardenedBlocked = false;
  try {
    openAes256Gcm(key, tampered);
  } catch {
    hardenedBlocked = true;
  }

  const leaked = vulnerable.plaintext.length > 0 && !vulnerable.tagValid;
  return {
    vector: "3a.release-before-verify-oracle",
    bypassed: leaked && hardenedBlocked,
    recovered: vulnerable.plaintext.toString("utf8"),
    detail: leaked
      ? `Vulnerable impl released ${vulnerable.plaintext.length}B despite invalid tag (tagValid=${vulnerable.tagValid}); hardened path blocked=${hardenedBlocked}.`
      : "Release-before-verify demo did not leak.",
  };
}

// ---------------------------------------------------------------------------
// 3b. Non-constant-time tag comparison (timing side-channel)
// ---------------------------------------------------------------------------

/** Leaky compare: early-return per byte with measurable artificial delay. */
export function leakyTagCompare(expected: Buffer, provided: Buffer): {
  equal: boolean;
  steps: number;
  elapsedNs: bigint;
} {
  const start = process.hrtime.bigint();
  let steps = 0;
  const len = Math.min(expected.length, provided.length);
  for (let i = 0; i < len; i++) {
    steps += 1;
    // Artificial per-byte work so timing differences are observable in tests.
    busyWait(50);
    if (expected[i] !== provided[i]) {
      const elapsedNs = process.hrtime.bigint() - start;
      return { equal: false, steps, elapsedNs };
    }
  }
  if (expected.length !== provided.length) {
    const elapsedNs = process.hrtime.bigint() - start;
    return { equal: false, steps, elapsedNs };
  }
  const elapsedNs = process.hrtime.bigint() - start;
  return { equal: true, steps, elapsedNs };
}

function busyWait(iters: number): void {
  let x = 0;
  for (let i = 0; i < iters; i++) x ^= i;
  if (x === -1) throw new Error("unreachable");
}

export function bypassTimingTagCompare(): BypassResult {
  const realTag = randomBytes(16);
  const stepSamples: number[] = [];
  const timeSamples: number[] = [];

  for (let matchPrefix = 0; matchPrefix <= 4; matchPrefix++) {
    const forged = Buffer.from(realTag);
    for (let i = 0; i < matchPrefix; i++) forged[i] = realTag[i]!;
    if (matchPrefix < forged.length) forged[matchPrefix] = realTag[matchPrefix]! ^ 0x01;
    for (let i = matchPrefix + 1; i < forged.length; i++) forged[i] = realTag[i]! ^ 0xff;

    const { steps, elapsedNs } = leakyTagCompare(realTag, forged);
    stepSamples.push(steps);
    timeSamples.push(Number(elapsedNs));
  }

  // Early-return leaks how many leading bytes matched (steps == matchPrefix+1).
  let stepsLeak = true;
  for (let matchPrefix = 0; matchPrefix <= 4; matchPrefix++) {
    if (stepSamples[matchPrefix] !== matchPrefix + 1) stepsLeak = false;
  }

  // Secure path: timingSafeEqual does not expose prefix length via step count.
  const a = randomBytes(16);
  const b = Buffer.from(a);
  b[0] ^= 1;
  const c = Buffer.from(a);
  c[15] ^= 1;
  const secureEarly = timingSafeEqual(a, b);
  const secureLate = timingSafeEqual(a, c);

  return {
    vector: "3b.non-constant-time-tag-compare",
    bypassed: stepsLeak && !secureEarly && !secureLate,
    detail: stepsLeak
      ? `Leaky compare early-returns at steps=${stepSamples.join(",")} (prefix length leaked); timingSafeEqual rejects both forgeries without prefix oracle.`
      : `Step leak not observed (steps=${stepSamples.join(",")}).`,
  };
}

// ---------------------------------------------------------------------------
// 3c. Use-after-free analogue (stale buffer not wiped)
// ---------------------------------------------------------------------------

export function bypassStaleBufferAfterTagFail(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = "ZOSMA|stale-buffer-secret";
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext) }, nonce);

  // Vulnerable: keep decrypted bytes in a shared buffer even after tag fail.
  const stale: { buf: Buffer | null } = { buf: null };
  const tampered: SealedBox = {
    ...box,
    tag: Buffer.from(box.tag),
  };
  tampered.tag[0] ^= 0xff;

  // Simulate decrypt-into-buffer then fail tag (CTR decrypt without verify).
  const iv = Buffer.alloc(16);
  box.nonce.copy(iv, 0, 0, 12);
  iv.writeUInt32BE(2, 12);
  const ctr = createDecipheriv("aes-256-ctr", key, iv);
  stale.buf = Buffer.concat([ctr.update(box.ciphertext), ctr.final()]);
  // Tag fails — vulnerable code forgets to zeroize stale.buf
  const leaked = stale.buf.toString("utf8");

  // Hardened: wipe on failure
  const hardened: { buf: Buffer | null } = { buf: Buffer.from(stale.buf) };
  try {
    openAes256Gcm(key, tampered);
  } catch {
    hardened.buf!.fill(0);
    hardened.buf = null;
  }

  const ok = leaked === plaintext && hardened.buf === null;
  return {
    vector: "3c.stale-buffer-after-tag-fail",
    bypassed: ok,
    recovered: leaked,
    detail: ok
      ? "Vulnerable path left plaintext in memory after tag fail; hardened path zeroized and dropped the buffer."
      : "Stale-buffer demo failed.",
  };
}

// ---------------------------------------------------------------------------
// 4. Authentication tag truncation
// ---------------------------------------------------------------------------

export function bypassTruncatedTag(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = Buffer.from("ZOSMA|trunc-tag");
  const full = sealAes256Gcm({ key, plaintext }, nonce);

  // Truncate to 1 byte (8 bits) — forgery probability ~1/256 per try.
  const shortTagLen = 1;
  const shortTag = full.tag.subarray(0, shortTagLen);

  let forged = false;
  let attempts = 0;
  const maxAttempts = 4096;
  for (let i = 0; i < maxAttempts; i++) {
    attempts += 1;
    const guess = randomBytes(shortTagLen);
    // Accept if truncated tag matches (simulates verifier that only checks shortTagLen bytes)
    if (guess[0] === shortTag[0]) {
      forged = true;
      break;
    }
  }

  return {
    vector: "4.authentication-tag-truncation",
    bypassed: forged,
    detail: forged
      ? `Forged ${shortTagLen}-byte truncated tag in ${attempts} attempts (full 128-bit tag would need ~2^128 work).`
      : `No truncated-tag forgery in ${maxAttempts} attempts (unlucky; retry).`,
  };
}

// ---------------------------------------------------------------------------
// 5. Exceeding data limits
// ---------------------------------------------------------------------------

export function bypassDataLimitPolicy(bytesUnderNonce: number): BypassResult {
  const exceeded = bytesUnderNonce > MAX_BYTES_PER_NONCE;
  return {
    vector: exceeded ? "5a.data-limit-exceeded" : "5b.data-limit-within-bounds",
    bypassed: exceeded,
    detail: exceeded
      ? `Encrypting ${bytesUnderNonce} bytes under one nonce exceeds ~64 GiB NIST ceiling — security proof no longer applies; rotate key/nonce.`
      : `${bytesUnderNonce} bytes under one nonce is within the 64 GiB guidance (no bypass).`,
  };
}

// ---------------------------------------------------------------------------
// 6. AAD mismanagement
// ---------------------------------------------------------------------------

/** Vulnerable: ignores AAD on decrypt (contextual integrity bypass). */
export function openIgnoringAad(key: Buffer, box: SealedBox): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, box.nonce);
  // BUG: does not call setAAD(box.aad) — and seals were created WITH aad,
  // so correct verify would need aad. To simulate "omitted AAD from tag calc"
  // on BOTH seal and open, we seal without binding and "accept" wrong context.
  // True bypass: seal with empty AAD always, then any context appears valid.
  decipher.setAAD(Buffer.alloc(0));
  decipher.setAuthTag(box.tag);
  return Buffer.concat([decipher.update(box.ciphertext), decipher.final()]);
}

export function bypassAadMismanagement(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = "ZOSMA|aad-context-secret";

  // Vulnerable system seals with EMPTY aad (forgot to bind tenant).
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext), aad: Buffer.alloc(0) }, nonce);

  // Attacker presents ciphertext under wrong tenant context.
  const wrongContext = Buffer.from("tenant-EVIL|obj-9");
  // Hardened open with wrong AAD fails if original had correct AAD.
  // Here original AAD was empty, so open with empty AAD works in ANY UI context —
  // contextual authorization is bypassed.
  const opened = openAes256Gcm(key, { ...box, aad: Buffer.alloc(0) }).toString("utf8");

  // Show correct binding would have blocked wrong tenant:
  const bound = sealAes256Gcm(
    { key, plaintext: Buffer.from(plaintext), aad: Buffer.from("tenant-a|obj-1") },
    randomBytes(12),
  );
  let wrongTenantBlocked = false;
  try {
    openAes256Gcm(key, { ...bound, aad: wrongContext });
  } catch {
    wrongTenantBlocked = true;
  }

  return {
    vector: "6.aad-mismanagement",
    bypassed: opened === plaintext && wrongTenantBlocked,
    recovered: opened,
    detail:
      opened === plaintext
        ? `Sealed without AAD bind — ciphertext validates in any context (missing authorization analogue). Correct AAD bind blocks wrong tenant=${wrongTenantBlocked}.`
        : "AAD mismanagement demo failed.",
  };
}

// ---------------------------------------------------------------------------
// 7. Library misuse — wrong counter / custom crypto foot-gun
// ---------------------------------------------------------------------------

export function bypassLibraryMisuseWrongCounter(): BypassResult {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const plaintext = Buffer.from("ZOSMA|misuse-counter");

  // Correct seal
  const correct = sealAes256Gcm({ key, plaintext }, nonce);

  // Misuse: decrypt with wrong counter start (off-by-one) — garbage, not silent success.
  // More dangerous misuse: reuse nonce (already covered) or truncate tag (covered).
  // Here: developer "rolls own" by using aes-256-ctr with counter=0 instead of GCM layout.
  const iv = Buffer.alloc(16);
  nonce.copy(iv, 0, 0, 12);
  iv.writeUInt32BE(0, 12); // WRONG — GCM uses 1 for J0-related, plaintext at 2
  const ctr = createDecipheriv("aes-256-ctr", key, iv);
  const garbage = Buffer.concat([ctr.update(correct.ciphertext), ctr.final()]);
  const notPlaintext = garbage.toString("utf8") !== plaintext.toString("utf8");

  // Critical misuse: encrypt two messages with same nonce via "helpful" shared IV constant
  const fixedIv = Buffer.alloc(12, 0x42);
  const m1 = sealAes256Gcm({ key, plaintext: Buffer.from("AAAA") }, fixedIv);
  const m2 = sealAes256Gcm({ key, plaintext: Buffer.from("BBBB") }, fixedIv);
  const ks = xor(m1.ciphertext, Buffer.from("AAAA"));
  const recovered = xor(m2.ciphertext, ks).toString("utf8");

  return {
    vector: "7.library-misuse-custom-impl",
    bypassed: notPlaintext && recovered === "BBBB",
    recovered,
    detail:
      `Wrong-counter decrypt yields garbage (not silent success)=${notPlaintext}; ` +
      `hardcoded IV reuse recovers second plaintext='${recovered}' (custom-impl foot-gun).`,
  };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export function runAllGcmBypasses(): BypassResult[] {
  return [
    bypassNonceReuseForbiddenAttack(),
    bypassCompromisedKey(),
    bypassReleaseBeforeVerify(),
    bypassTimingTagCompare(),
    bypassStaleBufferAfterTagFail(),
    bypassTruncatedTag(),
    bypassDataLimitPolicy(65 * 1024 * 1024 * 1024),
    bypassDataLimitPolicy(1024),
    bypassAadMismanagement(),
    bypassLibraryMisuseWrongCounter(),
  ];
}

function xor(a: Buffer, b: Buffer): Buffer {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}
