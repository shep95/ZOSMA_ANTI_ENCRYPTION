/**
 * High-asset AEAD controls (AES-256-GCM) with taxonomy-hardened nonce handling.
 * Uses Node crypto — real AES-GCM, not a mock.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { AttackError } from "../../errors.js";

const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;

export type SealedBox = {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  aad: Buffer;
};

export type SealInput = {
  key: Buffer;
  plaintext: Buffer;
  aad?: Buffer;
};

/** Monotonic nonce source: actorId|op|counter — never a random UUID alone. */
export class NonceVault {
  private counter = 0n;
  private readonly actorId: string;
  private readonly op: string;

  constructor(actorId: string, op: string) {
    if (!actorId || !op) throw new AttackError("nonce_vault", "actorId and op are required");
    this.actorId = actorId;
    this.op = op;
  }

  /** Idempotency material: stable hash of actor, op, and counter. */
  nextNonce(): Buffer {
    this.counter += 1n;
    if (this.counter > 0xffffffffn) {
      throw new AttackError("nonce_exhausted", "Nonce counter exhausted; rotate key");
    }
    const prefix = createHash("sha256")
      .update(`nonce|${this.actorId}|${this.op}`)
      .digest()
      .subarray(0, 8);
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(Number(this.counter), 0);
    return Buffer.concat([prefix, counterBuf]);
  }

  /** Stable idempotency key for seal ops (1.2.1). */
  idempotencyKey(stableInput: Buffer): string {
    return createHash("sha256")
      .update(`seal|${this.actorId}|${this.op}|`)
      .update(stableInput)
      .digest("hex");
  }
}

/**
 * Broken vault: shared mutable counter without atomicity narrative.
 * Demonstrates 3.3.1 race / 2.3.1 mutation flaws.
 */
export class BrokenSharedNonceVault {
  /** Intentionally shared — do not use in production paths. */
  static counter = 0;
  static nextNonce(): Buffer {
    BrokenSharedNonceVault.counter += 1;
    const buf = Buffer.alloc(NONCE_BYTES);
    buf.writeUInt32BE(BrokenSharedNonceVault.counter, 8);
    return buf;
  }
}

export function generateDataKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

export function sealAes256Gcm(input: SealInput, nonce: Buffer): SealedBox {
  assertKey(input.key);
  assertNonce(nonce);
  const aad = input.aad ?? Buffer.alloc(0);
  const cipher = createCipheriv("aes-256-gcm", input.key, nonce);
  if (aad.length > 0) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (tag.length !== TAG_BYTES) {
    throw new AttackError("aead", "Unexpected GCM tag length");
  }
  return { nonce: Buffer.from(nonce), ciphertext, tag, aad: Buffer.from(aad) };
}

export function openAes256Gcm(key: Buffer, box: SealedBox): Buffer {
  assertKey(key);
  assertNonce(box.nonce);
  if (box.tag.length !== TAG_BYTES) {
    throw new AttackError("aead_tag", "Invalid tag length");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, box.nonce);
  if (box.aad.length > 0) decipher.setAAD(box.aad);
  decipher.setAuthTag(box.tag);
  try {
    return Buffer.concat([decipher.update(box.ciphertext), decipher.final()]);
  } catch {
    // Fail closed — never return partial plaintext (3.2.1 / 4.6.1).
    throw new AttackError("aead_verify", "Authentication failed; plaintext withheld");
  }
}

/**
 * Educational break: AES-GCM with nonce reuse does not "crack AES",
 * but voids confidentiality for CTR-style keystream (same nonce+key).
 * For GCM we demonstrate the operational failure: second seal with same nonce
 * is detectable as a control violation and must be rejected by policy.
 */
export function detectNonceReuse(nonces: Buffer[]): boolean {
  const seen = new Set<string>();
  for (const n of nonces) {
    const hex = n.toString("hex");
    if (seen.has(hex)) return true;
    seen.add(hex);
  }
  return false;
}

/**
 * Classic stream-cipher style break when the same keystream is applied twice.
 * Uses AES-256-CTR (same underlying PRF family as GCM's counter mode) to show
 * C1⊕C2 = P1⊕P2 under nonce reuse — the narrative flaw, not a key recovery.
 */
export function demonstrateKeystreamReuseBreak(
  key: Buffer,
  nonce: Buffer,
  p1: Buffer,
  p2: Buffer,
): { c1xorc2: Buffer; p1xorp2: Buffer; matches: boolean } {
  assertKey(key);
  assertNonce(nonce);
  const c1 = aesCtr(key, nonce, p1);
  const c2 = aesCtr(key, nonce, p2);
  const c1xorc2 = xor(c1, c2);
  const p1xorp2 = xor(p1, p2);
  const matches =
    c1xorc2.length === p1xorp2.length && timingSafeEqual(c1xorc2, p1xorp2);
  return { c1xorc2, p1xorp2, matches };
}

function aesCtr(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  // 16-byte IV: 12-byte nonce + 4-byte counter starting at 1 (GCM-like layout).
  const iv = Buffer.alloc(16);
  nonce.copy(iv, 0, 0, 12);
  iv.writeUInt32BE(1, 12);
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function xor(a: Buffer, b: Buffer): Buffer {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function assertKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) {
    throw new AttackError("aead_key", `AES-256 key must be ${KEY_BYTES} bytes`);
  }
}

function assertNonce(nonce: Buffer): void {
  if (nonce.length !== NONCE_BYTES) {
    throw new AttackError("aead_nonce", `Nonce must be ${NONCE_BYTES} bytes`);
  }
}
