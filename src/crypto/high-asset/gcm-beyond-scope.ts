/**
 * AES-256-GCM bypasses *outside* the algorithm's mathematical core.
 * Perfect GCM still fails when the operational context is hostile.
 *
 * Physical power/EM are simulated as leakage oracles (software stand-ins).
 * Grover is modeled as effective keyspace reduction, not a real QPU.
 */

import { createHash, randomBytes } from "node:crypto";

import {
  generateDataKey,
  openAes256Gcm,
  sealAes256Gcm,
  type SealedBox,
} from "./aead.js";

export type BeyondResult = {
  vector: string;
  theoryHolds: boolean;
  detail: string;
  recovered?: string;
};

// ---------------------------------------------------------------------------
// Shared victim: perfect AES-256-GCM seal (unique nonce, full tag, AAD bind)
// ---------------------------------------------------------------------------

export type PerfectSeal = {
  key: Buffer;
  box: SealedBox;
  plaintext: string;
};

export function createPerfectGcmSeal(plaintext: string): PerfectSeal {
  const key = generateDataKey();
  const nonce = randomBytes(12); // CSPRNG — narrative assumes this is good
  const aad = Buffer.from("tenant-global|asset-1");
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext), aad }, nonce);
  return { key, box, plaintext };
}

// ---------------------------------------------------------------------------
// 1. Side-channel: cache/timing leakage of key material (software model)
// ---------------------------------------------------------------------------

/**
 * Simulates a cache-timing oracle: secret-dependent memory access pattern
 * leaks key bytes one at a time (classic software side-channel class).
 * Not real CPU cache; models the *narrative* that isolated execution is false.
 */
export function bypassSideChannelCacheTiming(seal: PerfectSeal): BeyondResult {
  // Victim "touches" a table at index = key[i], attacker measures which line.
  // Here the oracle directly returns key[i] — stand-in for recovered timing profile.
  const leakedKey = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    leakedKey[i] = sideChannelOracleTouch(seal.key, i);
  }

  const opened = openAes256Gcm(leakedKey, seal.box).toString("utf8");
  const ok = opened === seal.plaintext;

  return {
    vector: "1.side-channel-cache-timing",
    theoryHolds: ok,
    recovered: opened,
    detail: ok
      ? "Side-channel oracle recovered full AES-256 key from secret-dependent accesses; perfect GCM math never attacked."
      : "Side-channel key recovery failed.",
  };
}

function sideChannelOracleTouch(key: Buffer, index: number): number {
  // Model: attacker distinguishes cache line for key[index].
  const table = new Uint8Array(256);
  table[key[index]!] = 1;
  // "Probe" returns the index that was touched.
  for (let b = 0; b < 256; b++) {
    if (table[b] === 1) return b;
  }
  return 0;
}

/**
 * Power/EM class: simulated leakage of key-dependent Hamming weight per byte,
 * then brute each byte (256 tries) — educational stand-in for DPA-style recovery.
 */
export function bypassSideChannelPowerModel(seal: PerfectSeal): BeyondResult {
  const leakedKey = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    const weight = hammingWeight(seal.key[i]!);
    // Attacker tries all bytes with that Hamming weight (narrowed search).
    // For demo, oracle also leaks the byte when weight matches (strong leakage model).
    leakedKey[i] = recoverByteFromWeightOracle(seal.key[i]!, weight);
  }
  const opened = openAes256Gcm(leakedKey, seal.box).toString("utf8");
  return {
    vector: "1b.side-channel-power-em-model",
    theoryHolds: opened === seal.plaintext,
    recovered: opened,
    detail:
      opened === seal.plaintext
        ? "Power/EM leakage model recovered key bytes; algorithm core untouched."
        : "Power/EM model recovery failed.",
  };
}

function hammingWeight(byte: number): number {
  let n = byte;
  let c = 0;
  while (n) {
    c += n & 1;
    n >>= 1;
  }
  return c;
}

function recoverByteFromWeightOracle(real: number, weight: number): number {
  // Simulated: leakage identifies exact byte among weight class (strong channel).
  for (let b = 0; b < 256; b++) {
    if (hammingWeight(b) === weight && b === real) return b;
  }
  return real;
}

// ---------------------------------------------------------------------------
// 2. Quantum — Grover effective keyspace (model, not live QPU)
// ---------------------------------------------------------------------------

export function bypassGroverKeyspaceModel(): BeyondResult {
  const classicalBits = 256;
  const groverBits = classicalBits / 2; // Grover quadratic speedup
  const classicalWork = 2n ** BigInt(classicalBits);
  const groverWork = 2n ** BigInt(groverBits);

  // Theory: "brute force off the table" weakens from 2^256 to 2^128.
  // 2^128 is still infeasible today, but the *narrative claim* is reduced.
  const narrativeWeakened = groverWork < classicalWork && groverBits === 128;

  return {
    vector: "2.quantum-grover-keyspace",
    theoryHolds: narrativeWeakened,
    detail: narrativeWeakened
      ? `Grover reduces effective AES-256 search from 2^${classicalBits} to 2^${groverBits}. Classical "impossible" claim no longer holds against a cryptographically relevant quantum adversary (2^128 still huge, but narrative boundary is real).`
      : "Grover model did not show keyspace reduction.",
  };
}

// ---------------------------------------------------------------------------
// 3. Compromised operating environment (pre/post crypto)
// ---------------------------------------------------------------------------

/** Malware scrapes plaintext from process memory *before* seal. */
export function bypassCompromisedEnvironmentPreEncrypt(): BeyondResult {
  const plaintext = "ZOSMA|pre-encrypt-memory-scrape";
  // App holds plaintext in RAM; rootkit reads it before GCM runs.
  const memoryScraped = Buffer.from(plaintext).toString("utf8");

  // GCM still seals correctly afterward — irrelevant; asset already stolen.
  const seal = createPerfectGcmSeal(plaintext);
  const gcmStillValid = openAes256Gcm(seal.key, seal.box).toString("utf8") === plaintext;

  return {
    vector: "3a.compromised-env-pre-encrypt",
    theoryHolds: memoryScraped === plaintext && gcmStillValid,
    recovered: memoryScraped,
    detail:
      "Malware captured plaintext in RAM before encryption. Perfect GCM seal still verifies, but confidentiality already lost outside the algorithm.",
  };
}

/** Malware scrapes key from memory while GCM runs. */
export function bypassCompromisedEnvironmentKeyInRam(seal: PerfectSeal): BeyondResult {
  const scrapedKey = Buffer.from(seal.key); // hypervisor/rootkit read
  const opened = openAes256Gcm(scrapedKey, seal.box).toString("utf8");
  return {
    vector: "3b.compromised-env-key-in-ram",
    theoryHolds: opened === seal.plaintext,
    recovered: opened,
    detail:
      opened === seal.plaintext
        ? "Key scraped from process memory; attacker decrypts without breaking AES math."
        : "Key scrape path failed.",
  };
}

/** Plaintext accessible after decrypt in hostile host. */
export function bypassCompromisedEnvironmentPostDecrypt(seal: PerfectSeal): BeyondResult {
  const opened = openAes256Gcm(seal.key, seal.box);
  // Legitimate app decrypts; malware reads output buffer.
  const exfiltrated = opened.toString("utf8");
  return {
    vector: "3c.compromised-env-post-decrypt",
    theoryHolds: exfiltrated === seal.plaintext,
    recovered: exfiltrated,
    detail:
      "Host decrypts correctly; malware exfiltrates plaintext after GCM returns. Algorithm held; environment did not.",
  };
}

// ---------------------------------------------------------------------------
// 4. Weak / compromised RNG
// ---------------------------------------------------------------------------

/** Predictable nonce stream → forced nonce reuse → Forbidden Attack. */
export function bypassWeakRngPredictableNonce(): BeyondResult {
  // Flawed RNG: always returns the same "random" nonce.
  const weakNonce = () => Buffer.alloc(12, 0x11);
  const key = generateDataKey();
  const known = Buffer.from("ZOSMA|BEACON-000000000");
  const secret = Buffer.from("ZOSMA|weak-rng-secret0"); // same length as known

  const n1 = weakNonce();
  const n2 = weakNonce();
  const same = n1.equals(n2);

  const boxKnown = sealAes256Gcm({ key, plaintext: known }, n1);
  const boxSecret = sealAes256Gcm({ key, plaintext: secret }, n2);

  const keystream = xor(boxKnown.ciphertext, known);
  const recovered = xor(boxSecret.ciphertext, keystream).toString("utf8");

  return {
    vector: "4a.weak-rng-predictable-nonce",
    theoryHolds: same && recovered === secret.toString("utf8"),
    recovered,
    detail:
      same && recovered === secret.toString("utf8")
        ? "Weak RNG produced identical nonces; GCM used them 'correctly' but Forbidden Attack recovered the secret."
        : "Weak-RNG nonce path failed.",
  };
}

/** Predictable key material from weak seeding. */
export function bypassWeakRngPredictableKey(): BeyondResult {
  // Flawed keygen: key = SHA-256(low-entropy seed)
  const seed = "password"; // insufficient entropy
  const predictableKey = createHash("sha256").update(seed).digest();
  const attackerKey = createHash("sha256").update(seed).digest(); // same guess

  const nonce = randomBytes(12);
  const plaintext = "ZOSMA|predictable-key-asset";
  const box = sealAes256Gcm(
    { key: predictableKey, plaintext: Buffer.from(plaintext), aad: Buffer.from("t|1") },
    nonce,
  );
  const opened = openAes256Gcm(attackerKey, box).toString("utf8");

  return {
    vector: "4b.weak-rng-predictable-key",
    theoryHolds: opened === plaintext,
    recovered: opened,
    detail:
      opened === plaintext
        ? "Low-entropy key derivation was guessed; perfect GCM operations still decrypt for the attacker."
        : "Predictable-key path failed.",
  };
}

// ---------------------------------------------------------------------------
// 5. Human element (non-technical acquisition)
// ---------------------------------------------------------------------------

export function bypassHumanElementInsider(seal: PerfectSeal): BeyondResult {
  // Insider exports key through approved UI / social engineering — no crypto break.
  const keyFromInsider = Buffer.from(seal.key);
  const opened = openAes256Gcm(keyFromInsider, seal.box).toString("utf8");
  return {
    vector: "5a.human-insider-key-export",
    theoryHolds: opened === seal.plaintext,
    recovered: opened,
    detail:
      opened === seal.plaintext
        ? "Insider/social-engineering provided the key; AES-256-GCM decrypted as designed."
        : "Insider path failed.",
  };
}

export function bypassHumanElementStolenDevice(): BeyondResult {
  // Device stores key in plaintext file beside ciphertext (lost laptop).
  const seal = createPerfectGcmSeal("ZOSMA|stolen-laptop-secret");
  const disk = {
    ciphertextBundle: seal.box,
    keyFile: seal.key.toString("hex"), // narrative violation: key beside ciphertext
  };
  const stolenKey = Buffer.from(disk.keyFile, "hex");
  const opened = openAes256Gcm(stolenKey, disk.ciphertextBundle).toString("utf8");
  return {
    vector: "5b.human-stolen-device-key-on-disk",
    theoryHolds: opened === "ZOSMA|stolen-laptop-secret",
    recovered: opened,
    detail:
      opened === "ZOSMA|stolen-laptop-secret"
        ? "Stolen device had key stored unencrypted beside ciphertext; thief opens GCM without cryptanalysis."
        : "Stolen-device path failed.",
  };
}

// ---------------------------------------------------------------------------
// Control: perfect context — beyond-scope attacks that need leakage must fail
// if we only have public blob (no oracle, no leak, no insider).
// ---------------------------------------------------------------------------

export function controlPublicBlobOnlyNoBeyondScopeLeak(): BeyondResult {
  const seal = createPerfectGcmSeal("ZOSMA|still-secret-under-perfect-context");
  // Attacker has only public fields — no side channel, no malware, no weak RNG, no insider.
  const publicOnly = {
    nonce: seal.box.nonce,
    ciphertext: seal.box.ciphertext,
    tag: seal.box.tag,
    aad: seal.box.aad,
  };
  void publicOnly;
  // Cannot open without key.
  let blocked = false;
  try {
    openAes256Gcm(Buffer.alloc(32, 0), seal.box);
  } catch {
    blocked = true;
  }
  return {
    vector: "0.control-public-blob-only",
    theoryHolds: blocked,
    detail: blocked
      ? "With only public (nonce,AAD,C,T) and no beyond-scope leak, perfect GCM still withholds plaintext — theory boundary confirmed."
      : "Control failed: zero key opened the box.",
  };
}

export function runAllBeyondScopeBypasses(): BeyondResult[] {
  const seal = createPerfectGcmSeal("ZOSMA|global-asset-perfect-gcm");
  return [
    controlPublicBlobOnlyNoBeyondScopeLeak(),
    bypassSideChannelCacheTiming(seal),
    bypassSideChannelPowerModel(seal),
    bypassGroverKeyspaceModel(),
    bypassCompromisedEnvironmentPreEncrypt(),
    bypassCompromisedEnvironmentKeyInRam(seal),
    bypassCompromisedEnvironmentPostDecrypt(seal),
    bypassWeakRngPredictableNonce(),
    bypassWeakRngPredictableKey(),
    bypassHumanElementInsider(seal),
    bypassHumanElementStolenDevice(),
  ];
}

function xor(a: Buffer, b: Buffer): Buffer {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}
