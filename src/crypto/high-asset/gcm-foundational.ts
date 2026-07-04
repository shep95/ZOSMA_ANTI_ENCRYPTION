/**
 * Foundational-limits theory for AES-256-GCM.
 *
 * Premise (absolute under current physics/math):
 *   Flawless GCM + no side-channels + pristine host + no known classical/quantum
 *   algorithm break ⇒ reading ciphertext without the key is impossible.
 *
 * "Bypass vectors" here are NOT practical attacks. They are hypothetical
 * paradigm shifts. Under current reality they are blocked. Only if a
 * breakthrough oracle is granted does the narrative of "unbreakable" collapse.
 */

import { createHash, randomBytes } from "node:crypto";

import {
  generateDataKey,
  openAes256Gcm,
  sealAes256Gcm,
  type SealedBox,
} from "./aead.js";

export type FoundationalResult = {
  vector: string;
  /** Theory claim validated for this row. */
  theoryHolds: boolean;
  /** Whether plaintext was recovered. */
  plaintextRecovered: boolean;
  recovered?: string;
  detail: string;
};

export type PerfectWorld = {
  key: Buffer;
  box: SealedBox;
  plaintext: string;
  /** Entropy seed used only inside the sealed world — not published. */
  entropySecret: Buffer;
};

/** Flawless seal: unique nonce from CSPRNG, full tag, AAD bind, key never published. */
export function createFlawlessWorld(plaintext: string): PerfectWorld {
  const entropySecret = randomBytes(32);
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const aad = Buffer.from("tenant-perfect|asset-0");
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext), aad }, nonce);
  return { key, box, plaintext, entropySecret };
}

export function publicView(world: PerfectWorld): {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  aad: Buffer;
} {
  return {
    nonce: world.box.nonce,
    ciphertext: world.box.ciphertext,
    tag: world.box.tag,
    aad: world.box.aad,
  };
}

// ---------------------------------------------------------------------------
// 0. Absolute premise under current physics: no leak ⇒ cannot read
// ---------------------------------------------------------------------------

export function premiseNoLeakCannotRead(world: PerfectWorld): FoundationalResult {
  const pub = publicView(world);
  void pub;

  // Attacker attempts: zero key, random keys, hash-of-public-fields — all fail.
  const guesses = [
    Buffer.alloc(32, 0),
    randomBytes(32),
    createHash("sha256").update(world.box.ciphertext).update(world.box.nonce).digest(),
  ];

  let anyOpened = false;
  for (const g of guesses) {
    try {
      openAes256Gcm(g, world.box);
      anyOpened = true;
    } catch {
      // expected
    }
  }

  return {
    vector: "0.premise-no-leak-cannot-read",
    theoryHolds: !anyOpened,
    plaintextRecovered: false,
    detail: !anyOpened
      ? "Under flawless GCM with only public (nonce,AAD,C,T), no guess recovered plaintext — current physics: impossible without the key."
      : "UNEXPECTED: opened without key — premise violated.",
  };
}

// ---------------------------------------------------------------------------
// 1. Unknown mathematical weakness (unknown unknown)
// ---------------------------------------------------------------------------

/**
 * Under current mathematics: no non-brute-force AES inverse exists in this program.
 * With a hypothetical "breakthrough oracle" (simulating future theorem), inversion works.
 * The oracle is NOT derived from ciphertext alone — it is an injected paradigm shift.
 */
export function vectorUnknownMathWeakness(
  world: PerfectWorld,
  breakthroughOracle: boolean,
): FoundationalResult {
  if (!breakthroughOracle) {
    // Attempt "clever" algebraic shortcuts — none exist here.
    const failed = tryAlgebraicShortcuts(world);
    return {
      vector: "1.unknown-math-weakness",
      theoryHolds: !failed.recovered,
      plaintextRecovered: false,
      detail:
        "No non-brute-force AES inverse under current mathematics. Unknown-unknown breakthrough not granted — attack blocked.",
    };
  }

  // Hypothetical: future theorem yields an efficient inverse oracle.
  // We model it as an external capability that maps C→P without publishing the key
  // to the attacker API — but scientifically this *is* a new law of math, not a leak.
  const recovered = hypotheticalAesInverseOracle(world).toString("utf8");
  return {
    vector: "1.unknown-math-weakness-with-breakthrough",
    theoryHolds: recovered === world.plaintext,
    plaintextRecovered: recovered === world.plaintext,
    recovered,
    detail:
      recovered === world.plaintext
        ? "IF a fundamental AES inverse were discovered, plaintext is recoverable without a conventional leak. (Simulated breakthrough oracle — not real cryptanalysis.)"
        : "Breakthrough oracle simulation failed.",
  };
}

function tryAlgebraicShortcuts(world: PerfectWorld): { recovered: boolean } {
  // Placeholder "attacks" that do not work: linearize S-box, treat as OTP, etc.
  const nonsense = createHash("sha256").update(world.box.ciphertext).digest();
  try {
    openAes256Gcm(nonsense, world.box);
    return { recovered: true };
  } catch {
    return { recovered: false };
  }
}

/** Simulates a future mathematical inverse — only callable when breakthrough is granted. */
function hypotheticalAesInverseOracle(world: PerfectWorld): Buffer {
  // This stands in for "new mathematics," not key theft.
  return openAes256Gcm(world.key, world.box);
}

// ---------------------------------------------------------------------------
// 2. P=NP (computational complexity breakthrough)
// ---------------------------------------------------------------------------

export function vectorPvsNP(
  world: PerfectWorld,
  pEqualsNpOracle: boolean,
): FoundationalResult {
  if (!pEqualsNpOracle) {
    // Under standard assumption P≠NP (or AES not poly-time invertible), blocked.
    const polyGuesses = 1000;
    let hit = false;
    for (let i = 0; i < polyGuesses; i++) {
      try {
        openAes256Gcm(randomBytes(32), world.box);
        hit = true;
        break;
      } catch {
        // continue
      }
    }
    return {
      vector: "2.p-vs-np-standard-assumption",
      theoryHolds: !hit,
      plaintextRecovered: false,
      detail: !hit
        ? `Under standard complexity assumptions, ${polyGuesses} poly-bounded key guesses failed. P=NP breakthrough not granted — brute force remains off the table.`
        : "Unexpected hit under standard assumption.",
    };
  }

  // Hypothetical P=NP: an efficient inverter exists (modeled as poly-time oracle).
  const recovered = hypotheticalPolyTimeInverter(world).toString("utf8");
  return {
    vector: "2.p-equals-np-breakthrough",
    theoryHolds: recovered === world.plaintext,
    plaintextRecovered: recovered === world.plaintext,
    recovered,
    detail:
      recovered === world.plaintext
        ? "IF P=NP (or AES admitted a poly-time inverse), the 'brute force off the table' narrative collapses. (Simulated complexity oracle.)"
        : "P=NP oracle simulation failed.",
  };
}

function hypotheticalPolyTimeInverter(world: PerfectWorld): Buffer {
  return openAes256Gcm(world.key, world.box);
}

// ---------------------------------------------------------------------------
// 3. Deterministic universe / predictable entropy (philosophical)
// ---------------------------------------------------------------------------

export function vectorDeterministicUniverse(
  world: PerfectWorld,
  laplaceOracle: boolean,
): FoundationalResult {
  if (!laplaceOracle) {
    // Without perfect physics model of entropy, CSPRNG outputs remain unpredictable.
    const predictedKey = createHash("sha256").update("laplace-guess").digest();
    let opened = false;
    try {
      openAes256Gcm(predictedKey, world.box);
      opened = true;
    } catch {
      // expected
    }
    return {
      vector: "3.deterministic-universe-no-laplace",
      theoryHolds: !opened,
      plaintextRecovered: false,
      detail: !opened
        ? "Without a Laplace oracle over physical entropy, keys/nonces stay unpredictable — philosophical determinism not operationally available."
        : "Unexpected open without Laplace oracle.",
    };
  }

  // Hypothetical: entity models all entropy → predicts key material.
  // Modeled as oracle access to entropySecret-derived key schedule (paradigm shift).
  const predictedKey = world.key; // Laplace demon knows the microstate
  const recovered = openAes256Gcm(predictedKey, world.box).toString("utf8");
  return {
    vector: "3.deterministic-universe-with-laplace",
    theoryHolds: recovered === world.plaintext,
    plaintextRecovered: recovered === world.plaintext,
    recovered,
    detail:
      recovered === world.plaintext
        ? "IF entropy were fully predictable, 'fresh unpredictable nonces/keys' collapses. (Simulated Laplace oracle — not a GCM bug.)"
        : "Laplace simulation failed.",
  };
}

// ---------------------------------------------------------------------------
// 4. Coordinated temporal manipulation (metaphysical)
// ---------------------------------------------------------------------------

export function vectorTemporalManipulation(
  world: PerfectWorld,
  timelineOracle: boolean,
): FoundationalResult {
  if (!timelineOracle) {
    return {
      vector: "4.temporal-manipulation-unavailable",
      theoryHolds: true,
      plaintextRecovered: false,
      detail:
        "No temporal rewrite capability under known physics. Past key exposure / nonce reuse cannot be retroactively inserted. Attack blocked.",
    };
  }

  // Hypothetical: rewind to a branch where key was exposed, then decrypt in present.
  const recovered = openAes256Gcm(world.key, world.box).toString("utf8");
  return {
    vector: "4.temporal-manipulation-with-oracle",
    theoryHolds: recovered === world.plaintext,
    plaintextRecovered: recovered === world.plaintext,
    recovered,
    detail:
      recovered === world.plaintext
        ? "IF an adversary could rewrite timeline state to expose the key, perfect present-tense GCM is moot. (Metaphysical oracle — not engineering.)"
        : "Timeline oracle simulation failed.",
  };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export function runFoundationalTheoryLab(): FoundationalResult[] {
  const world = createFlawlessWorld("ZOSMA|foundational-limit-asset");

  return [
    // Current physics: cannot read
    premiseNoLeakCannotRead(world),

    // Theoretical vectors WITHOUT breakthroughs — must stay blocked
    vectorUnknownMathWeakness(world, false),
    vectorPvsNP(world, false),
    vectorDeterministicUniverse(world, false),
    vectorTemporalManipulation(world, false),

    // Same vectors WITH hypothetical breakthroughs — narrative would collapse
    vectorUnknownMathWeakness(world, true),
    vectorPvsNP(world, true),
    vectorDeterministicUniverse(world, true),
    vectorTemporalManipulation(world, true),
  ];
}
