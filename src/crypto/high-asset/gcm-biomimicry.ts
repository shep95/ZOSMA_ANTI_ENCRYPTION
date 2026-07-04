/**
 * Moth & Butterfly biomimicry narrative for AES-256-GCM.
 *
 * Defense mimicry (under perfect conditions):
 *   1. Radar-absorbing scales  → AES-256 key (brute force invisible)
 *   2. Ultrasonic evasion      → CTR keystream + fresh nonce
 *   3. Structural color        → GHASH authentication tag
 *
 * Anti-biomimicry "predators" only work if the rules of nature change
 * (new math, P=NP, Laplace entropy, timeline rewrite, tag→plaintext oracle).
 * Under current physics: cannot read ciphertext without the key.
 */

import { createHash, randomBytes } from "node:crypto";

import {
  generateDataKey,
  openAes256Gcm,
  sealAes256Gcm,
  type SealedBox,
} from "./aead.js";

export type BiomimicryResult = {
  vector: string;
  mimicry: string;
  predator: string;
  theoryHolds: boolean;
  plaintextRecovered: boolean;
  recovered?: string;
  detail: string;
};

export type Ecosystem = {
  key: Buffer;
  box: SealedBox;
  plaintext: string;
};

/** Perfect GCM seal — moth/butterfly defenses fully intact. */
export function createPerfectEcosystem(plaintext: string): Ecosystem {
  const key = generateDataKey();
  const nonce = randomBytes(12);
  const aad = Buffer.from("biome|asset-moth-butterfly");
  const box = sealAes256Gcm({ key, plaintext: Buffer.from(plaintext), aad }, nonce);
  return { key, box, plaintext };
}

// ---------------------------------------------------------------------------
// Baseline: bat with only sonar (public ciphertext) cannot see the moth
// ---------------------------------------------------------------------------

export function batSonarOnlyCannotSee(eco: Ecosystem): BiomimicryResult {
  const guesses = [
    Buffer.alloc(32, 0),
    randomBytes(32),
    createHash("sha256").update(eco.box.ciphertext).update(eco.box.tag).digest(),
  ];
  let seen = false;
  for (const g of guesses) {
    try {
      openAes256Gcm(g, eco.box);
      seen = true;
    } catch {
      // radar absorbed
    }
  }
  return {
    vector: "0.bat-sonar-only",
    mimicry: "Full moth+butterfly defense (key, nonce, GHASH)",
    predator: "Classical attacker with only (nonce, AAD, C, T)",
    theoryHolds: !seen,
    plaintextRecovered: false,
    detail: !seen
      ? "Sonar (public blob) alone cannot see the moth. Radar-absorbing scales, evasion, and structural color all hold under current physics."
      : "UNEXPECTED: sonar recovered plaintext.",
  };
}

// ---------------------------------------------------------------------------
// 1. Radar-absorbing scales (AES-256 key)
// ---------------------------------------------------------------------------

export function scalesWithoutNewSense(eco: Ecosystem): BiomimicryResult {
  // No new mathematical "sense" — algebraic shortcuts fail
  let opened = false;
  try {
    openAes256Gcm(createHash("sha256").update("invert-spn").digest(), eco.box);
    opened = true;
  } catch {
    // blocked
  }
  return {
    vector: "1a.scales-no-new-sense",
    mimicry: "Radar-absorbing scales (AES-256 key / 2^256)",
    predator: "Known classical/quantum algorithms only",
    theoryHolds: !opened,
    plaintextRecovered: false,
    detail: !opened
      ? "No non-brute-force SPN inverse exists in current mathematics. Scales remain radar-invisible."
      : "Unexpected open.",
  };
}

export function scalesWithNewSenseOracle(eco: Ecosystem): BiomimicryResult {
  // Hypothetical: new mathematical sense inverts AES without conventional key leak
  const recovered = antiBiomimicryMathSense(eco).toString("utf8");
  return {
    vector: "1b.scales-with-new-sense-oracle",
    mimicry: "Radar-absorbing scales (AES-256 key)",
    predator: "Fundamental mathematical inversion / P=NP-class breakthrough (simulated)",
    theoryHolds: recovered === eco.plaintext,
    plaintextRecovered: recovered === eco.plaintext,
    recovered,
    detail:
      recovered === eco.plaintext
        ? "IF a new 'sense' (AES inverse theorem / complexity collapse) existed, scales would not hide the moth. Simulated only — not real cryptanalysis."
        : "New-sense oracle failed.",
  };
}

export function scalesComplexityRedefinition(
  eco: Ecosystem,
  pEqualsNp: boolean,
): BiomimicryResult {
  if (!pEqualsNp) {
    let hit = false;
    for (let i = 0; i < 500; i++) {
      try {
        openAes256Gcm(randomBytes(32), eco.box);
        hit = true;
        break;
      } catch {
        // continue
      }
    }
    return {
      vector: "1c.scales-complexity-standard",
      mimicry: "Radar-absorbing scales (computational hardness)",
      predator: "Poly-bounded search under P≠NP assumption",
      theoryHolds: !hit,
      plaintextRecovered: false,
      detail: !hit
        ? "Under standard complexity assumptions, scales stay absorbing — right 'frequency' not found."
        : "Unexpected hit.",
    };
  }
  const recovered = antiBiomimicryMathSense(eco).toString("utf8");
  return {
    vector: "1d.scales-complexity-p-equals-np",
    mimicry: "Radar-absorbing scales",
    predator: "P=NP / problem-class redefinition (simulated)",
    theoryHolds: recovered === eco.plaintext,
    plaintextRecovered: recovered === eco.plaintext,
    recovered,
    detail:
      recovered === eco.plaintext
        ? "IF hardness were redefined (P=NP), scales were never inherently absorbing — we lacked the frequency. Simulated oracle."
        : "Complexity oracle failed.",
  };
}

// ---------------------------------------------------------------------------
// 2. Ultrasonic evasion (CTR + nonce)
// ---------------------------------------------------------------------------

export function evasionWithoutLaplace(eco: Ecosystem): BiomimicryResult {
  const fakeNonceSeed = createHash("sha256").update("predict-flight").digest().subarray(0, 12);
  // Predicting nonce alone is insufficient without key; try derived key from seed
  const fakeKey = createHash("sha256").update(fakeNonceSeed).digest();
  let opened = false;
  try {
    openAes256Gcm(fakeKey, eco.box);
    opened = true;
  } catch {
    // blocked
  }
  return {
    vector: "2a.evasion-no-laplace",
    mimicry: "Ultrasonic evasion (fresh nonce + CTR keystream)",
    predator: "Guess entropy without physics omniscience",
    theoryHolds: !opened,
    plaintextRecovered: false,
    detail: !opened
      ? "Flight path (nonce/key entropy) stays unpredictable without a Laplace model of physical entropy."
      : "Unexpected open.",
  };
}

export function evasionWithLaplaceOracle(eco: Ecosystem): BiomimicryResult {
  // Hypothetical: perfect model of entropy seed → knows key (and could know nonce)
  const recovered = openAes256Gcm(eco.key, eco.box).toString("utf8");
  return {
    vector: "2b.evasion-with-laplace-oracle",
    mimicry: "Ultrasonic evasion (nonce/keystream)",
    predator: "Absolute deterministic prediction of randomness (simulated Laplace demon)",
    theoryHolds: recovered === eco.plaintext,
    plaintextRecovered: recovered === eco.plaintext,
    recovered,
    detail:
      recovered === eco.plaintext
        ? "IF entropy inputs were fully predictable, evasion patterns become deterministic. Not a GCM bug — collapse of unpredictability."
        : "Laplace oracle failed.",
  };
}

export function evasionWithTemporalOracle(eco: Ecosystem): BiomimicryResult {
  // Hypothetical: see future CSPRNG output / rewrite past exposure
  const recovered = openAes256Gcm(eco.key, eco.box).toString("utf8");
  return {
    vector: "2c.evasion-with-temporal-oracle",
    mimicry: "Ultrasonic evasion",
    predator: "Temporal manipulation / retroactive prediction (metaphysical, simulated)",
    theoryHolds: recovered === eco.plaintext,
    plaintextRecovered: recovered === eco.plaintext,
    recovered,
    detail:
      recovered === eco.plaintext
        ? "IF spacetime could be rewritten to expose key/nonce state, present-tense evasion is moot. Metaphysical oracle only."
        : "Temporal oracle failed.",
  };
}

// ---------------------------------------------------------------------------
// 3. Structural color (GHASH tag)
// ---------------------------------------------------------------------------

export function colorWithoutNewLight(eco: Ecosystem): BiomimicryResult {
  // Try to "read structure" from C+T alone (no key) — no known inversion
  const guessFromTag = createHash("sha256")
    .update(eco.box.ciphertext)
    .update(eco.box.tag)
    .digest();
  let opened = false;
  try {
    openAes256Gcm(guessFromTag, eco.box);
    opened = true;
  } catch {
    // blocked
  }

  // Tamper tag — structural color "breaks" (auth fails), no plaintext
  const tampered = {
    ...eco.box,
    tag: Buffer.from(eco.box.tag),
  };
  tampered.tag[0] ^= 0xff;
  let tamperLeaked = false;
  try {
    openAes256Gcm(eco.key, tampered);
    tamperLeaked = true;
  } catch {
    // color broke — refused
  }

  return {
    vector: "3a.color-no-new-light",
    mimicry: "Structural color (GHASH tag)",
    predator: "Passive read of C+T / surface tamper",
    theoryHolds: !opened && !tamperLeaked,
    plaintextRecovered: false,
    detail:
      !opened && !tamperLeaked
        ? "Tag+ciphertext do not yield plaintext without key. Tamper breaks structural color and releases nothing."
        : "Unexpected structural-color failure.",
  };
}

export function colorWithBlueprintOracle(eco: Ecosystem): BiomimicryResult {
  // Hypothetical: C+T contain invertible blueprint of P (new math on GF(2^128) + AES)
  const recovered = antiBiomimicryStructuralBlueprint(eco).toString("utf8");
  return {
    vector: "3b.color-with-blueprint-oracle",
    mimicry: "Structural color (GHASH)",
    predator: "Direct plaintext extraction from valid (C,T) without key (simulated math flaw)",
    theoryHolds: recovered === eco.plaintext,
    plaintextRecovered: recovered === eco.plaintext,
    recovered,
    detail:
      recovered === eco.plaintext
        ? "IF (C,T) inverted to P without K, structural color would be a blueprint, not a seal. No such algorithm known — simulated only."
        : "Blueprint oracle failed.",
  };
}

export function colorWithQuantumForgeryNote(eco: Ecosystem): BiomimicryResult {
  // Advanced quantum forgery is interactive (forge tags), not passive read.
  // Under current knowledge: passive read still blocked; forgery without key unknown.
  let passiveRead = false;
  try {
    openAes256Gcm(randomBytes(32), eco.box);
    passiveRead = true;
  } catch {
    // blocked
  }
  return {
    vector: "3c.color-quantum-forgery-not-passive-read",
    mimicry: "Structural color (GHASH)",
    predator: "Unknown advanced quantum forgery (not a passive ciphertext read)",
    theoryHolds: !passiveRead,
    plaintextRecovered: false,
    detail: !passiveRead
      ? "Even hypothesizing quantum tag forgery: that is interactive authenticity attack, not passive 'read C without K'. Passive remains unread."
      : "Unexpected passive read.",
  };
}

// ---------------------------------------------------------------------------
// Oracles = paradigm shifts (not engineering)
// ---------------------------------------------------------------------------

function antiBiomimicryMathSense(eco: Ecosystem): Buffer {
  return openAes256Gcm(eco.key, eco.box);
}

function antiBiomimicryStructuralBlueprint(eco: Ecosystem): Buffer {
  return openAes256Gcm(eco.key, eco.box);
}

export function runBiomimicryTheoryLab(): BiomimicryResult[] {
  const eco = createPerfectEcosystem("ZOSMA|moth-butterfly-asset");
  return [
    batSonarOnlyCannotSee(eco),
    scalesWithoutNewSense(eco),
    scalesComplexityRedefinition(eco, false),
    evasionWithoutLaplace(eco),
    colorWithoutNewLight(eco),
    colorWithQuantumForgeryNote(eco),
    // Anti-biomimicry oracles (rules of nature change)
    scalesWithNewSenseOracle(eco),
    scalesComplexityRedefinition(eco, true),
    evasionWithLaplaceOracle(eco),
    evasionWithTemporalOracle(eco),
    colorWithBlueprintOracle(eco),
  ];
}
