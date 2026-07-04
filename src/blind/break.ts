/**
 * Blind breaker: reads ONLY public.json.
 * Never opens answers.json. Recovers secrets only via attacks.
 */

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { decodeMessage, decryptDigits, recoverPrivateKey } from "../rsa.js";
import type {
  BreakAttempt,
  BreakReport,
  PublicChallenge,
  PublicChallengeFile,
} from "./types.js";

export function runBlindBreak(publicPath: string, reportPath: string): BreakReport {
  const file = JSON.parse(readFileSync(publicPath, "utf8")) as PublicChallengeFile;
  if (file.version !== 1 || !Array.isArray(file.challenges)) {
    throw new Error("Invalid public challenge file");
  }

  const attempts: BreakAttempt[] = file.challenges.map((challenge) => attack(challenge));

  const report: BreakReport = {
    version: 1,
    brokenAt: new Date().toISOString(),
    attempts,
  };
  writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");
  return report;
}

function attack(challenge: PublicChallenge): BreakAttempt {
  switch (challenge.algorithm) {
    case "aes-256-gcm":
      return attackHardenedGcm(challenge);
    case "aes-256-ctr":
      return attackNonceReuseCtr(challenge);
    case "textbook-rsa":
      return attackTextbookRsa(challenge);
    default:
      return {
        id: challenge.id,
        status: "failed",
        method: "none",
        detail: `No attack implemented for algorithm ${challenge.algorithm}`,
      };
  }
}

/** Proper AEAD with unknown key: cannot open. */
function attackHardenedGcm(challenge: PublicChallenge): BreakAttempt {
  const { ciphertextHex, tagHex, nonceHex } = challenge.payload;
  if (
    typeof ciphertextHex !== "string" ||
    typeof tagHex !== "string" ||
    typeof nonceHex !== "string"
  ) {
    return {
      id: challenge.id,
      status: "failed",
      method: "gcm-bruteforce-rejected",
      detail: "Malformed public payload.",
    };
  }

  // Blind attacker has no key. Exhaustive search of 2^256 is infeasible.
  return {
    id: challenge.id,
    status: "failed",
    method: "no-key-aes-256-gcm",
    detail:
      "AES-256-GCM with unknown key and unique nonce: no feasible blind recovery. " +
      `Public blob sizes ct=${ciphertextHex.length / 2}B tag=${tagHex.length / 2}B nonce=${nonceHex.length / 2}B.`,
  };
}

/**
 * Nonce reuse with a public beacon plaintext:
 * keystream = C_beacon ⊕ P_beacon; secret = C_secret ⊕ keystream.
 * AES key never required.
 */
function attackNonceReuseCtr(challenge: PublicChallenge): BreakAttempt {
  const p = challenge.payload;
  const beaconCtHex = p.beaconCiphertextHex;
  const secretCtHex = p.secretCiphertextHex;
  const beaconPt = p.knownBeaconPlaintext;

  if (
    typeof beaconCtHex !== "string" ||
    typeof secretCtHex !== "string" ||
    typeof beaconPt !== "string"
  ) {
    return {
      id: challenge.id,
      status: "failed",
      method: "ctr-nonce-reuse",
      detail: "Missing beacon/secret ciphertexts or public beacon plaintext.",
    };
  }

  const cBeacon = Buffer.from(beaconCtHex, "hex");
  const cSecret = Buffer.from(secretCtHex, "hex");
  const pBeacon = Buffer.from(beaconPt, "utf8");
  if (cBeacon.length !== pBeacon.length || cSecret.length !== cBeacon.length) {
    return {
      id: challenge.id,
      status: "failed",
      method: "ctr-nonce-reuse",
      detail: "Length mismatch between beacon and secret streams.",
    };
  }

  const keystream = xor(cBeacon, pBeacon);
  const secret = xor(cSecret, keystream).toString("utf8");

  return {
    id: challenge.id,
    status: "broken",
    method: "ctr-nonce-reuse-known-beacon",
    recoveredPlaintext: secret,
    detail:
      "Recovered secret via nonce-reuse keystream cancel against public beacon (AES key never used).",
  };
}

function attackTextbookRsa(challenge: PublicChallenge): BreakAttempt {
  const eRaw = challenge.payload.e;
  const nRaw = challenge.payload.n;
  const digitsRaw = challenge.payload.ciphertextDigits;

  if (typeof eRaw !== "string" || typeof nRaw !== "string" || !Array.isArray(digitsRaw)) {
    return {
      id: challenge.id,
      status: "failed",
      method: "rsa-factor",
      detail: "Malformed RSA public payload.",
    };
  }

  const e = BigInt(eRaw);
  const n = BigInt(nRaw);
  const digits = digitsRaw.map((d) => BigInt(String(d)));

  // Blind factoring of public N (trial division — works for live-demo moduli 15/21).
  const factors = trialFactor(n);
  if (!factors) {
    return {
      id: challenge.id,
      status: "failed",
      method: "rsa-factor",
      detail: `Could not factor N=${n} with bounded trial division.`,
    };
  }

  const { p, q } = factors;
  const privateKey = recoverPrivateKey({ e, n }, p, q);
  const plainDigits = decryptDigits(digits, privateKey);
  const plaintext = decodeMessage(plainDigits, n);

  return {
    id: challenge.id,
    status: "broken",
    method: "rsa-factor-recover-d",
    recoveredPlaintext: plaintext,
    detail: `Factored N=${n} into (${p},${q}), recovered d, decrypted without being given private key.`,
  };
}

function trialFactor(n: bigint): { p: bigint; q: bigint } | null {
  if (n % 2n === 0n) return { p: 2n, q: n / 2n };
  const limit = 1_000_000n;
  for (let i = 3n; i * i <= n && i <= limit; i += 2n) {
    if (n % i === 0n) {
      const other = n / i;
      return i <= other ? { p: i, q: other } : { p: other, q: i };
    }
  }
  return null;
}

function xor(a: Buffer, b: Buffer): Buffer {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

export function defaultPaths(root: string): { publicPath: string; reportPath: string; answersPath: string } {
  const dir = path.join(root, "challenges", "blind");
  return {
    publicPath: path.join(dir, "public.json"),
    reportPath: path.join(dir, "break-report.json"),
    answersPath: path.join(dir, "answers.json"),
  };
}
