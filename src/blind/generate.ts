/**
 * Create blind challenges: public ciphertext only.
 * Secrets go to answers.json (referee). Breaker never receives them.
 */

import { createCipheriv, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import {
  NonceVault,
  generateDataKey,
  sealAes256Gcm,
} from "../crypto/high-asset/aead.js";
import { encryptMessage, generateLiveKeypair } from "../rsa.js";
import type { AnswersFile, PublicChallenge, PublicChallengeFile } from "./types.js";

/** Public framing known to attackers studying the protocol — not the secret payload. */
export const PUBLIC_PREFIX = "ZOSMA|";

/** Equal-length secrets so CTR nonce-reuse yields aligned P1⊕P2. */
const SECRETS = [
  "alpha-vault-7741",
  "beta-ledger-9902",
  "gamma-wire-9903",
  "delta-root-5528",
] as const;

function aesCtr(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const iv = Buffer.alloc(16);
  nonce.copy(iv, 0, 0, 12);
  iv.writeUInt32BE(1, 12);
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function generateBlindChallenges(outDir: string): {
  publicPath: string;
  answersPath: string;
} {
  mkdirSync(outDir, { recursive: true });

  const challenges: PublicChallenge[] = [];
  const answers: AnswersFile = {
    version: 1,
    answers: [],
    material: {},
  };

  // --- 1) HA-1 style: proper AES-256-GCM (unique nonces) — must NOT break ---
  {
    const key = generateDataKey();
    const vault = new NonceVault("blind-ha1", "seal");
    const plaintext = `${PUBLIC_PREFIX}${SECRETS[0]}`;
    const aad = Buffer.from("tenant-blind|obj-1");
    const box = sealAes256Gcm(
      { key, plaintext: Buffer.from(plaintext, "utf8"), aad },
      vault.nextNonce(),
    );
    challenges.push({
      id: "ha1-gcm-hardened",
      tier: "ha.aes256_gcm_hsm",
      algorithm: "aes-256-gcm",
      publicProtocolNotes:
        "NIST SP 800-38D AES-256-GCM: secret 256-bit key withheld; unique 96-bit nonce; AAD-bound; 128-bit tag; verify-then-decrypt. Public fields only: nonce, AAD, C, T.",
      payload: {
        narrativeId: "aes-256-gcm",
        standard: "NIST SP 800-38D",
        nonceHex: box.nonce.toString("hex"),
        ciphertextHex: box.ciphertext.toString("hex"),
        tagHex: box.tag.toString("hex"),
        aadHex: box.aad.toString("hex"),
      },
    });
    answers.answers.push({ id: "ha1-gcm-hardened", plaintext, expectBreak: false });
    answers.material["ha1-gcm-hardened"] = { keyHex: key.toString("hex") };
  }

  // --- 2) HA-1 flawed: AES-CTR nonce reuse with public beacon (taxonomy 4.6.2) ---
  // Public beacon is protocol-visible; secret is not. Same nonce ⇒ keystream recovery.
  {
    const key = generateDataKey();
    const nonce = randomBytes(12);
    const secretBody = SECRETS[1];
    const beaconBody = "BEACON-000000000".slice(0, secretBody.length); // public protocol constant
    const beacon = `${PUBLIC_PREFIX}${beaconBody}`;
    const secret = `${PUBLIC_PREFIX}${secretBody}`;
    if (beacon.length !== secret.length) {
      throw new Error("Beacon and secret must be equal length for CTR nonce-reuse lab");
    }
    const cBeacon = aesCtr(key, nonce, Buffer.from(beacon, "utf8"));
    const cSecret = aesCtr(key, nonce, Buffer.from(secret, "utf8"));
    challenges.push({
      id: "ha1-ctr-nonce-reuse",
      tier: "ha.aes256_gcm_hsm",
      algorithm: "aes-256-ctr",
      publicProtocolNotes:
        "Operator reused nonce for a public beacon and a secret. Beacon plaintext is public protocol knowledge; AES key withheld.",
      payload: {
        nonceHex: nonce.toString("hex"),
        beaconCiphertextHex: cBeacon.toString("hex"),
        secretCiphertextHex: cSecret.toString("hex"),
        knownBeaconPlaintext: beacon,
      },
    });
    answers.answers.push({ id: "ha1-ctr-nonce-reuse", plaintext: secret, expectBreak: true });
    answers.material["ha1-ctr-nonce-reuse"] = { keyHex: key.toString("hex"), beacon, secret };
  }

  // --- 3) Textbook RSA N=15 — breakable by factoring public N (no d/p/q given) ---
  {
    const { publicKey, privateKey, p, q } = generateLiveKeypair(15);
    const plaintext = `${PUBLIC_PREFIX}${SECRETS[3]}`;
    const ciphertext = encryptMessage(plaintext, publicKey);
    challenges.push({
      id: "rsa15-textbook",
      tier: "quantum.shor_rsa",
      algorithm: "textbook-rsa",
      publicProtocolNotes:
        "Public (e,N) and ciphertext digits only. Private d and factors withheld. Framing prefix 'ZOSMA|'.",
      payload: {
        e: publicKey.e.toString(),
        n: publicKey.n.toString(),
        ciphertextDigits: ciphertext.map(String),
        framingPrefix: PUBLIC_PREFIX,
      },
    });
    answers.answers.push({ id: "rsa15-textbook", plaintext, expectBreak: true });
    answers.material["rsa15-textbook"] = {
      d: privateKey.d.toString(),
      p: p.toString(),
      q: q.toString(),
    };
  }

  // --- 4) Textbook RSA N=21 — second RSA blind target ---
  {
    const { publicKey, privateKey, p, q } = generateLiveKeypair(21);
    const plaintext = `${PUBLIC_PREFIX}epsilon-core-1188`;
    const ciphertext = encryptMessage(plaintext, publicKey);
    challenges.push({
      id: "rsa21-textbook",
      tier: "quantum.shor_rsa",
      algorithm: "textbook-rsa",
      publicProtocolNotes:
        "Public (e,N) and ciphertext digits only. Private d and factors withheld.",
      payload: {
        e: publicKey.e.toString(),
        n: publicKey.n.toString(),
        ciphertextDigits: ciphertext.map(String),
        framingPrefix: PUBLIC_PREFIX,
      },
    });
    answers.answers.push({ id: "rsa21-textbook", plaintext, expectBreak: true });
    answers.material["rsa21-textbook"] = {
      d: privateKey.d.toString(),
      p: p.toString(),
      q: q.toString(),
    };
  }

  // --- 5) Second hardened GCM message — must NOT break ---
  {
    const key = generateDataKey();
    const vault = new NonceVault("blind-ha1-b", "seal");
    const plaintext = `${PUBLIC_PREFIX}omega-sealed-0001`;
    const box = sealAes256Gcm(
      { key, plaintext: Buffer.from(plaintext, "utf8"), aad: Buffer.from("tenant-blind|obj-9") },
      vault.nextNonce(),
    );
    challenges.push({
      id: "ha1-gcm-hardened-2",
      tier: "ha.aes256_gcm_hsm",
      algorithm: "aes-256-gcm",
      publicProtocolNotes:
        "Second independent NIST SP 800-38D AES-256-GCM seal. Key withheld. Unique nonce. Public fields only: nonce, AAD, C, T.",
      payload: {
        narrativeId: "aes-256-gcm",
        standard: "NIST SP 800-38D",
        nonceHex: box.nonce.toString("hex"),
        ciphertextHex: box.ciphertext.toString("hex"),
        tagHex: box.tag.toString("hex"),
        aadHex: box.aad.toString("hex"),
      },
    });
    answers.answers.push({ id: "ha1-gcm-hardened-2", plaintext, expectBreak: false });
    answers.material["ha1-gcm-hardened-2"] = { keyHex: key.toString("hex") };
  }

  const publicFile: PublicChallengeFile = {
    version: 1,
    createdAt: new Date().toISOString(),
    challenges,
  };

  const publicPath = path.join(outDir, "public.json");
  const answersPath = path.join(outDir, "answers.json");
  writeFileSync(publicPath, JSON.stringify(publicFile, null, 2), "utf8");
  writeFileSync(answersPath, JSON.stringify(answers, null, 2), "utf8");

  return { publicPath, answersPath };
}
