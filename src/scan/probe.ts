/**
 * Local-only "what could this key do" probes.
 * Never calls third-party cloud APIs with found secrets (no unauthorized access).
 */

import { openAes256Gcm, type SealedBox } from "../crypto/high-asset/aead.js";
import type { Finding } from "./scanner.js";

export type ProbeResult = {
  findingId: string;
  action: string;
  outcome: "would_decrypt_local" | "public_ok" | "secret_risk" | "skipped";
  detail: string;
};

/**
 * If we have a local GCM box (from blind challenges) and a 64-hex AES key,
 * try compromised-key path locally only.
 */
export function probeCryptoMaterial(
  findings: Finding[],
  localBoxes: SealedBox[] = [],
): ProbeResult[] {
  const results: ProbeResult[] = [];

  for (const f of findings) {
    if (f.patternId === "aes_key_hex_32") {
      const key = Buffer.from(f.value, "hex");
      if (key.length !== 32) {
        results.push({
          findingId: f.id,
          action: "aes-256-key-try-local",
          outcome: "skipped",
          detail: "Not a 32-byte key.",
        });
        continue;
      }

      if (localBoxes.length === 0) {
        results.push({
          findingId: f.id,
          action: "aes-256-key-try-local",
          outcome: "secret_risk",
          detail:
            "Looks like AES-256 key material. If real, attacker uses compromised-key path on any ciphertext sealed with it. No local ciphertext provided to demo decrypt.",
        });
        continue;
      }

      let decrypted = false;
      let plaintext: string | undefined;
      for (const box of localBoxes) {
        try {
          plaintext = openAes256Gcm(key, box).toString("utf8");
          decrypted = true;
          break;
        } catch {
          // wrong key for this box
        }
      }

      results.push({
        findingId: f.id,
        action: "aes-256-key-try-local",
        outcome: decrypted ? "would_decrypt_local" : "secret_risk",
        detail: decrypted
          ? `Local GCM box opened with exposed key → ${JSON.stringify(plaintext)}`
          : "Key did not open provided local boxes (still treat as high risk if real).",
      });
      continue;
    }

    if (f.class === "public_by_design") {
      results.push({
        findingId: f.id,
        action: "classify",
        outcome: "public_ok",
        detail: `${f.description}: public-by-design. Restrict by HTTP referrer / app ID / API quotas.`,
      });
      continue;
    }

    if (f.class === "likely_secret") {
      results.push({
        findingId: f.id,
        action: "classify-no-remote-use",
        outcome: "secret_risk",
        detail:
          `${f.description}: ${f.impact} ` +
          "Scanner does NOT call third-party APIs with this value (authorized testing only reports exposure).",
      });
      continue;
    }

    results.push({
      findingId: f.id,
      action: "classify",
      outcome: "secret_risk",
      detail: `${f.description}: ${f.impact}`,
    });
  }

  return results;
}
