import { createHash } from "node:crypto";

import { extractScriptUrls, fetchText } from "./fetch.js";
import { SECRET_PATTERNS, type KeyClass } from "./patterns.js";

export type Finding = {
  id: string;
  patternId: string;
  class: KeyClass;
  description: string;
  impact: string;
  value: string;
  redacted: string;
  sourceUrl: string;
};

export type ScanReport = {
  targetUrl: string;
  scannedAt: string;
  sources: string[];
  findings: Finding[];
  summary: {
    total: number;
    likelySecret: number;
    publicByDesign: number;
    cryptoMaterial: number;
    unknown: number;
  };
};

export async function scanUrl(targetUrl: string): Promise<ScanReport> {
  const sources: string[] = [];
  const bodies: { url: string; body: string }[] = [];

  const page = await fetchText(targetUrl);
  sources.push(page.url);
  bodies.push({ url: page.url, body: page.body });

  const scripts = extractScriptUrls(page.body, page.url);
  for (const scriptUrl of scripts) {
    try {
      const doc = await fetchText(scriptUrl);
      sources.push(doc.url);
      bodies.push({ url: doc.url, body: doc.body });
    } catch {
      // skip failed script fetches
    }
  }

  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const { url, body } of bodies) {
    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(body)) !== null) {
        const value = match[1] ?? match[0];
        if (!value || value.length < 8) continue;
        // Filter common false positives for hex keys (hashes in integrity attrs)
        if (pattern.id === "aes_key_hex_32" && isLikelyHashContext(body, match.index)) {
          continue;
        }

        const dedupe = `${pattern.id}:${value}`;
        if (seen.has(dedupe)) continue;
        seen.add(dedupe);

        findings.push({
          id: createHash("sha256").update(dedupe).digest("hex").slice(0, 12),
          patternId: pattern.id,
          class: pattern.class,
          description: pattern.description,
          impact: pattern.impact,
          value,
          redacted: redact(value),
          sourceUrl: url,
        });
      }
    }
  }

  return {
    targetUrl,
    scannedAt: new Date().toISOString(),
    sources,
    findings,
    summary: {
      total: findings.length,
      likelySecret: findings.filter((f) => f.class === "likely_secret").length,
      publicByDesign: findings.filter((f) => f.class === "public_by_design").length,
      cryptoMaterial: findings.filter((f) => f.class === "crypto_material").length,
      unknown: findings.filter((f) => f.class === "unknown").length,
    },
  };
}

function redact(value: string): string {
  if (value.length <= 8) return "****";
  if (value.startsWith("-----BEGIN")) return "-----BEGIN PRIVATE KEY----- [REDACTED]";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function isLikelyHashContext(body: string, index: number): boolean {
  const window = body.slice(Math.max(0, index - 40), index).toLowerCase();
  return (
    window.includes("sha256-") ||
    window.includes("sha384-") ||
    window.includes("sha512-") ||
    window.includes("integrity=")
  );
}
