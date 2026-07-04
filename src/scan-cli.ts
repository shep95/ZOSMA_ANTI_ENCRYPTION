/**
 * Authorized secret-exposure scanner for web/app client bundles.
 *
 * - Finds likely keys in HTML/JS
 * - Classifies public vs secret
 * - Probes AES keys only against optional LOCAL ciphertext
 * - Does NOT call third-party APIs with found secrets
 *
 * Use only on systems you own or have permission to test.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { sealAes256Gcm, type SealedBox } from "./crypto/high-asset/aead.js";
import { createLogger } from "./log.js";
import { SECRET_PATTERNS } from "./scan/patterns.js";
import { probeCryptoMaterial } from "./scan/probe.js";
import { scanUrl, type Finding, type ScanReport } from "./scan/scanner.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEMO_AES_KEY_HEX =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

function printHelp(): void {
  console.log(`Usage:
  npm run scan -- --fixture --with-local-aes-demo
  npm run scan -- <url> --i-own-this

Options:
  --fixture              Scan local fixtures/exposed-secrets.html
  --i-own-this           Required for remote URLs (authorization)
  --with-local-aes-demo  Try exposed AES hex keys on a local GCM box
  --json                 Full JSON
  --out <file>           Write report

Ethics: only scan systems you own or may test. Secrets are redacted in console.
Remote cloud APIs are never called with discovered values.
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (!args[0] || args[0] === "-h" || args[0] === "--help") {
    printHelp();
    process.exit(args[0] ? 0 : 1);
  }

  const log = createLogger("scan");
  const asJson = args.includes("--json");
  const own = args.includes("--i-own-this");
  const withAesDemo = args.includes("--with-local-aes-demo");
  const outIdx = args.indexOf("--out");
  const outFile = outIdx >= 0 ? args[outIdx + 1] : undefined;

  let report: ScanReport;
  const localBoxes: SealedBox[] = withAesDemo ? [buildLocalAesDemoBox()] : [];

  if (args.includes("--fixture")) {
    report = scanFixture();
  } else {
    const url = args.find((a) => a.startsWith("http://") || a.startsWith("https://"));
    if (!url) {
      console.error("Provide a URL or --fixture");
      printHelp();
      process.exit(1);
    }
    if (!own) {
      console.error("Refusing remote scan without --i-own-this (authorization required).");
      process.exit(1);
    }
    console.log(`Scanning (authorized): ${url}`);
    report = await scanUrl(url);
  }

  const probes = probeCryptoMaterial(report.findings, localBoxes);

  if (asJson) {
    console.log(JSON.stringify({ report: redactReport(report), probes }, null, 2));
  } else {
    printHuman(report, probes);
  }

  if (outFile) {
    const abs = path.resolve(outFile);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, JSON.stringify({ report: redactReport(report), probes }, null, 2), "utf8");
    console.log(`\nWrote ${abs}`);
  }

  log.info("scan_complete", {
    target: report.targetUrl,
    findings: report.summary.total,
    highRiskCount: report.summary.likelySecret,
  });
}

function redactReport(report: ScanReport): ScanReport {
  return {
    ...report,
    findings: report.findings.map((f) => ({ ...f, value: f.redacted })),
  };
}

function scanFixture(): ScanReport {
  const fixturePath = path.join(ROOT, "fixtures", "exposed-secrets.html");
  const body = readFileSync(fixturePath, "utf8");
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(body)) !== null) {
      const value = match[1] ?? match[0];
      if (!value) continue;
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
        sourceUrl: `file://${fixturePath}`,
      });
    }
  }

  return {
    targetUrl: `fixture:${fixturePath}`,
    scannedAt: new Date().toISOString(),
    sources: [fixturePath],
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

function buildLocalAesDemoBox(): SealedBox {
  const key = Buffer.from(DEMO_AES_KEY_HEX, "hex");
  const nonce = Buffer.alloc(12, 7);
  return sealAes256Gcm(
    {
      key,
      plaintext: Buffer.from("ZOSMA|dataset-row-from-exposed-key"),
      aad: Buffer.from("demo|fixture"),
    },
    nonce,
  );
}

function redact(value: string): string {
  if (value.length <= 8) return "****";
  if (value.startsWith("-----BEGIN")) return "-----BEGIN PRIVATE KEY----- [REDACTED]";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function printHuman(
  report: ScanReport,
  probes: ReturnType<typeof probeCryptoMaterial>,
): void {
  console.log(`Target: ${report.targetUrl}`);
  console.log(`Sources scanned: ${report.sources.length}`);
  console.log(
    `Findings: total=${report.summary.total} secret=${report.summary.likelySecret} public=${report.summary.publicByDesign} crypto=${report.summary.cryptoMaterial} unknown=${report.summary.unknown}`,
  );
  console.log("");

  for (const f of report.findings) {
    console.log(`[${f.class}] ${f.description}`);
    console.log(`  redacted=${f.redacted}`);
    console.log(`  source=${f.sourceUrl}`);
    console.log(`  impact=${f.impact}`);
  }

  console.log("\nProbes (local only — no third-party API calls):");
  for (const p of probes) {
    console.log(`  [${p.outcome}] ${p.action}: ${p.detail}`);
  }

  console.log(
    "\nNote: Reports exposure + local crypto impact. Does not use secrets against cloud APIs.",
  );
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
