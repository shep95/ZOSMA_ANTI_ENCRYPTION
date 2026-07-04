/**
 * CLI: catalog encryption levels, emit narratives, run taxonomy break audits.
 */

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  allNarrativesMarkdown,
  auditProfile,
  describeBreak,
  presetProfile,
  type AuditReport,
} from "./crypto/audit.js";
import { ENCRYPTION_LEVELS } from "./crypto/levels.js";
import { createLogger } from "./log.js";

function printHelp(): void {
  console.log(`Usage: npm run audit -- <command>

Commands:
  levels                 List all encryption levels
  narratives [--write]   Print (or write) detailed narratives
  audit [--profile insecure|hardened] [--json]
  break <levelId> <microDomainId>
  summary                Old vs new posture for ZOSMA quantum path

Docs:
  docs/ENCRYPTION_NARRATIVES.md
  docs/TAXONOMY_BREAKS_CRYPTO.md
`);
}

function main(): void {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const log = createLogger("audit-cli");

  if (!cmd || cmd === "--help" || cmd === "-h") {
    printHelp();
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === "levels") {
    for (const level of ENCRYPTION_LEVELS) {
      console.log(
        `${level.id.padEnd(28)} ${level.layer.padEnd(22)} shor=${level.shorBreakable ? "Y" : "n"}  ${level.name}`,
      );
    }
    log.info("levels_listed", { count: ENCRYPTION_LEVELS.length });
    return;
  }

  if (cmd === "narratives") {
    const md = allNarrativesMarkdown();
    if (args.includes("--write")) {
      const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
      const out = path.join(root, "docs", "ENCRYPTION_NARRATIVES.generated.md");
      writeFileSync(out, md, "utf8");
      console.log(`Wrote ${out}`);
    } else {
      console.log(md);
    }
    return;
  }

  if (cmd === "audit") {
    const profileFlag = args.indexOf("--profile");
    const rawProfile = profileFlag >= 0 ? args[profileFlag + 1] : args[1];
    const profileName: "insecure" | "hardened" =
      rawProfile === "hardened" ? "hardened" : "insecure";
    const report = auditProfile(profileName, presetProfile(profileName));
    if (args.includes("--json")) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printReport(report);
    }
    log.info("audit_complete", {
      profile: profileName,
      findings: report.summary.findings,
      critical: report.summary.critical,
    });
    return;
  }

  if (cmd === "break") {
    const levelId = args[1];
    const microId = args[2];
    if (!levelId || !microId) {
      console.error("Usage: npm run audit -- break <levelId> <microDomainId>");
      process.exit(1);
    }
    console.log(describeBreak(levelId, microId));
    return;
  }

  if (cmd === "summary") {
    printOldVsNew();
    return;
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

function printReport(report: AuditReport): void {
  console.log(`Profile: ${report.profileName}`);
  console.log(`Generated: ${report.generatedAt}`);
  console.log(
    `Summary: findings=${report.summary.findings} pass=${report.summary.passes} n/a=${report.summary.na} critical=${report.summary.critical} high=${report.summary.high}`,
  );
  console.log(`Shor-breakable levels: ${report.shorBreakableLevels.join(", ")}`);
  console.log("");

  const findings = report.lines.filter((l) => l.status === "finding");
  for (const line of findings) {
    console.log(
      `[FINDING ${line.severity ?? "?"}] ${line.levelId} × ${line.microDomainId} — ${line.message}`,
    );
  }

  if (findings.length === 0) {
    console.log("No findings — all claimed controls present for mapped edges.");
  }
}

function printOldVsNew(): void {
  console.log(`ZOSMA posture — old vs new (taxonomy × encryption)

OLD NARRATIVE
- Only toy RSA + classical period finding (later live Shor).
- No catalog of world encryption levels.
- No mapping from implementation taxonomy to crypto breaks.
- Silent QPU waits, unbounded bases, token-leaking errors.
- Easy to imply "encryption is broken" without scoping which level.

NEW NARRATIVE
- Full operational catalog: classical → AEAD → PKI → PQ → tokens → assurance → quantum threat.
- Each level has promise + workflow + assumptions.
- Taxonomy micro-domains are bound to concrete break edges.
- Audit emits finding | pass | n/a (silence is not evidence).
- Live Shor path only claims quantum.shor_rsa / textbook RSA — not AES-GCM.
- Attack state machine, timeouts, schema validation, secret scrubbing.

WHAT THE TAXONOMY "BREAKS"
- Not AES math — the *workflow* around crypto (nonce, AEAD, JWT claims, KMS, RLS, logs).
- For RSA: taxonomy finds implementation voids; Shor finds factoring voids (toy N live).

RUN
  npm run audit -- levels
  npm run audit -- audit --profile insecure
  npm run audit -- audit --profile hardened
  npm run demo   # live Shor against toy RSA only
`);
}

main();
