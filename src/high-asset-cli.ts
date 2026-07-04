/**
 * High-asset encryption: narratives, taxonomy break audits, workable flaw labs.
 */

import {
  auditHighAssetProfile,
  narrativesMarkdown,
  presetHighAssetProfile,
} from "./crypto/high-asset/audit.js";
import { HIGH_ASSET_TIERS } from "./crypto/high-asset/levels.js";
import { selfTestHighAsset } from "./crypto/high-asset/flaw-lab.js";
import { createLogger } from "./log.js";

function printHelp(): void {
  console.log(`Usage: npm run high-asset -- <command>

Commands:
  tiers                      List hardest high-asset encryption tiers
  narratives                 Print detailed workflows
  audit [--profile broken|hardened] [--json]
  lab                        Run workable taxonomy-break demonstrations
  self-test                  Verify labs + hardened controls (must pass)
  summary                    Old vs new narrative

Docs:
  docs/HIGH_ASSET_ENCRYPTION.md
`);
}

function main(): void {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const log = createLogger("high-asset-cli");

  if (!cmd || cmd === "-h" || cmd === "--help") {
    printHelp();
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === "tiers") {
    for (const tier of HIGH_ASSET_TIERS) {
      console.log(
        `${tier.id.padEnd(28)} shorPrim=${tier.shorBreakablePrimitive ? "Y" : "n"}  ${tier.name}`,
      );
    }
    return;
  }

  if (cmd === "narratives") {
    console.log(narrativesMarkdown());
    return;
  }

  if (cmd === "audit") {
    const raw = args.includes("--profile")
      ? args[args.indexOf("--profile") + 1]
      : args[1];
    const profileName: "broken" | "hardened" = raw === "hardened" ? "hardened" : "broken";
    const report = auditHighAssetProfile(presetHighAssetProfile(profileName));
    if (args.includes("--json")) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(
        `Profile=${report.profileName} findings=${report.summary.findings} pass=${report.summary.passes} critical=${report.summary.critical}`,
      );
      for (const f of report.findings.filter((x) => x.status === "finding")) {
        console.log(
          `[FINDING ${f.severity}] ${f.tierId} × ${f.microDomainId} (${f.controlId}) — ${f.message}`,
        );
      }
      if (report.summary.findings === 0) {
        console.log("No findings — all high-asset controls claimed present.");
      }
    }
    log.info("high_asset_audit", {
      profile: profileName,
      findings: report.summary.findings,
      critical: report.summary.critical,
    });
    return;
  }

  if (cmd === "lab" || cmd === "self-test") {
    const { passed, results } = selfTestHighAsset();
    for (const r of results) {
      console.log(`${r.ok ? "PASS" : "FAIL"} ${r.name}: ${r.detail}`);
    }
    console.log(passed ? "\nSelf-test PASSED" : "\nSelf-test FAILED");
    log.info("high_asset_self_test", { passed, count: results.length });
    process.exit(passed ? 0 : 1);
  }

  if (cmd === "summary") {
    console.log(`HIGH-ASSET ENCRYPTION — old vs new

OLD
- Catalog mixed toy RSA with "encryption" generally.
- No dedicated tiers for HSM/AEAD-256/hybrid PQ/payment/TPM/MPC/CNSA.
- No workable demo that taxonomy flaws void HA confidentiality without claiming AES is cracked.
- Easy to over-claim QPU breaks high-asset data protection.

NEW
- Nine hardest tiers for high-value assets with full workflows.
- Taxonomy edges map to control ids (nonce_vault, fail_closed, hybrid_enforce, …).
- Workable code: real AES-256-GCM seal/open, NonceVault, AAD tenant bind, fail-closed tag verify.
- Lab proves nonce-reuse keystream relation (C1⊕C2=P1⊕P2) and that hardened path refuses tampering.
- broken profile → findings; hardened profile → pass; self-test must pass.

WHAT TAXONOMY BREAKS (not AES math)
- Nonce reuse, ignored tags, IDOR on key ids, secret logs, classical-only TLS fallback,
  SSRF on JWKS, cache of revoked trust, missing rate limits on unseal.

RUN
  npm run high-asset -- tiers
  npm run high-asset -- audit --profile broken
  npm run high-asset -- audit --profile hardened
  npm run high-asset -- self-test
`);
    return;
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

main();
