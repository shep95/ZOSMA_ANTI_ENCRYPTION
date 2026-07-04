/**
 * Live test: foundational-limits theory for perfect AES-256-GCM.
 *
 * Claim A: With no leaks and current physics/math → cannot read ciphertext.
 * Claim B: Only hypothetical paradigm-shift oracles would change that.
 */

import { runFoundationalTheoryLab } from "./crypto/high-asset/gcm-foundational.js";
import { createLogger } from "./log.js";

function main(): void {
  const log = createLogger("gcm-foundational");
  console.log("AES-256-GCM — foundational limits theory (live)\n");
  console.log(
    "Premise: flawless GCM, no side-channels, pristine host, no known algorithm break.\n",
  );

  const results = runFoundationalTheoryLab();
  let failed = 0;

  for (const r of results) {
    const ok = r.theoryHolds;
    if (!ok) failed += 1;
    const rec = r.plaintextRecovered ? " READ" : " HOLD";
    console.log(`[${ok ? "PASS" : "FAIL"}]${rec} ${r.vector}`);
    console.log(`  ${r.detail}`);
    if (r.recovered !== undefined) console.log(`  recovered: ${JSON.stringify(r.recovered)}`);
    console.log("");
  }

  const noLeak = results.find((r) => r.vector === "0.premise-no-leak-cannot-read");
  const blocked = results.filter(
    (r) =>
      r.vector.includes("no-laplace") ||
      r.vector.includes("unavailable") ||
      r.vector.includes("standard-assumption") ||
      r.vector === "1.unknown-math-weakness",
  );
  const breakthroughs = results.filter((r) => r.vector.includes("breakthrough") || r.vector.includes("with-laplace") || r.vector.includes("with-oracle"));

  const claimA = noLeak?.theoryHolds && blocked.every((r) => r.theoryHolds && !r.plaintextRecovered);
  const claimB = breakthroughs.every((r) => r.theoryHolds && r.plaintextRecovered);

  console.log(`Total: ${results.length}, row failures: ${failed}`);
  console.log(
    claimA
      ? "CLAIM A PASS: cannot read ciphertext with no leaks under current physics/math"
      : "CLAIM A FAIL",
  );
  console.log(
    claimB
      ? "CLAIM B PASS: only hypothetical breakthrough oracles recover plaintext"
      : "CLAIM B FAIL",
  );
  console.log(
    failed === 0 && claimA && claimB
      ? "\nFOUNDATIONAL THEORY PASSED"
      : "\nFOUNDATIONAL THEORY FAILED",
  );

  log.info("gcm_foundational_lab", { failed, claimA, claimB });
  process.exit(failed === 0 && claimA && claimB ? 0 : 1);
}

main();
