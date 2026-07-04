/**
 * Live test: Moth & Butterfly biomimicry / anti-biomimicry theory for AES-256-GCM.
 */

import { runBiomimicryTheoryLab } from "./crypto/high-asset/gcm-biomimicry.js";
import { createLogger } from "./log.js";

function main(): void {
  const log = createLogger("gcm-biomimicry");
  console.log("AES-256-GCM — Moth & Butterfly biomimicry theory (live)\n");
  console.log("Defense: scales (key) · evasion (nonce/CTR) · structural color (GHASH)");
  console.log("Predator under current physics: sonar only (public ciphertext)\n");

  const results = runBiomimicryTheoryLab();
  let failed = 0;

  for (const r of results) {
    const ok = r.theoryHolds;
    if (!ok) failed += 1;
    const rec = r.plaintextRecovered ? "READ" : "HOLD";
    console.log(`[${ok ? "PASS" : "FAIL"}] ${rec} ${r.vector}`);
    console.log(`  mimicry:  ${r.mimicry}`);
    console.log(`  predator: ${r.predator}`);
    console.log(`  ${r.detail}`);
    if (r.recovered !== undefined) console.log(`  recovered: ${JSON.stringify(r.recovered)}`);
    console.log("");
  }

  const currentPhysics = results.filter((r) => !r.plaintextRecovered);
  const paradigmShift = results.filter((r) => r.plaintextRecovered);

  const claimA = currentPhysics.every((r) => r.theoryHolds && !r.plaintextRecovered);
  const claimB = paradigmShift.every((r) => r.theoryHolds && r.plaintextRecovered);

  console.log(`Total: ${results.length}, failures: ${failed}`);
  console.log(
    claimA
      ? "CLAIM A PASS: under current physics, anti-biomimicry fails — cannot read without key/leak"
      : "CLAIM A FAIL",
  );
  console.log(
    claimB
      ? "CLAIM B PASS: only paradigm-shift oracles (new sense / Laplace / time / blueprint) read plaintext"
      : "CLAIM B FAIL",
  );
  console.log(
    failed === 0 && claimA && claimB
      ? "\nMOTH-BUTTERFLY THEORY PASSED"
      : "\nMOTH-BUTTERFLY THEORY FAILED",
  );

  log.info("gcm_biomimicry_lab", { failed, claimA, claimB });
  process.exit(failed === 0 && claimA && claimB ? 0 : 1);
}

main();
