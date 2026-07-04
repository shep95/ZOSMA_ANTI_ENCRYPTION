/**
 * Live demo: AES-256-GCM bypass vectors from the protection narrative.
 */

import { runAllGcmBypasses } from "./crypto/high-asset/gcm-bypass.js";
import { createLogger } from "./log.js";

/** Expected: true = attack succeeds (narrative violated), false = no bypass (safe). */
const EXPECT_BYPASS: Record<string, boolean> = {
  "1.nonce-reuse-forbidden-attack": true,
  "2.compromised-key-management": true,
  "3a.release-before-verify-oracle": true,
  "3b.non-constant-time-tag-compare": true,
  "3c.stale-buffer-after-tag-fail": true,
  "4.authentication-tag-truncation": true,
  "5a.data-limit-exceeded": true,
  "5b.data-limit-within-bounds": false,
  "6.aad-mismanagement": true,
  "7.library-misuse-custom-impl": true,
};

function main(): void {
  const log = createLogger("gcm-bypass");
  console.log("AES-256-GCM bypass vectors (from protection narrative)\n");

  const results = runAllGcmBypasses();
  let failed = 0;

  for (const r of results) {
    const expect = EXPECT_BYPASS[r.vector];
    const ok = expect === undefined ? r.bypassed : r.bypassed === expect;
    if (!ok) failed += 1;

    console.log(`[${ok ? "PASS" : "FAIL"}] ${r.vector} (bypassed=${r.bypassed}, expect=${expect})`);
    console.log(`  ${r.detail}`);
    if (r.recovered !== undefined) console.log(`  recovered: ${JSON.stringify(r.recovered)}`);
    console.log("");
  }

  console.log(`Total: ${results.length}, failures: ${failed}`);
  console.log(failed === 0 ? "GCM BYPASS LAB PASSED" : "GCM BYPASS LAB FAILED");
  log.info("gcm_bypass_lab", { failed, total: results.length });
  process.exit(failed === 0 ? 0 : 1);
}

main();
