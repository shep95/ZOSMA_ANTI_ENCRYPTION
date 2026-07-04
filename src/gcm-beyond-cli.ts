/**
 * Live test: AES-256-GCM bypasses *beyond* algorithm scope.
 */

import { runAllBeyondScopeBypasses } from "./crypto/high-asset/gcm-beyond-scope.js";
import { createLogger } from "./log.js";

function main(): void {
  const log = createLogger("gcm-beyond");
  console.log("AES-256-GCM — beyond-algorithm-scope theory (live)\n");
  console.log(
    "Premise: perfect GCM math holds; data still falls when context is hostile.\n",
  );

  const results = runAllBeyondScopeBypasses();
  let failed = 0;

  for (const r of results) {
    const ok = r.theoryHolds;
    if (!ok) failed += 1;
    console.log(`[${ok ? "PASS" : "FAIL"}] ${r.vector}`);
    console.log(`  ${r.detail}`);
    if (r.recovered !== undefined) console.log(`  recovered: ${JSON.stringify(r.recovered)}`);
    console.log("");
  }

  console.log(`Total: ${results.length}, failures: ${failed}`);
  console.log(
    failed === 0
      ? "BEYOND-SCOPE THEORY PASSED — context attacks work; public-blob-only still holds"
      : "BEYOND-SCOPE THEORY FAILED",
  );
  log.info("gcm_beyond_lab", { failed, total: results.length });
  process.exit(failed === 0 ? 0 : 1);
}

main();
