/**
 * Standalone factorizer matching Factorizer_Quantum_Simulator.ipynb.
 */

import { shorsBreaker } from "./shor.js";

function main(): void {
  const raw = process.argv[2];
  if (!raw || raw === "--help" || raw === "-h") {
    console.log("Usage: npm run factor -- <positive-integer>");
    console.log("Example: npm run factor -- 21");
    process.exit(raw ? 0 : 1);
  }

  const n = BigInt(raw);
  if (n <= 0n) throw new Error("Input must be positive");

  const { p, q } = shorsBreaker(n);
  console.log(`(${p}, ${q})`);
}

main();
