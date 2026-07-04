/**
 * Factor an integer with live Shor's algorithm on IBM Quantum hardware.
 */

import { shorsBreaker } from "./shor.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (!args[0] || args[0] === "--help" || args[0] === "-h") {
    console.log("Usage: npm run factor -- <N> [--shots 4096] [--backend ibm_…]");
    console.log("Example: npm run factor -- 15");
    console.log("Requires IBM_QUANTUM_TOKEN and: pip install -r quantum/requirements.txt");
    process.exit(args[0] ? 0 : 1);
  }

  const n = BigInt(args[0]);
  let shots = 4096;
  let backend: string | undefined;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--shots") shots = Number(args[++i]);
    else if (args[i] === "--backend") backend = args[++i];
  }

  const result = await shorsBreaker(n, { shots, backend });
  console.log(JSON.stringify({
    p: result.p.toString(),
    q: result.q.toString(),
    mode: result.mode,
    backend: result.backend,
    job_id: result.jobId,
    order: result.order,
    base: result.base,
    shots: result.shots,
  }, null, 2));
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
