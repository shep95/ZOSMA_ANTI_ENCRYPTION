/**
 * Factor-only CLI — same live quantum engine as the full attack.
 */

import { AttackError } from "./errors.js";
import { shorsBreaker } from "./shor.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (!args[0] || args[0] === "--help" || args[0] === "-h") {
    console.log("Usage: npm run factor -- <N> [--shots 1024] [--backend ibm_…] [--max-attempts 2]");
    console.log("Example: npm run factor -- 15");
    console.log("Requires IBM_QUANTUM_TOKEN and: pip install -r quantum/requirements.txt");
    process.exit(args[0] ? 0 : 1);
  }

  let n: bigint;
  try {
    n = BigInt(args[0]);
  } catch {
    throw new AttackError("invalid_args", `Invalid integer: ${args[0]}`);
  }

  let shots = 1024;
  let backend: string | undefined;
  let maxAttempts = 2;
  let timeoutMs = 30 * 60 * 1000;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--shots") shots = Number.parseInt(args[++i] ?? "", 10);
    else if (args[i] === "--backend") backend = args[++i];
    else if (args[i] === "--max-attempts") maxAttempts = Number.parseInt(args[++i] ?? "", 10);
    else if (args[i] === "--timeout-ms") timeoutMs = Number.parseInt(args[++i] ?? "", 10);
  }

  const controller = new AbortController();
  const onSignal = () => controller.abort();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    const result = await shorsBreaker(n, {
      shots,
      backend,
      maxAttempts,
      timeoutMs,
      signal: controller.signal,
      onProgress: (event) => console.error(`progress: ${event.stage} — ${event.message}`),
    });

    console.log(
      JSON.stringify(
        {
          p: result.p.toString(),
          q: result.q.toString(),
          mode: result.mode,
          backend: result.backend,
          job_id: result.jobId,
          order: result.order,
          base: result.base,
          shots: result.shots,
          duration_ms: result.durationMs,
        },
        null,
        2,
      ),
    );
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
}

main().catch((err: unknown) => {
  if (err instanceof AttackError) {
    console.error(`[${err.code}] ${err.message}`);
  } else {
    console.error(err instanceof Error ? err.message : err);
  }
  process.exit(1);
});
