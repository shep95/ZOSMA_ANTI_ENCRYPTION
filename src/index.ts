/**
 * Live end-to-end attack CLI.
 * Orchestrates the attack state machine; never blocks the event loop on crypto math.
 */

import { AttackError } from "./errors.js";
import { runAttack } from "./attack.js";

function parseArgs(argv: string[]): {
  modulus: 15 | 21;
  message: string;
  shots: number;
  backend?: string;
  timeoutMs: number;
  maxAttempts: number;
} {
  let modulus: 15 | 21 = 15;
  let message = "ZOSMA";
  let shots = 1024;
  let backend: string | undefined;
  let timeoutMs = 30 * 60 * 1000;
  let maxAttempts = 2;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--modulus" || arg === "-n") {
      const value = Number.parseInt(argv[++i] ?? "", 10);
      if (value !== 15 && value !== 21) {
        throw new AttackError("invalid_args", "Live moduli supported today: 15 or 21");
      }
      modulus = value;
    } else if (arg === "--message" || arg === "-m") {
      message = argv[++i] ?? message;
    } else if (arg === "--shots") {
      shots = Number.parseInt(argv[++i] ?? "", 10);
    } else if (arg === "--backend") {
      backend = argv[++i];
    } else if (arg === "--timeout-ms") {
      timeoutMs = Number.parseInt(argv[++i] ?? "", 10);
    } else if (arg === "--max-attempts") {
      maxAttempts = Number.parseInt(argv[++i] ?? "", 10);
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  if (!Number.isInteger(shots) || shots < 1) {
    throw new AttackError("invalid_args", "shots must be a positive integer");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000) {
    throw new AttackError("invalid_args", "timeout-ms must be >= 1000");
  }
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 8) {
    throw new AttackError("invalid_args", "max-attempts must be in [1, 8]");
  }

  return { modulus, message, shots, backend, timeoutMs, maxAttempts };
}

function printHelp(): void {
  console.log(`Usage: npm start -- [options]

Live RSA break using Shor's algorithm on IBM Quantum hardware.

Options:
  -n, --modulus <15|21>   RSA modulus (default: 15)
  -m, --message <text>    Plaintext (default: ZOSMA)
      --shots <k>         QPU shots (default: 1024)
      --backend <name>    IBM backend (default: least busy real QPU)
      --timeout-ms <ms>   Wall-clock budget (default: 1800000)
      --max-attempts <n>  Max QPU base attempts (default: 2)
  -h, --help              Show help

Requires:
  IBM_QUANTUM_TOKEN   API token from https://quantum.cloud.ibm.com/
  pip install -r quantum/requirements.txt
`);
}

async function main(): Promise<void> {
  const config = parseArgs(process.argv.slice(2));
  const controller = new AbortController();

  const onSignal = () => controller.abort();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  if (!process.env.IBM_QUANTUM_TOKEN && !process.env.QISKIT_IBM_TOKEN) {
    console.warn(
      "IBM_QUANTUM_TOKEN is not set — quantum step requires a live IBM Quantum account.\n",
    );
  }

  try {
    const result = await runAttack({
      ...config,
      signal: controller.signal,
      onStatus: (line) => console.log(line),
    });

    console.log("\n--- result ---");
    console.log(`correlation_id: ${result.correlationId}`);
    console.log(`plaintext: ${result.plaintext}`);
    console.log(`factors: (${result.factors.p}, ${result.factors.q})`);
    console.log(`backend: ${result.factors.backend ?? "n/a"}`);
    console.log(`job_id: ${result.factors.jobId ?? "n/a"}`);
    console.log(`duration_ms: ${result.durationMs}`);
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
