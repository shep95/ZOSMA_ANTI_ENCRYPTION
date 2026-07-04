import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { AttackError } from "./errors.js";
import { createLogger } from "./log.js";

export type Factors = { p: bigint; q: bigint };

export type ShorResult = Factors & {
  backend: string | null;
  jobId: string | null;
  mode: string;
  order: number | null;
  base: number | null;
  shots: number;
  durationMs: number;
  raw: Record<string, unknown>;
};

export type ShorOptions = {
  shots?: number;
  backend?: string;
  pythonPath?: string;
  /** Wall-clock budget for the whole quantum subprocess (default 30 min). */
  timeoutMs?: number;
  /** Max QPU base attempts inside Python (default 2). */
  maxAttempts?: number;
  signal?: AbortSignal;
  correlationId?: string;
  onProgress?: (event: ProgressEvent) => void;
};

export type ProgressEvent = {
  stage: string;
  message: string;
  backend?: string;
  jobId?: string;
  attempt?: number;
};

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHOR_SCRIPT = path.join(ROOT, "quantum", "shor_live.py");
const DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_STDOUT_BYTES = 8 * 1024 * 1024;

const SUPPORTED_N = new Set([15n, 21n]);

/**
 * Factor n with live Shor on IBM Quantum.
 * Cheap validation first; one bounded Python job; schema-validated result.
 */
export async function shorsBreaker(n: bigint, options: ShorOptions = {}): Promise<ShorResult> {
  const log = createLogger("shor", options.correlationId);
  const started = Date.now();

  // 2.2 cheap-before-expensive
  if (n <= 1n) throw new AttackError("invalid_n", "n must be > 1");
  if (n % 2n === 0n) {
    return {
      p: 2n,
      q: n / 2n,
      backend: null,
      jobId: null,
      mode: "trivial_even",
      order: null,
      base: null,
      shots: 0,
      durationMs: Date.now() - started,
      raw: { mode: "trivial_even" },
    };
  }
  if (!SUPPORTED_N.has(n)) {
    throw new AttackError(
      "unsupported_n",
      `N=${n} is not a live-hardware modulus. Supported: 15, 21.`,
    );
  }

  const shots = options.shots ?? 1024;
  if (!Number.isInteger(shots) || shots < 1 || shots > 100_000) {
    throw new AttackError("invalid_shots", "shots must be an integer in [1, 100000]");
  }

  const maxAttempts = options.maxAttempts ?? 2;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const python = options.pythonPath ?? process.env.PYTHON ?? "python";

  // 1.2.1 idempotency key from stable inputs (not random UUID)
  const idempotencyKey = createHash("sha256")
    .update(`shor|${n}|${shots}|${options.backend ?? "least_busy"}|${maxAttempts}`)
    .digest("hex")
    .slice(0, 16);

  log.info("quantum_factor_start", {
    n: n.toString(),
    shots,
    maxAttempts,
    timeoutMs,
    idempotencyKey,
    backend: options.backend ?? "least_busy",
  });

  const args = [
    SHOR_SCRIPT,
    "--n",
    n.toString(),
    "--shots",
    String(shots),
    "--max-attempts",
    String(maxAttempts),
    "--correlation-id",
    log.correlationId,
    "--json",
  ];
  if (options.backend) args.push("--backend", options.backend);

  const payload = await runPython(python, args, {
    timeoutMs,
    signal: options.signal,
    onProgress: options.onProgress,
    log,
  });

  const data = parseJsonObject(payload);
  if (typeof data.error === "string") {
    throw new AttackError("quantum_engine", scrubSecrets(data.error), isRetryable(data.error));
  }

  const result = validateShorPayload(data, n);
  const durationMs = Date.now() - started;

  log.info("quantum_factor_ok", {
    p: result.p.toString(),
    q: result.q.toString(),
    mode: result.mode,
    backend: result.backend,
    jobId: result.jobId,
    durationMs,
    idempotencyKey,
  });

  return { ...result, durationMs };
}

function validateShorPayload(data: Record<string, unknown>, n: bigint): Omit<ShorResult, "durationMs"> {
  const p = toBigInt(data.p, "p");
  const q = toBigInt(data.q, "q");
  if (p * q !== n) {
    throw new AttackError("factor_mismatch", `Factors (${p}, ${q}) do not multiply to ${n}`);
  }

  return {
    p: p <= q ? p : q,
    q: p <= q ? q : p,
    backend: data.backend == null ? null : String(data.backend),
    jobId: data.job_id == null ? null : String(data.job_id),
    mode: String(data.mode ?? "unknown"),
    order: data.order == null ? null : Number(data.order),
    base: data.base == null ? null : Number(data.base),
    shots: Number(data.shots ?? 0),
    raw: data,
  };
}

function toBigInt(value: unknown, field: string): bigint {
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new AttackError("schema", `Missing or invalid field '${field}' in quantum response`);
}

function parseJsonObject(payload: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    throw new AttackError("schema", "Quantum engine returned non-JSON output");
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AttackError("schema", "Quantum engine JSON must be an object");
  }
  return parsed as Record<string, unknown>;
}

function isRetryable(message: string): boolean {
  const m = message.toLowerCase();
  return m.includes("timeout") || m.includes("queue") || m.includes("temporar") || m.includes("503");
}

function scrubSecrets(text: string): string {
  return text
    .replace(/IBM_QUANTUM_TOKEN=\S+/gi, "IBM_QUANTUM_TOKEN=[redacted]")
    .replace(/token["']?\s*[:=]\s*["']?[\w.-]+/gi, "token=[redacted]");
}

type RunOptions = {
  timeoutMs: number;
  signal?: AbortSignal;
  onProgress?: (event: ProgressEvent) => void;
  log: ReturnType<typeof createLogger>;
};

function runPython(python: string, args: string[], options: RunOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new AttackError("cancelled", "Quantum factoring cancelled", false));
      return;
    }

    let child: ChildProcess;
    try {
      child = spawn(python, args, {
        cwd: ROOT,
        env: process.env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (err) {
      reject(
        new AttackError(
          "python_spawn",
          `Failed to start Python (${python}). Install Python 3.11+ and: pip install -r quantum/requirements.txt. ${err instanceof Error ? err.message : String(err)}`,
        ),
      );
      return;
    }

    let stdout = "";
    let stdoutBytes = 0;
    let stderrLine = "";
    let settled = false;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };

    const onAbort = () => {
      child.kill("SIGTERM");
      settle(() => reject(new AttackError("cancelled", "Quantum factoring cancelled", false)));
    };

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      settle(() =>
        reject(
          new AttackError(
            "timeout",
            `Quantum engine exceeded ${options.timeoutMs}ms wall-clock budget`,
            true,
          ),
        ),
      );
    }, options.timeoutMs);

    const cleanup = () => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    };

    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        child.kill("SIGTERM");
        settle(() => reject(new AttackError("output_limit", "Quantum engine stdout exceeded 8 MiB")));
        return;
      }
      stdout += chunk.toString("utf8");
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderrLine += chunk.toString("utf8");
      const lines = stderrLine.split(/\r?\n/);
      stderrLine = lines.pop() ?? "";
      for (const line of lines) {
        handleProgressLine(line, options);
      }
    });

    child.on("error", (err) => {
      settle(() =>
        reject(
          new AttackError(
            "python_spawn",
            `Failed to start Python (${python}). Install Python 3.11+ and: pip install -r quantum/requirements.txt. ${err.message}`,
          ),
        ),
      );
    });

    child.on("close", (code) => {
      if (stderrLine.trim()) handleProgressLine(stderrLine, options);

      settle(() => {
        const line = stdout
          .trim()
          .split(/\r?\n/)
          .filter(Boolean)
          .at(-1);

        if (code !== 0) {
          if (line) {
            try {
              const errJson = JSON.parse(line) as { error?: string };
              if (errJson.error) {
                reject(new AttackError("quantum_engine", scrubSecrets(errJson.error), isRetryable(errJson.error)));
                return;
              }
            } catch {
              // fall through
            }
          }
          reject(
            new AttackError(
              "quantum_engine",
              scrubSecrets(
                `Live Shor process failed (exit ${code}). ${line ?? "No output"}. ` +
                  "Set IBM_QUANTUM_TOKEN and run: pip install -r quantum/requirements.txt",
              ),
              false,
            ),
          );
          return;
        }

        if (!line) {
          reject(new AttackError("schema", "Live Shor produced no JSON result"));
          return;
        }
        resolve(line);
      });
    });
  });
}

function handleProgressLine(line: string, options: RunOptions): void {
  const trimmed = line.trim();
  if (!trimmed.startsWith("{")) return;
  try {
    const event = JSON.parse(trimmed) as ProgressEvent & { type?: string };
    if (event.type === "progress" && event.stage && event.message) {
      options.log.info("quantum_progress", {
        stage: event.stage,
        message: event.message,
        backend: event.backend,
        jobId: event.jobId,
        attempt: event.attempt,
      });
      options.onProgress?.({
        stage: event.stage,
        message: event.message,
        backend: event.backend,
        jobId: event.jobId,
        attempt: event.attempt,
      });
    }
  } catch {
    // ignore non-JSON stderr noise from libraries
  }
}
