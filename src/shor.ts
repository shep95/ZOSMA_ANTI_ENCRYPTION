import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type Factors = { p: bigint; q: bigint };

export type ShorResult = Factors & {
  backend: string | null;
  jobId: string | null;
  mode: string;
  order: number | null;
  base: number | null;
  shots: number;
  raw: Record<string, unknown>;
};

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHOR_SCRIPT = path.join(ROOT, "quantum", "shor_live.py");

export type ShorOptions = {
  shots?: number;
  backend?: string;
  pythonPath?: string;
};

/**
 * Factor n with live Shor's algorithm on IBM Quantum hardware.
 * Spawns quantum/shor_live.py — real QPE circuit, real QPU.
 */
export async function shorsBreaker(n: bigint, options: ShorOptions = {}): Promise<ShorResult> {
  if (n <= 1n) throw new Error("n must be > 1");

  const args = [SHOR_SCRIPT, "--n", n.toString(), "--json"];
  if (options.shots != null) args.push("--shots", String(options.shots));
  if (options.backend) args.push("--backend", options.backend);

  const python = options.pythonPath ?? process.env.PYTHON ?? "python";
  const payload = await runPython(python, args);
  const data = JSON.parse(payload) as Record<string, unknown>;

  if (typeof data.error === "string") {
    throw new Error(data.error);
  }

  const p = BigInt(String(data.p));
  const q = BigInt(String(data.q));
  if (p * q !== n) {
    throw new Error(`Quantum factorizer returned (${p}, ${q}) which do not multiply to ${n}`);
  }

  return {
    p: p <= q ? p : q,
    q: p <= q ? q : p,
    backend: (data.backend as string | null) ?? null,
    jobId: (data.job_id as string | null) ?? null,
    mode: String(data.mode ?? "unknown"),
    order: data.order == null ? null : Number(data.order),
    base: data.base == null ? null : Number(data.base),
    shots: Number(data.shots ?? 0),
    raw: data,
  };
}

function runPython(python: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(python, args, {
      cwd: ROOT,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (err) => {
      reject(
        new Error(
          `Failed to start Python (${python}). Install Python 3.11+ and run: pip install -r quantum/requirements.txt\n${err.message}`,
        ),
      );
    });

    child.on("close", (code) => {
      if (code !== 0) {
        try {
          const errJson = JSON.parse(stdout) as { error?: string };
          if (errJson.error) {
            reject(new Error(errJson.error));
            return;
          }
        } catch {
          // fall through
        }
        reject(
          new Error(
            `Live Shor process failed (exit ${code}).\n${(stdout + stderr).trim() || "No output"}\n\n` +
              "Set IBM_QUANTUM_TOKEN from https://quantum.cloud.ibm.com/ and install:\n" +
              "  pip install -r quantum/requirements.txt",
          ),
        );
        return;
      }

      const line = stdout
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .at(-1);
      if (!line) {
        reject(new Error(`Live Shor produced no JSON.\n${stderr}`));
        return;
      }
      resolve(line);
    });
  });
}
