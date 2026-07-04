import { AttackError } from "./errors.js";
import { createLogger } from "./log.js";
import {
  decryptMessage,
  encryptMessage,
  formatCiphertext,
  generateLiveKeypair,
  recoverPrivateKey,
  type KeyPair,
  type PrivateKey,
  type PublicKey,
} from "./rsa.js";
import { shorsBreaker, type ShorResult } from "./shor.js";

/** Attack workflow states — illegal transitions are rejected. */
export type AttackState =
  | "idle"
  | "keyed"
  | "encrypted"
  | "quantum_running"
  | "factored"
  | "cracked"
  | "failed"
  | "cancelled";

export type AttackConfig = {
  modulus: 15 | 21;
  message: string;
  shots: number;
  backend?: string;
  timeoutMs?: number;
  maxAttempts?: number;
  signal?: AbortSignal;
  /** Human-readable progress (non-JSON). Structured logs always emit. */
  onStatus?: (line: string) => void;
};

export type AttackResult = {
  state: "cracked";
  correlationId: string;
  publicKey: PublicKey;
  privateKey: PrivateKey;
  ciphertext: bigint[];
  factors: ShorResult;
  crackedKey: PrivateKey;
  plaintext: string;
  durationMs: number;
};

type Internal = {
  state: AttackState;
  keyPair?: KeyPair;
  ciphertext?: bigint[];
  factors?: ShorResult;
  crackedKey?: PrivateKey;
  plaintext?: string;
};

const ALLOWED: Record<AttackState, readonly AttackState[]> = {
  idle: ["keyed", "failed", "cancelled"],
  keyed: ["encrypted", "failed", "cancelled"],
  encrypted: ["quantum_running", "failed", "cancelled"],
  quantum_running: ["factored", "failed", "cancelled"],
  factored: ["cracked", "failed", "cancelled"],
  cracked: [],
  failed: [],
  cancelled: [],
};

function transition(ctx: Internal, next: AttackState): void {
  if (!ALLOWED[ctx.state].includes(next)) {
    throw new AttackError(
      "illegal_transition",
      `Cannot move attack state ${ctx.state} → ${next}`,
    );
  }
  ctx.state = next;
}

/**
 * Full live attack as an explicit state machine with cancel + timeout edges.
 */
export async function runAttack(config: AttackConfig): Promise<AttackResult> {
  const log = createLogger("attack");
  const started = Date.now();
  const ctx: Internal = { state: "idle" };
  const status = (line: string) => config.onStatus?.(line);

  const abort = () => {
    if (ctx.state === "cracked" || ctx.state === "failed" || ctx.state === "cancelled") return;
    transition(ctx, "cancelled");
  };
  config.signal?.addEventListener("abort", abort, { once: true });

  try {
    if (config.signal?.aborted) {
      transition(ctx, "cancelled");
      throw new AttackError("cancelled", "Attack cancelled before start");
    }

    // Act 1 — keygen (cheap, local)
    status("Act 1/4 — building live-hardware RSA keypair");
    log.info("attack_keyed_start", { modulus: config.modulus });
    const keyPair = generateLiveKeypair(config.modulus);
    ctx.keyPair = keyPair;
    transition(ctx, "keyed");
    status(`Public key (e, N) = (${keyPair.publicKey.e}, ${keyPair.publicKey.n})`);

    // Act 2 — encrypt + sanity decrypt
    status("Act 2/4 — encrypting message with real RSA");
    const ciphertext = encryptMessage(config.message, keyPair.publicKey);
    const legit = decryptMessage(ciphertext, keyPair.privateKey);
    if (legit !== config.message) {
      transition(ctx, "failed");
      throw new AttackError("rsa_roundtrip", "Legitimate RSA decrypt failed");
    }
    ctx.ciphertext = ciphertext;
    transition(ctx, "encrypted");
    status(`Ciphertext digits: ${formatCiphertext(ciphertext)}`);

    // Act 3 — live QPU (expensive)
    status("Act 3/4 — submitting Shor order-finding circuit to IBM Quantum");
    transition(ctx, "quantum_running");
    const factors = await shorsBreaker(keyPair.publicKey.n, {
      shots: config.shots,
      backend: config.backend,
      timeoutMs: config.timeoutMs,
      maxAttempts: config.maxAttempts,
      signal: config.signal,
      correlationId: log.correlationId,
      onProgress: (event) => status(`QPU ${event.stage}: ${event.message}`),
    });
    ctx.factors = factors;
    transition(ctx, "factored");
    status(
      `Factored N=${keyPair.publicKey.n} → (${factors.p}, ${factors.q})` +
        (factors.jobId ? ` job=${factors.jobId}` : ""),
    );

    // Act 4 — forge d and decrypt
    status("Act 4/4 — recovering private exponent and decrypting");
    const crackedKey = recoverPrivateKey(keyPair.publicKey, factors.p, factors.q);
    const plaintext = decryptMessage(ciphertext, crackedKey);
    if (plaintext !== config.message) {
      transition(ctx, "failed");
      throw new AttackError("crack_mismatch", "Cracked plaintext does not match original message");
    }
    ctx.crackedKey = crackedKey;
    ctx.plaintext = plaintext;
    transition(ctx, "cracked");

    const durationMs = Date.now() - started;
    log.info("attack_cracked", {
      durationMs,
      backend: factors.backend,
      jobId: factors.jobId,
      mode: factors.mode,
    });
    status(`Success in ${durationMs}ms`);

    return {
      state: "cracked",
      correlationId: log.correlationId,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      ciphertext,
      factors,
      crackedKey,
      plaintext,
      durationMs,
    };
  } catch (err) {
    if (ctx.state !== "failed" && ctx.state !== "cancelled" && ctx.state !== "cracked") {
      try {
        transition(ctx, err instanceof AttackError && err.code === "cancelled" ? "cancelled" : "failed");
      } catch {
        ctx.state = "failed";
      }
    }
    log.error("attack_failed", {
      state: ctx.state,
      code: err instanceof AttackError ? err.code : "unknown",
      message: err instanceof Error ? err.message : String(err),
    });
    throw err;
  } finally {
    config.signal?.removeEventListener("abort", abort);
  }
}
