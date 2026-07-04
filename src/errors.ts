/** Exhaustiveness helper for discriminated unions / state machines. */
export function assertNever(value: never, label = "value"): never {
  throw new Error(`Unhandled ${label}: ${JSON.stringify(value)}`);
}

export class AttackError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, retryable = false) {
    super(message);
    this.name = "AttackError";
    this.code = code;
    this.retryable = retryable;
  }
}
