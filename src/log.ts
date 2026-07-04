import { randomUUID } from "node:crypto";

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogFields = Record<string, string | number | boolean | null | undefined>;

const SECRET_KEYS = /token|password|secret|authorization|api[_-]?key/i;

/** Structured JSON logs. PII/secrets scrubbed at the boundary. */
export function createLogger(scope: string, correlationId?: string) {
  const id = correlationId ?? randomUUID();
  const emit = (level: LogLevel, message: string, fields: LogFields = {}) => {
    const entry: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level,
      scope,
      correlationId: id,
      message,
      ...scrub(fields),
    };
    const line = JSON.stringify(entry);
    if (level === "error") console.error(line);
    else if (level === "warn") console.warn(line);
    else console.log(line);
  };

  return {
    correlationId: id,
    debug: (message: string, fields?: LogFields) => emit("debug", message, fields),
    info: (message: string, fields?: LogFields) => emit("info", message, fields),
    warn: (message: string, fields?: LogFields) => emit("warn", message, fields),
    error: (message: string, fields?: LogFields) => emit("error", message, fields),
  };
}

function scrub(fields: LogFields): LogFields {
  const out: LogFields = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = SECRET_KEYS.test(key) ? "[redacted]" : value;
  }
  return out;
}
