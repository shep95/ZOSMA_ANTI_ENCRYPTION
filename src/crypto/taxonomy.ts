/**
 * CODE_NARRATIVE_PROTOCOL flaw taxonomy (dimensions → micro-domains).
 * Each micro-domain is one enforceable check line.
 */

export type TaxonomyFindingStatus = "finding" | "n/a";

export type MicroDomain = {
  id: string;
  dimension: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
  title: string;
  /** How this micro-domain breaks crypto workflows when violated. */
  cryptoBreak: string;
};

export const MICRO_DOMAINS: readonly MicroDomain[] = [
  // 1 Workflow
  { id: "1.1.1", dimension: 1, title: "Entry/exit/error/cancel edges", cryptoBreak: "Handshake or key-rotation aborts leave keys in memory or half-open sessions." },
  { id: "1.1.2", dimension: 1, title: "Illegal-transition guard", cryptoBreak: "Skipping verify-cert or verify-tag states yields unauthenticated traffic keys." },
  { id: "1.1.3", dimension: 1, title: "Timeout edge with fallback", cryptoBreak: "Hung KMS/QPU/TLS calls; fallback must fail closed, not disable crypto." },
  { id: "1.1.4", dimension: 1, title: "Replay-safety", cryptoBreak: "Replaying encrypt steps reuses nonces/IVs." },
  { id: "1.2.1", dimension: 1, title: "Idempotency key = (actor, op, input hash)", cryptoBreak: "Random UUID retries mint duplicate keys or nonces." },
  { id: "1.2.2", dimension: 1, title: "Compensation is exact inverse", cryptoBreak: "Failed rotation does not destroy old key material." },
  { id: "1.2.3", dimension: 1, title: "Saga persists step outcomes", cryptoBreak: "Recovery restarts keygen and orphans secrets." },
  { id: "1.3.1", dimension: 1, title: "p-limit on parallel branches", cryptoBreak: "Parallel encryptors collide on counters/nonces." },
  { id: "1.3.2", dimension: 1, title: "allSettled + per-branch timeout", cryptoBreak: "One slow HSM call blocks revocation fan-out." },
  { id: "1.4.1", dimension: 1, title: "At-least-once + idempotent consumers", cryptoBreak: "Duplicate key-distribution events apply twice." },
  { id: "1.5.1", dimension: 1, title: "UTC crons DST-safe", cryptoBreak: "Key expiry jobs skip or double-run around DST." },

  // 2 Code logic
  { id: "2.1.1", dimension: 2, title: "Inclusive/exclusive boundaries", cryptoBreak: "Ciphertext length off-by-one truncates tags." },
  { id: "2.2.1", dimension: 2, title: "assertNever exhaustiveness", cryptoBreak: "New alg enum falls through to 'none' or ECB." },
  { id: "2.2.2", dimension: 2, title: "Cheap-before-expensive", cryptoBreak: "QPU/KMS called before authn/authz checks." },
  { id: "2.3.1", dimension: 2, title: "No prop/buffer mutation", cryptoBreak: "Shared IV buffer mutated across requests." },
  { id: "2.4.1", dimension: 2, title: "parseInt radix", cryptoBreak: "Key size or exp claim misparsed." },
  { id: "2.4.2", dimension: 2, title: "IANA timezones for exp", cryptoBreak: "Token expiry checked in wrong zone." },

  // 3 Bug-class
  { id: "3.1.1", dimension: 3, title: "Nullability of key handles", cryptoBreak: "Null key → crash or zero key." },
  { id: "3.2.1", dimension: 3, title: "Unhandled rejections", cryptoBreak: "Verify failure ignored; plaintext returned." },
  { id: "3.2.2", dimension: 3, title: "AbortController cancel", cryptoBreak: "Cancelled encrypt still commits nonce." },
  { id: "3.3.1", dimension: 3, title: "Races on nonce/counter", cryptoBreak: "AEAD nonce reuse under concurrency." },
  { id: "3.4.1", dimension: 3, title: "Integer overflow on counters", cryptoBreak: "CTR/GCM counter wrap." },

  // 4 Security
  { id: "4.1.1", dimension: 4, title: "Injection into key stores", cryptoBreak: "SQL/NoSQL injection reads private keys." },
  { id: "4.2.1", dimension: 4, title: "Prompt injection on agent tools", cryptoBreak: "Model exfiltrates keys via tool calls." },
  { id: "4.3.1", dimension: 4, title: "IDOR / missing RLS on keys", cryptoBreak: "Cross-tenant private key read." },
  { id: "4.4.1", dimension: 4, title: "SSRF on JWKS/OCSP URLs", cryptoBreak: "Key fetch hits metadata/link-local." },
  { id: "4.5.1", dimension: 4, title: "XSS token theft", cryptoBreak: "Bearer tokens stolen from DOM/storage." },
  { id: "4.6.1", dimension: 4, title: "AEAD only", cryptoBreak: "Raw CBC/CTR without MAC." },
  { id: "4.6.2", dimension: 4, title: "IV/nonce never reused", cryptoBreak: "GCM/ChaCha catastrophic failure." },
  { id: "4.6.3", dimension: 4, title: "argon2id for passwords", cryptoBreak: "Fast hashes enable offline cracking." },
  { id: "4.6.4", dimension: 4, title: "JWT aud+iss+exp", cryptoBreak: "Token accepted across apps or forever." },
  { id: "4.6.5", dimension: 4, title: "Secret hygiene", cryptoBreak: "Keys in logs, repos, client bundles." },
  { id: "4.7.1", dimension: 4, title: "Safe deserialization of key blobs", cryptoBreak: "pickle/yaml.load RCE on key import." },

  // 5 Concurrency & data
  { id: "5.1.1", dimension: 5, title: "Optimistic locking on key rows", cryptoBreak: "Lost update on rotation." },
  { id: "5.2.1", dimension: 5, title: "Cache TTL + invalidation", cryptoBreak: "Revoked public keys still trusted." },
  { id: "5.3.1", dimension: 5, title: "Additive migrations", cryptoBreak: "Key table drift drops algorithm metadata." },
  { id: "5.4.1", dimension: 5, title: "Statement timeout on crypto meta queries", cryptoBreak: "Authz checks skipped under load." },

  // 6 Performance
  { id: "6.1.1", dimension: 6, title: "No skip-verify optimization", cryptoBreak: "Integrity checks removed for speed." },
  { id: "6.2.1", dimension: 6, title: "Memoize expensive verify materials", cryptoBreak: "Or inverse: memoize plaintext across users." },

  // 7 API/network
  { id: "7.1.1", dimension: 7, title: "Timeout+abort on KMS/QPU", cryptoBreak: "Hung crypto dependency." },
  { id: "7.1.2", dimension: 7, title: "Idempotent-only retries", cryptoBreak: "Retry encrypt → nonce reuse." },
  { id: "7.2.1", dimension: 7, title: "Schema-validate JWK/KMS responses", cryptoBreak: "Alg confusion / attacker-controlled keys." },
  { id: "7.2.2", dimension: 7, title: "Enumerate non-2xx", cryptoBreak: "Silent decrypt of error bodies." },
  { id: "7.4.1", dimension: 7, title: "Explicit CORS", cryptoBreak: "Token-bearing responses to evil origins." },
  { id: "7.5.1", dimension: 7, title: "Rate limit auth routes", cryptoBreak: "Password/token spray." },

  // 8 UI (crypto-adjacent)
  { id: "8.1.1", dimension: 8, title: "Error UX not an oracle", cryptoBreak: "Distinct errors enable padding/MAC oracles." },
  { id: "8.3.1", dimension: 8, title: "Secret fields focus management", cryptoBreak: "Key material left on screen/clipboard." },

  // 9 Realism & observability
  { id: "9.1.1", dimension: 9, title: "No mock KMS as live", cryptoBreak: "False assurance in production paths." },
  { id: "9.2.1", dimension: 9, title: "Provenance on security claims", cryptoBreak: "UI claims 'encrypted' without AEAD upstream." },
  { id: "9.3.1", dimension: 9, title: "Structured logs scrub secrets", cryptoBreak: "Key/password/token leakage." },
  { id: "9.4.1", dimension: 9, title: "Alarms on verify-fail spikes", cryptoBreak: "Active oracle/bruteforce unnoticed." },
] as const;

export function microDomain(id: string): MicroDomain | undefined {
  return MICRO_DOMAINS.find((m) => m.id === id);
}
