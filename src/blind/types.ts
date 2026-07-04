/** Public challenge material only — no keys, plaintexts, or factors. */

export type PublicChallenge = {
  id: string;
  tier: string;
  algorithm: string;
  /** Human-readable attack surface (public protocol knowledge, not secrets). */
  publicProtocolNotes: string;
  payload: Record<string, unknown>;
};

export type PublicChallengeFile = {
  version: 1;
  createdAt: string;
  challenges: PublicChallenge[];
};

/** Referee-only answers. Breaker must never read this file. */
export type AnswerEntry = {
  id: string;
  plaintext: string;
  /** True if a correct blind break is expected. */
  expectBreak: boolean;
};

export type AnswersFile = {
  version: 1;
  answers: AnswerEntry[];
  /** Secrets used to build challenges — referee only. */
  material: Record<string, unknown>;
};

export type BreakAttempt = {
  id: string;
  status: "broken" | "failed" | "partial";
  recoveredPlaintext?: string;
  method: string;
  detail: string;
};

export type BreakReport = {
  version: 1;
  brokenAt: string;
  attempts: BreakAttempt[];
};

export type ScoreReport = {
  total: number;
  expectedBreaks: number;
  unexpectedSurvivors: number;
  correctBreaks: number;
  falseBreaks: number;
  correctFailures: number;
  missedBreaks: number;
  lines: string[];
};
