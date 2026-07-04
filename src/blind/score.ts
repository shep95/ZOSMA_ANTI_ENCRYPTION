/**
 * Referee: compares break-report to answers.json.
 * Breaker process must not import or read answers during attack.
 */

import { readFileSync } from "node:fs";

import type { AnswersFile, BreakReport, ScoreReport } from "./types.js";

export function scoreBlind(answersPath: string, reportPath: string): ScoreReport {
  const answers = JSON.parse(readFileSync(answersPath, "utf8")) as AnswersFile;
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as BreakReport;

  const byId = new Map(report.attempts.map((a) => [a.id, a]));
  const lines: string[] = [];
  let correctBreaks = 0;
  let falseBreaks = 0;
  let correctFailures = 0;
  let missedBreaks = 0;
  let expectedBreaks = 0;
  let unexpectedSurvivors = 0;

  for (const answer of answers.answers) {
    const attempt = byId.get(answer.id);
    if (!attempt) {
      lines.push(`MISS ${answer.id}: no attempt recorded`);
      if (answer.expectBreak) missedBreaks += 1;
      continue;
    }

    if (answer.expectBreak) expectedBreaks += 1;
    else unexpectedSurvivors += 1;

    const recovered = attempt.recoveredPlaintext ?? "";
    const exact = recovered === answer.plaintext;
    const broke = attempt.status === "broken" && exact;

    if (answer.expectBreak) {
      if (broke) {
        correctBreaks += 1;
        lines.push(`OK   BREAK ${answer.id} via ${attempt.method}`);
      } else {
        missedBreaks += 1;
        lines.push(
          `FAIL MISS  ${answer.id}: expected break, got status=${attempt.status} recovered=${JSON.stringify(recovered)}`,
        );
      }
    } else if (attempt.status === "broken") {
      falseBreaks += 1;
      lines.push(`FAIL FALSE ${answer.id}: hardened target was broken (should be impossible)`);
    } else {
      correctFailures += 1;
      lines.push(`OK   HOLD  ${answer.id} (${attempt.method})`);
    }
  }

  return {
    total: answers.answers.length,
    expectedBreaks,
    unexpectedSurvivors,
    correctBreaks,
    falseBreaks,
    correctFailures,
    missedBreaks,
    lines,
  };
}
