/**
 * Blind live test:
 *   generate → public.json only to breaker
 *   break    → never reads answers.json
 *   score    → referee only
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import { runBlindBreak, defaultPaths } from "./blind/break.js";
import { generateBlindChallenges } from "./blind/generate.js";
import { scoreBlind } from "./blind/score.js";
import { createLogger } from "./log.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function printHelp(): void {
  console.log(`Usage: npm run blind -- <command>

Commands:
  generate   Create public challenges + referee answers (answers not given to breaker)
  break      Blind-attack public.json only
  score      Referee: compare break-report to answers
  live       generate → break → score (full blind run)
`);
}

function main(): void {
  const cmd = process.argv[2];
  const log = createLogger("blind-cli");
  const paths = defaultPaths(ROOT);
  const outDir = path.dirname(paths.publicPath);

  if (!cmd || cmd === "-h" || cmd === "--help") {
    printHelp();
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === "generate") {
    const { publicPath, answersPath } = generateBlindChallenges(outDir);
    console.log(`Public challenges (breaker input): ${publicPath}`);
    console.log(`Referee answers (NOT for breaker): ${answersPath}`);
    log.info("blind_generated", { publicPath, answersPath });
    return;
  }

  if (cmd === "break") {
    console.log(`Blind break reading ONLY: ${paths.publicPath}`);
    console.log("answers.json is not opened by this process.");
    const report = runBlindBreak(paths.publicPath, paths.reportPath);
    for (const a of report.attempts) {
      console.log(`\n[${a.status.toUpperCase()}] ${a.id} — ${a.method}`);
      if (a.recoveredPlaintext) console.log(`  recovered: ${a.recoveredPlaintext}`);
      if (a.narrativeChecks?.length) {
        for (const c of a.narrativeChecks) {
          console.log(`  [${c.outcome}] ${c.id}: ${c.detail}`);
        }
      } else {
        console.log(`  ${a.detail}`);
      }
    }
    console.log(`\nWrote ${paths.reportPath}`);
    log.info("blind_break_done", {
      broken: report.attempts.filter((x) => x.status === "broken").length,
      failed: report.attempts.filter((x) => x.status === "failed").length,
    });
    return;
  }

  if (cmd === "score") {
    const score = scoreBlind(paths.answersPath, paths.reportPath);
    for (const line of score.lines) console.log(line);
    console.log(
      `\nScore: correctBreaks=${score.correctBreaks}/${score.expectedBreaks} ` +
        `correctHolds=${score.correctFailures}/${score.unexpectedSurvivors} ` +
        `falseBreaks=${score.falseBreaks} missed=${score.missedBreaks}`,
    );
    const perfect =
      score.missedBreaks === 0 &&
      score.falseBreaks === 0 &&
      score.correctBreaks === score.expectedBreaks;
    console.log(perfect ? "BLIND TEST PASSED" : "BLIND TEST FAILED");
    log.info("blind_score", { ...score, lines: score.lines.length });
    process.exit(perfect ? 0 : 1);
  }

  if (cmd === "live") {
    generateBlindChallenges(outDir);
    console.log("=== GENERATE (secrets sealed; answers withheld from breaker) ===\n");
    const report = runBlindBreak(paths.publicPath, paths.reportPath);
    console.log("=== BLIND BREAK (public.json only) ===\n");
    for (const a of report.attempts) {
      console.log(`\n[${a.status.toUpperCase()}] ${a.id} (${a.method})`);
      if (a.recoveredPlaintext) {
        console.log(`  recovered: ${a.recoveredPlaintext}`);
      }
      if (a.narrativeChecks?.length) {
        console.log("  AES-256-GCM narrative checks:");
        for (const c of a.narrativeChecks) {
          console.log(`    [${c.outcome}] ${c.id}: ${c.detail}`);
        }
      } else if (!a.recoveredPlaintext) {
        console.log(`  ${a.detail}`);
      }
    }
    console.log("\n=== REFEREE SCORE (answers opened only here) ===\n");
    const score = scoreBlind(paths.answersPath, paths.reportPath);
    for (const line of score.lines) console.log(line);
    const perfect =
      score.missedBreaks === 0 &&
      score.falseBreaks === 0 &&
      score.correctBreaks === score.expectedBreaks;
    console.log(
      `\ncorrectBreaks=${score.correctBreaks}/${score.expectedBreaks} ` +
        `holds=${score.correctFailures}/${score.unexpectedSurvivors} ` +
        `falseBreaks=${score.falseBreaks} missed=${score.missedBreaks}`,
    );
    console.log(perfect ? "\nBLIND TEST PASSED" : "\nBLIND TEST FAILED");
    process.exit(perfect ? 0 : 1);
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

main();
