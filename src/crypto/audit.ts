/**
 * Audit engine: encryption narrative × taxonomy claims → findings or n/a.
 * Silence is not evidence.
 */

import {
  BREAK_EDGES,
  HARDENED_DEMO_PROFILE,
  INSECURE_DEMO_PROFILE,
  edgesForLevel,
  levelOrThrow,
  type ProfileClaim,
} from "./breaks.js";
import { ENCRYPTION_LEVELS, type EncryptionLevel } from "./levels.js";
import { MICRO_DOMAINS, microDomain } from "./taxonomy.js";

export type AuditStatus = "finding" | "pass" | "n/a";

export type AuditLine = {
  status: AuditStatus;
  levelId: string;
  levelName: string;
  microDomainId: string;
  microTitle: string;
  severity?: "critical" | "high" | "medium" | "low";
  message: string;
  reason?: string;
};

export type AuditReport = {
  profileName: string;
  generatedAt: string;
  summary: {
    findings: number;
    passes: number;
    na: number;
    critical: number;
    high: number;
  };
  lines: AuditLine[];
  shorBreakableLevels: string[];
};

/**
 * Evaluate a profile. For each break edge on a claimed level:
 * - claim false or missing → finding (control absent)
 * - claim true → pass
 * Micro-domains with no edge for that level → n/a
 */
export function auditProfile(profileName: string, profile: ProfileClaim[]): AuditReport {
  const lines: AuditLine[] = [];
  const claimedLevels = new Set(profile.map((p) => p.levelId));
  const claimMap = new Map(profile.map((p) => [p.levelId, p.claims] as const));

  for (const level of ENCRYPTION_LEVELS) {
    const edges = edgesForLevel(level.id);
    const claims = claimMap.get(level.id);

    if (!claimedLevels.has(level.id)) {
      lines.push({
        status: "n/a",
        levelId: level.id,
        levelName: level.name,
        microDomainId: "*",
        microTitle: "profile coverage",
        message: "Level not in audit profile",
        reason: "n/a — level not selected for this profile",
      });
      continue;
    }

    if (edges.length === 0) {
      lines.push({
        status: "n/a",
        levelId: level.id,
        levelName: level.name,
        microDomainId: "*",
        microTitle: "break map",
        message: "No taxonomy break edges mapped",
        reason: "n/a — no curated break edge for this level yet",
      });
      continue;
    }

    for (const edge of edges) {
      const micro = microDomain(edge.microDomainId);
      const present = claims?.[edge.microDomainId];
      if (present === true) {
        lines.push({
          status: "pass",
          levelId: level.id,
          levelName: level.name,
          microDomainId: edge.microDomainId,
          microTitle: micro?.title ?? edge.microDomainId,
          message: `Control claimed present; narrative holds for: ${edge.narrative}`,
        });
      } else {
        lines.push({
          status: "finding",
          levelId: level.id,
          levelName: level.name,
          microDomainId: edge.microDomainId,
          microTitle: micro?.title ?? edge.microDomainId,
          severity: edge.severity,
          message: edge.narrative,
          reason:
            present === false
              ? "control explicitly absent in profile"
              : "silence is not evidence — claim missing",
        });
      }
    }
  }

  // Global micro-domains never referenced in any edge for profile levels → explicit n/a sample
  const referenced = new Set(
    BREAK_EDGES.filter((e) => claimedLevels.has(e.levelId)).map((e) => e.microDomainId),
  );
  for (const micro of MICRO_DOMAINS) {
    if (referenced.has(micro.id)) continue;
    lines.push({
      status: "n/a",
      levelId: "global",
      levelName: "Global taxonomy",
      microDomainId: micro.id,
      microTitle: micro.title,
      message: micro.cryptoBreak,
      reason: "n/a — no profile edge binds this micro-domain to a selected level",
    });
  }

  const findings = lines.filter((l) => l.status === "finding");
  return {
    profileName,
    generatedAt: new Date().toISOString(),
    summary: {
      findings: findings.length,
      passes: lines.filter((l) => l.status === "pass").length,
      na: lines.filter((l) => l.status === "n/a").length,
      critical: findings.filter((l) => l.severity === "critical").length,
      high: findings.filter((l) => l.severity === "high").length,
    },
    lines,
    shorBreakableLevels: ENCRYPTION_LEVELS.filter((l) => l.shorBreakable).map((l) => l.id),
  };
}

export function narrativeForLevel(level: EncryptionLevel): string {
  return [
    `## ${level.name} (\`${level.id}\`)`,
    "",
    `**Promise:** ${level.promise}`,
    "",
    `**Assumption:** ${level.assumption}`,
    "",
    "**Workflow:**",
    ...level.workflow.map((step, i) => `${i + 1}. ${step}`),
    "",
    `**Shor-breakable:** ${level.shorBreakable ? "yes" : "no"}`,
    `**Grover-relevant:** ${level.groverRelevant ? "yes" : "no"}`,
  ].join("\n");
}

export function allNarrativesMarkdown(): string {
  const header = `# Encryption level narratives (generated)\n\nSource: \`src/crypto/levels.ts\`\n`;
  return header + ENCRYPTION_LEVELS.map((l) => narrativeForLevel(l)).join("\n\n---\n\n");
}

export function presetProfile(name: "insecure" | "hardened"): ProfileClaim[] {
  return name === "insecure" ? INSECURE_DEMO_PROFILE : HARDENED_DEMO_PROFILE;
}

export function describeBreak(levelId: string, microDomainId: string): string {
  const level = levelOrThrow(levelId);
  const edge = BREAK_EDGES.find((e) => e.levelId === levelId && e.microDomainId === microDomainId);
  const micro = microDomain(microDomainId);
  if (!edge || !micro) {
    return `n/a — no break edge for ${levelId} × ${microDomainId}`;
  }
  return [
    `Level: ${level.name}`,
    `Promise: ${level.promise}`,
    `Taxonomy ${micro.id}: ${micro.title}`,
    `Break: ${edge.narrative}`,
    `Generic crypto impact: ${micro.cryptoBreak}`,
    `Severity: ${edge.severity}`,
  ].join("\n");
}
