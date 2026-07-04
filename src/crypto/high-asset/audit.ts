import {
  BROKEN_HIGH_ASSET_PROFILE,
  HARDENED_HIGH_ASSET_PROFILE,
  HIGH_ASSET_BREAKS,
  type HighAssetProfile,
} from "./breaks.js";
import { HIGH_ASSET_TIERS, highAssetTier } from "./levels.js";

export type HighAssetFinding = {
  status: "finding" | "pass";
  tierId: string;
  tierName: string;
  microDomainId: string;
  controlId: string;
  severity: "critical" | "high" | "medium";
  message: string;
};

export type HighAssetReport = {
  profileName: string;
  generatedAt: string;
  summary: { findings: number; passes: number; critical: number; high: number };
  findings: HighAssetFinding[];
};

export function auditHighAssetProfile(profile: HighAssetProfile): HighAssetReport {
  const findings: HighAssetFinding[] = [];

  for (const edge of HIGH_ASSET_BREAKS) {
    const tier = highAssetTier(edge.tierId);
    if (!tier) {
      throw new Error(`Unknown high-asset tier in break map: ${edge.tierId}`);
    }
    const present = profile.controls[edge.controlId] === true;
    findings.push({
      status: present ? "pass" : "finding",
      tierId: edge.tierId,
      tierName: tier.name,
      microDomainId: edge.microDomainId,
      controlId: edge.controlId,
      severity: edge.severity,
      message: edge.narrative,
    });
  }

  const open = findings.filter((f) => f.status === "finding");
  return {
    profileName: profile.name,
    generatedAt: new Date().toISOString(),
    summary: {
      findings: open.length,
      passes: findings.filter((f) => f.status === "pass").length,
      critical: open.filter((f) => f.severity === "critical").length,
      high: open.filter((f) => f.severity === "high").length,
    },
    findings,
  };
}

export function presetHighAssetProfile(name: "broken" | "hardened"): HighAssetProfile {
  return name === "broken" ? BROKEN_HIGH_ASSET_PROFILE : HARDENED_HIGH_ASSET_PROFILE;
}

export function narrativesMarkdown(): string {
  const parts = [
    "# High-asset encryption narratives (generated)\n",
    "Source: `src/crypto/high-asset/levels.ts`\n",
  ];
  for (const tier of HIGH_ASSET_TIERS) {
    parts.push(`## ${tier.name} (\`${tier.id}\`)\n`);
    parts.push(`**Assets:** ${tier.assets}\n`);
    parts.push(`**Promise:** ${tier.promise}\n`);
    parts.push(`**Hardness:** ${tier.primitiveHardness}\n`);
    parts.push(
      `**Shor-breakable primitive:** ${tier.shorBreakablePrimitive ? "partial/hybrid classical leg" : "no"}\n`,
    );
    parts.push("**Workflow:**\n");
    tier.workflow.forEach((step, i) => parts.push(`${i + 1}. ${step}`));
    parts.push("\n");
  }
  return parts.join("\n");
}
