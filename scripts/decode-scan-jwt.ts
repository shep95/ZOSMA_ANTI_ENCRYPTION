import { scanUrl } from "../src/scan/scanner.js";

function b64urlJson(part: string): unknown {
  const pad = part + "=".repeat((4 - (part.length % 4)) % 4);
  const json = Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  return JSON.parse(json);
}

const report = await scanUrl("https://aureonai.app/");
const finding = report.findings.find((f) => f.patternId === "jwt");
if (!finding) {
  console.log("No JWT finding");
  process.exit(0);
}
const [h, p] = finding.value.split(".");
console.log(
  JSON.stringify(
    {
      redacted: finding.redacted,
      source: finding.sourceUrl,
      header: b64urlJson(h!),
      payload: b64urlJson(p!),
    },
    null,
    2,
  ),
);
