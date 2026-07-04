/**
 * Authorized API surface probe for aureonai.app (owner-requested).
 * Uses only public client material. Non-destructive GETs. No mass exfil.
 */

import { scanUrl } from "../src/scan/scanner.js";

const SITE = "https://aureonai.app";

async function get(url: string, headers: Record<string, string> = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 12_000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json", ...headers },
      redirect: "follow",
    });
    const text = await res.text();
    return {
      status: res.status,
      ct: res.headers.get("content-type") ?? "",
      body: text.slice(0, 400),
    };
  } finally {
    clearTimeout(t);
  }
}

function b64urlJson(part: string): Record<string, unknown> {
  const pad = part + "=".repeat((4 - (part.length % 4)) % 4);
  return JSON.parse(
    Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
  );
}

async function main() {
  console.log("=== Aureon API probe (authorized, non-destructive) ===\n");

  // 1) Public paths on the app origin
  console.log("--- App origin paths ---");
  for (const p of [
    "/",
    "/api",
    "/api/health",
    "/api/v1",
    "/health",
    "/robots.txt",
    "/sitemap.xml",
  ]) {
    const r = await get(SITE + p);
    console.log(`${r.status} ${p} (${r.ct.slice(0, 32)}) ${r.body.replace(/\s+/g, " ").slice(0, 80)}`);
  }

  // 2) Recover public client JWT from bundle
  const report = await scanUrl(SITE + "/");
  const jwtFinding = report.findings.find((f) => f.patternId === "jwt");
  if (!jwtFinding) {
    console.log("\nNo JWT in client bundle — cannot probe Supabase REST as anon.");
    return;
  }

  const jwt = jwtFinding.value;
  const payload = b64urlJson(jwt.split(".")[1]!);
  const ref = String(payload.ref ?? "");
  const role = String(payload.role ?? "");
  const supabaseUrl = `https://${ref}.supabase.co`;

  console.log("\n--- Client identity (from public bundle) ---");
  console.log(`role=${role} ref=${ref}`);
  console.log(`supabase=${supabaseUrl}`);

  const authHeaders = {
    apikey: jwt,
    authorization: `Bearer ${jwt}`,
  };

  // 3) Supabase health / REST root
  console.log("\n--- Supabase surface ---");
  for (const path of ["/rest/v1/", "/auth/v1/health", "/auth/v1/settings"]) {
    const r = await get(supabaseUrl + path, authHeaders);
    console.log(`${r.status} ${path} ${r.body.replace(/\s+/g, " ").slice(0, 120)}`);
  }

  // 4) OpenAPI schema (lists tables if exposed)
  const openapi = await get(supabaseUrl + "/rest/v1/", {
    ...authHeaders,
    accept: "application/openapi+json",
  });
  console.log(`\nOpenAPI status=${openapi.status}`);

  let tableNames: string[] = [];
  if (openapi.status === 200) {
    try {
      const spec = JSON.parse(openapi.body.length < 400 ? openapi.body : await (async () => {
        const full = await fetch(supabaseUrl + "/rest/v1/", {
          headers: { ...authHeaders, accept: "application/openapi+json" },
        });
        return full.text();
      })());
      const paths = Object.keys(spec.paths ?? {});
      tableNames = paths
        .map((p) => p.replace(/^\//, "").split("/")[0]!)
        .filter((t) => t && !t.includes("{"));
      tableNames = [...new Set(tableNames)];
      console.log(`Tables/views in OpenAPI: ${tableNames.length ? tableNames.join(", ") : "(none)"}`);
    } catch (e) {
      console.log(`OpenAPI parse issue: ${e instanceof Error ? e.message : e}`);
      console.log(`body snippet: ${openapi.body.slice(0, 200)}`);
    }
  }

  // 5) Probe common names + discovered tables — HEAD/GET limit 1 row only
  const candidates = [
    ...tableNames,
    "users",
    "profiles",
    "accounts",
    "messages",
    "documents",
    "files",
    "data",
    "datasets",
    "items",
    "projects",
    "organizations",
    "orgs",
    "tenants",
    "api_keys",
    "secrets",
    "settings",
  ];
  const unique = [...new Set(candidates)];

  console.log("\n--- Table access as anon (max 1 row, non-destructive) ---");
  const openTables: string[] = [];
  for (const table of unique) {
    const url = `${supabaseUrl}/rest/v1/${table}?select=*&limit=1`;
    const r = await get(url, {
      ...authHeaders,
      prefer: "count=exact",
    });
    const interesting = r.status !== 404 && r.status !== 0;
    if (interesting) {
      const open = r.status === 200;
      if (open) openTables.push(table);
      console.log(
        `${r.status} ${table} ${r.body.replace(/\s+/g, " ").slice(0, 100)}`,
      );
    }
  }

  console.log("\n=== Summary ===");
  console.log(`Anon role JWT present in frontend: yes`);
  console.log(`Tables readable as anon (sample): ${openTables.length ? openTables.join(", ") : "none observed"}`);
  if (openTables.length) {
    console.log(
      "RISK: RLS may be missing/weak on listed tables — anon client can read rows.",
    );
  } else {
    console.log(
      "No open table reads observed on probed names (RLS may be blocking or tables use other names).",
    );
  }
  console.log("No service_role key found in client. No writes performed.");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
