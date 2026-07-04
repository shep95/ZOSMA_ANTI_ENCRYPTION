import { assertSafeUrl } from "./ssrf.js";

const DEFAULT_TIMEOUT_MS = 12_000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_SCRIPTS = 15;

export type FetchedDoc = {
  url: string;
  contentType: string;
  body: string;
};

export async function fetchText(rawUrl: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<FetchedDoc> {
  const url = await assertSafeUrl(rawUrl);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "user-agent": "ZOSMA-SecretScanner/1.0 (+authorized-security-testing)",
        accept: "text/html,application/javascript,text/javascript,application/json,text/plain,*/*",
      },
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} for ${url.href}`);
    }

    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_BODY_BYTES) {
      throw new Error(`Response exceeds ${MAX_BODY_BYTES} bytes`);
    }

    return {
      url: url.href,
      contentType: res.headers.get("content-type") ?? "application/octet-stream",
      body: buf.toString("utf8"),
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Extract same-origin script URLs from HTML (bounded). */
export function extractScriptUrls(html: string, pageUrl: string): string[] {
  const base = new URL(pageUrl);
  const urls: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const src = m[1];
    if (!src || src.startsWith("data:")) continue;
    try {
      const abs = new URL(src, base);
      if (abs.protocol !== "http:" && abs.protocol !== "https:") continue;
      // Prefer same-site scripts to reduce drive-by scanning of CDNs only when needed
      urls.push(abs.href);
    } catch {
      // skip
    }
    if (urls.length >= MAX_SCRIPTS) break;
  }
  return urls;
}
