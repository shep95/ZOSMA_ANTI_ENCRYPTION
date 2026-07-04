/**
 * Block SSRF to private/link-local/metadata addresses (taxonomy 4.4.1).
 */

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
]);

export async function assertSafeUrl(raw: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid URL: ${raw}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http/https URLs are allowed");
  }

  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
    throw new Error(`Blocked host: ${host}`);
  }

  const addresses = isIP(host) ? [host] : await resolveHost(host);
  for (const addr of addresses) {
    if (isPrivateOrSpecial(addr)) {
      throw new Error(`Blocked address ${addr} for host ${host} (SSRF protection)`);
    }
  }

  return url;
}

async function resolveHost(host: string): Promise<string[]> {
  try {
    const v4 = await lookup(host, { all: true, family: 4 });
    return v4.map((r) => r.address);
  } catch {
    try {
      const v6 = await lookup(host, { all: true, family: 6 });
      return v6.map((r) => r.address);
    } catch (err) {
      throw new Error(`DNS lookup failed for ${host}: ${err instanceof Error ? err.message : err}`);
    }
  }
}

function isPrivateOrSpecial(ip: string): boolean {
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return true;
  if (ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;

  const v4 = ip.includes(".") ? ip : null;
  if (!v4) return false;

  const parts = v4.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts as [number, number, number, number];

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}
