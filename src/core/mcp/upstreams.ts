import { isIP } from "node:net";

export interface McpUpstreamDefinition {
  id: string;
  url: string;
  headers?: Record<string, string> | undefined;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value.trim().toLowerCase() === "true";
}

function normalizeHost(host: string): string {
  let out = host.trim().toLowerCase();
  if (out.startsWith("[") && out.endsWith("]")) {
    out = out.slice(1, -1);
  }
  return out;
}

function isForbiddenHost(host: string): boolean {
  const normalized = normalizeHost(host);
  if (
    normalized.includes("169.254.") ||
    normalized.includes("metadata.internal") ||
    normalized.includes("metadata.google")
  ) {
    return true;
  }

  if (normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1" || normalized === "0.0.0.0" || normalized === "::") {
    return true;
  }

  const ipVersion = isIP(normalized);
  if (ipVersion === 4) {
    const ipv4Match = normalized.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    const first = ipv4Match ? Number.parseInt(ipv4Match[1]!, 10) : NaN;
    const second = ipv4Match ? Number.parseInt(ipv4Match[2]!, 10) : NaN;
    if (Number.isNaN(first) || Number.isNaN(second)) return true;
    if (first === 10) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    if (first === 127) return true;
    if (first === 169 && second === 254) return true;
    if (first === 0) return true;
    if (first === 100 && second >= 64 && second <= 127) return true;
    if (first === 198 && (second === 18 || second === 19)) return true;
  }

  if (ipVersion === 6) {
    if (normalized.startsWith("fd") || normalized.startsWith("fc")) return true;
    if (normalized.startsWith("fe80")) return true;
  }

  return false;
}

function safeId(value: string): string {
  const trimmed = value.trim();
  return trimmed.replace(/[^a-zA-Z0-9_-]/g, "_");
}

export function sanitizeProxyToolName(upstreamId: string, upstreamToolName: string): string {
  const upstream = safeId(upstreamId);
  const tool = upstreamToolName.trim().replace(/[^a-zA-Z0-9_-]/g, "_");
  return `mcp_${upstream}__${tool}`;
}

export function parseUpstreams(raw: string | undefined): McpUpstreamDefinition[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  const allowPrivate = parseBoolean(process.env.OARS_MCP_ALLOW_PRIVATE_NETWORK, false);
  const out: McpUpstreamDefinition[] = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object") continue;
    const candidate = entry as Partial<McpUpstreamDefinition>;
    if (typeof candidate.id !== "string" || typeof candidate.url !== "string") continue;
    const id = safeId(candidate.id);
    if (!id) continue;
    let url: URL;
    try {
      url = new URL(candidate.url);
    } catch {
      continue;
    }
    if (!(url.protocol === "http:" || url.protocol === "https:")) continue;
    if (!allowPrivate && isForbiddenHost(url.hostname)) {
      continue;
    }

    const headers: Record<string, string> = {};
    if (candidate.headers && typeof candidate.headers === "object") {
      for (const [key, value] of Object.entries(candidate.headers)) {
        if (typeof value !== "string") continue;
        if (key.trim().length === 0) continue;
        headers[key] = value;
      }
    }

    out.push({
      id,
      url: url.toString(),
      ...(Object.keys(headers).length > 0 ? { headers } : {})
    });
  }
  return out;
}

export function loadUpstreamsFromEnv(): McpUpstreamDefinition[] {
  return parseUpstreams(process.env.OARS_MCP_UPSTREAMS);
}

