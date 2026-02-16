import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { loadUpstreamsFromEnv, sanitizeProxyToolName, type McpUpstreamDefinition } from "./upstreams.js";

export interface ProxyToolDescriptor {
  name: string;
  upstreamId: string;
  upstreamToolName: string;
  title: string | null;
  description: string | null;
}

function parseIntWithMin(value: string | undefined, fallback: number, min: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < min) return fallback;
  return parsed;
}

export class McpProxyService {
  private readonly cacheTtlMs: number;
  private readonly upstreams: McpUpstreamDefinition[];
  private cache: { fetchedAt: number; tools: ProxyToolDescriptor[] } | null = null;

  constructor(upstreams = loadUpstreamsFromEnv()) {
    this.upstreams = upstreams;
    const ttlSeconds = parseIntWithMin(process.env.OARS_MCP_TOOL_CACHE_TTL_SECONDS, 300, 5);
    this.cacheTtlMs = ttlSeconds * 1000;
  }

  async listProxyTools(): Promise<ProxyToolDescriptor[]> {
    const now = Date.now();
    if (this.cache && now - this.cache.fetchedAt < this.cacheTtlMs) {
      return this.cache.tools;
    }

    const all: ProxyToolDescriptor[] = [];
    for (const upstream of this.upstreams) {
      const tools = await this.listUpstreamTools(upstream);
      for (const tool of tools) {
        all.push({
          name: sanitizeProxyToolName(upstream.id, tool.name),
          upstreamId: upstream.id,
          upstreamToolName: tool.name,
          title: tool.title ?? null,
          description: tool.description ?? null
        });
      }
    }

    this.cache = { fetchedAt: now, tools: all };
    return all;
  }

  private async listUpstreamTools(upstream: McpUpstreamDefinition): Promise<Tool[]> {
    let client: Client | null = null;
    try {
      const requestInit = upstream.headers ? ({ headers: upstream.headers } as RequestInit) : undefined;
      const transport = new StreamableHTTPClientTransport(new URL(upstream.url), {
        ...(requestInit ? { requestInit } : {})
      });
      client = new Client({ name: "oars-mcp-proxy", version: "0.1.0" }, { capabilities: {} });
      await client.connect(transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport);
      const result = await client.listTools();
      return result.tools ?? [];
    } catch {
      return [];
    } finally {
      await client?.close().catch(() => undefined);
    }
  }
}
