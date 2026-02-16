import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadUpstreamsFromEnv, type McpUpstreamDefinition } from "../mcp/upstreams.js";

function isContentResult(
  result: CallToolResult
): result is Extract<CallToolResult, { content: Array<{ type: string }> }> {
  return typeof result === "object" && result !== null && "content" in result;
}

function extractErrorText(result: CallToolResult): string {
  if (!isContentResult(result)) {
    return "Upstream MCP tool returned an error.";
  }
  const text = result.content
    .filter((entry): entry is { type: "text"; text: string } => entry.type === "text")
    .map((entry) => entry.text.trim())
    .filter(Boolean)
    .join("\n");
  return text || "Upstream MCP tool returned an error.";
}

export class McpConnector implements Connector {
  readonly toolId = "mcp";
  private readonly upstreamsById: Map<string, McpUpstreamDefinition>;

  constructor(upstreams: McpUpstreamDefinition[]) {
    this.upstreamsById = new Map(upstreams.map((upstream) => [upstream.id, upstream]));
  }

  static fromEnv(): McpConnector | null {
    const upstreams = loadUpstreamsFromEnv();
    if (upstreams.length === 0) {
      return null;
    }
    return new McpConnector(upstreams);
  }

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    const upstreamId = action.resource.target;
    const upstream = this.upstreamsById.get(upstreamId);
    if (!upstream) {
      return {
        success: false,
        output: {},
        error: `Unknown MCP upstream: ${upstreamId}`
      };
    }

    const toolName = action.resource.operation;
    const args = action.input as Record<string, unknown>;

    let client: Client | null = null;
    try {
      const requestInit = upstream.headers ? ({ headers: upstream.headers } as RequestInit) : undefined;
      const transport = new StreamableHTTPClientTransport(new URL(upstream.url), {
        ...(requestInit ? { requestInit } : {})
      });
      client = new Client(
        {
          name: "oars-mcp-connector",
          version: "0.1.0"
        },
        {
          capabilities: {}
        }
      );
      await client.connect(transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport);

      const result = (await client.callTool({
        name: toolName,
        arguments: args
      })) as unknown as CallToolResult;

      if (!isContentResult(result)) {
        return {
          success: true,
          output: {
            upstreamId,
            tool: toolName,
            toolResult: (result as { toolResult?: unknown }).toolResult ?? null
          },
          error: null
        };
      }

      if (result.isError) {
        return {
          success: false,
          output: {
            upstreamId,
            tool: toolName,
            content: result.content,
            structuredContent: result.structuredContent ?? null
          },
          error: extractErrorText(result)
        };
      }

      return {
        success: true,
        output: {
          upstreamId,
          tool: toolName,
          content: result.content,
          structuredContent: result.structuredContent ?? null
        },
        error: null
      };
    } catch (error) {
      return {
        success: false,
        output: {
          upstreamId,
          tool: toolName
        },
        error: error instanceof Error ? error.message : "Unknown MCP connector error."
      };
    } finally {
      await client?.close().catch(() => undefined);
    }
  }
}
