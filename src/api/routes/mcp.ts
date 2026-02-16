import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import { McpProxyService } from "../../core/mcp/mcp-proxy-service.js";
import { authHeaderFromHeaders, authenticate, requestIdFromHeaders } from "../http.js";

type SessionEntry = {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  createdAt: number;
};

function parseAllowedOrigins(raw: string | undefined): string[] | null {
  if (!raw) return null;
  const allowed = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return allowed.length > 0 ? allowed : null;
}

function isOriginAllowed(origin: string, allowed: string[] | null): boolean {
  if (!allowed) return true;
  if (allowed.includes("*")) return true;
  return allowed.includes(origin);
}

export function registerMcpRoutes(app: FastifyInstance, context: PlatformContext): void {
  const proxyService = new McpProxyService();
  const sessions = new Map<string, SessionEntry>();
  const allowedOrigins = parseAllowedOrigins(process.env.OARS_MCP_ALLOWED_ORIGINS);

  async function createSession(): Promise<{ transport: StreamableHTTPServerTransport; server: McpServer }> {
    let transport: StreamableHTTPServerTransport | null = null;
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        const entry = sessions.get(sessionId);
        if (entry) return;
        sessions.set(sessionId, {
          transport: transport!,
          server: server!,
          createdAt: Date.now()
        });
        transport!.onclose = () => {
          const removed = sessions.get(sessionId);
          sessions.delete(sessionId);
          void removed?.server.close().catch(() => undefined);
        };
      }
    });

    const server = new McpServer(
      {
        name: "oars-mcp-proxy",
        version: "0.1.0"
      },
      {
        capabilities: {
          tools: {
            listChanged: true
          }
        }
      }
    );

    server.registerTool(
      "oars_get_action",
      {
        title: "Get OARS action",
        description: "Fetch an OARS action by ID.",
        inputSchema: {
          actionId: z.string()
        }
      },
      async ({ actionId }) => {
        const action = await context.actionService.getAction(actionId);
        return {
          content: [
            {
              type: "text",
              text: action ? `Action ${actionId}: ${action.state}` : `Action not found: ${actionId}`
            }
          ],
          structuredContent: {
            action: action ?? null
          }
        };
      }
    );

    server.registerTool(
      "oars_list_receipts",
      {
        title: "List receipts",
        description: "List receipts for an OARS action.",
        inputSchema: {
          actionId: z.string()
        }
      },
      async ({ actionId }) => {
        const receipts = await context.store.listReceiptsByAction(actionId);
        return {
          content: [
            {
              type: "text",
              text: `Receipts for ${actionId}: ${receipts.length}`
            }
          ],
          structuredContent: {
            receipts
          }
        };
      }
    );

    const proxyTools = await proxyService.listProxyTools();
    for (const tool of proxyTools) {
      server.registerTool(
        tool.name,
        {
          title: tool.title ?? tool.upstreamToolName,
          description: tool.description ?? `Proxied MCP tool ${tool.upstreamToolName} via upstream ${tool.upstreamId}.`,
          inputSchema: z.record(z.string(), z.unknown())
        },
        async (args, extra) => {
          const authInfo = extra.authInfo;
          const extraData = authInfo?.extra as { tenantId?: unknown; subject?: unknown } | undefined;
          const tenantId = typeof extraData?.tenantId === "string" ? extraData.tenantId : null;
          const subject = typeof extraData?.subject === "string" ? extraData.subject : authInfo?.clientId ?? "unknown";
          if (!tenantId) {
            return {
              content: [{ type: "text", text: "Missing tenant context for MCP tool call." }],
              isError: true
            };
          }

          const requestId = requestIdFromHeaders(
            (extra.requestInfo?.headers ?? {}) as unknown as Record<string, unknown>
          );
          const result = await context.actionService.submitAction(
            {
              tenantId,
              agentId: `mcp:${subject}`,
              userContext: { userId: subject },
              resource: {
                toolId: "mcp",
                operation: tool.upstreamToolName,
                target: tool.upstreamId
              },
              input: args as Record<string, unknown>
            },
            requestId
          );

          return {
            content: [
              {
                type: "text",
                text: result.error
                  ? `Action ${result.actionId} ended in state ${result.state}: ${result.error}`
                  : `Action ${result.actionId} ended in state ${result.state}`
              }
            ],
            structuredContent: { result },
            isError: Boolean(result.error)
          };
        }
      );
    }

    await server.connect(
      transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport
    );
    return { transport, server };
  }

  // Basic session eviction to prevent unbounded memory growth.
  const sessionTtlMs = 60 * 60 * 1000;
  const evictionTimer = setInterval(() => {
    const cutoff = Date.now() - sessionTtlMs;
    for (const [sessionId, entry] of sessions.entries()) {
      if (entry.createdAt < cutoff) {
        sessions.delete(sessionId);
        void entry.transport.close().catch(() => undefined);
        void entry.server.close().catch(() => undefined);
      }
    }
  }, 60_000).unref();

  app.addHook("onClose", async () => {
    clearInterval(evictionTimer);
    for (const entry of sessions.values()) {
      await entry.transport.close().catch(() => undefined);
      await entry.server.close().catch(() => undefined);
    }
    sessions.clear();
  });

  app.all("/mcp", async (request, reply) => {
    const headers = request.headers as unknown as Record<string, unknown>;
    const origin = headers.origin;
    if (typeof origin === "string" && !isOriginAllowed(origin, allowedOrigins)) {
      return reply.status(403).send({ error: { code: "cors_forbidden", message: "Origin is not allowed." } });
    }

    // Authenticate once per HTTP request and pass through to MCP handlers via req.auth (SDK convention).
    const claims = authenticate(context, headers, "actions:write");
    const tenantHeader = headers["x-oars-tenant-id"];
    const requestedTenant =
      typeof tenantHeader === "string" && tenantHeader.trim().length > 0 ? tenantHeader.trim() : null;
    const tenantId =
      claims.tenantIds.length === 1
        ? claims.tenantIds[0]!
        : requestedTenant && claims.tenantIds.includes(requestedTenant)
          ? requestedTenant
          : null;
    if (!tenantId) {
      return reply.status(400).send({
        error: {
          code: "tenant_required",
          message: "Token has multiple tenants; set x-oars-tenant-id to select one."
        }
      });
    }

    (request.raw as unknown as { auth?: unknown }).auth = {
      token: authHeaderFromHeaders(headers) ?? "",
      clientId: claims.subject,
      scopes: claims.scopes,
      extra: {
        subject: claims.subject,
        role: claims.role,
        tenantId,
        tenantIds: claims.tenantIds
      }
    };

    const sessionIdHeader = headers["mcp-session-id"];
    const sessionId = typeof sessionIdHeader === "string" && sessionIdHeader.trim().length > 0 ? sessionIdHeader.trim() : null;

    let entry: SessionEntry | null = null;
    if (sessionId) {
      entry = sessions.get(sessionId) ?? null;
    }

    if (!entry) {
      if (request.method !== "POST" || !isInitializeRequest(request.body)) {
        return reply.status(400).send({
          error: {
            code: "bad_request",
            message: "MCP session not initialized. Send initialize first."
          }
        });
      }
      const created = await createSession();
      entry = {
        transport: created.transport,
        server: created.server,
        createdAt: Date.now()
      };
    }

    reply.hijack();
    await entry.transport.handleRequest(request.raw, reply.raw, request.body);
  });
}
