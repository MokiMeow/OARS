import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { TokenClaims } from "../../core/types/auth.js";
import { McpProxyService } from "../../core/mcp/mcp-proxy-service.js";
import { authHeaderFromHeaders, authenticate, HttpError, requireTenantAccess, requestIdFromHeaders } from "../http.js";

type SessionEntry = {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  createdAt: number;
  subject: string;
  tenantId: string;
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

  async function createSession(subject: string, tenantId: string): Promise<{ transport: StreamableHTTPServerTransport; server: McpServer }> {
    let transport: StreamableHTTPServerTransport | null = null;
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        const entry = sessions.get(sessionId);
        if (entry) return;
        sessions.set(sessionId, {
          transport: transport!,
          server: server!,
          subject,
          tenantId,
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

    // Never capture initializing claims: each tool uses the current HTTP request's
    // verified credentials, so renewed/reduced tokens cannot retain old privileges.
    function authorizeTool(authInfo: AuthInfo | undefined, headers: Record<string, unknown>, scope: string): void {
      if (!authInfo) throw new Error("Missing authentication context.");
      const claims = authenticate(context, { ...headers, authorization: authInfo.token }, scope);
      requireTenantAccess(context, claims, tenantId);
      if (claims.subject !== subject || authInfo.extra?.tenantId !== tenantId) {
        throw new Error("MCP session principal or tenant mismatch.");
      }
    }

    server.registerTool(
      "oars_get_action",
      {
        title: "Get OARS action",
        description: "Fetch an OARS action by ID.",
        inputSchema: {
          actionId: z.string()
        }
      },
      async ({ actionId }, extra) => {
        authorizeTool(extra.authInfo, (extra.requestInfo?.headers ?? {}) as Record<string, unknown>, "actions:read");
        const action = await context.actionService.getAction(actionId);
        if (!action || action.tenantId !== tenantId) throw new Error("Action not found.");
        return {
          content: [
            {
              type: "text",
              text: `Action ${actionId}: ${action.state}`
            }
          ],
          structuredContent: {
            action
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
      async ({ actionId }, extra) => {
        authorizeTool(extra.authInfo, (extra.requestInfo?.headers ?? {}) as Record<string, unknown>, "receipts:read");
        const action = await context.actionService.getAction(actionId);
        if (!action || action.tenantId !== tenantId) throw new Error("Action not found.");
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
          authorizeTool(extra.authInfo, (extra.requestInfo?.headers ?? {}) as Record<string, unknown>, "actions:write");

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

    // Authenticate every HTTP request; tools enforce their own scopes below.
    // Pass request-local credentials through req.auth (SDK convention).
    let claims: TokenClaims;
    try {
      claims = context.authService.authenticate(authHeaderFromHeaders(headers));
    } catch (error) {
      throw new HttpError(401, "unauthorized", error instanceof Error ? error.message : "Unauthorized.");
    }
    try {
      context.serviceIdentityService.enforceRequestIdentity(claims, headers);
    } catch (error) {
      throw new HttpError(403, "mtls_identity_required", error instanceof Error ? error.message : "Forbidden.");
    }
    const tenantHeader = headers["x-oars-tenant-id"];
    const requestedTenant =
      typeof tenantHeader === "string" && tenantHeader.trim().length > 0 ? tenantHeader.trim() : null;
    const tenantId = requestedTenant ?? (claims.tenantIds.length === 1 ? claims.tenantIds[0]! : null);
    if (!tenantId) {
      return reply.status(400).send({
        error: {
          code: "tenant_required",
          message: "Token has multiple tenants; set x-oars-tenant-id to select one."
        }
      });
    }

    requireTenantAccess(context, claims, tenantId);

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
      if (!entry) {
        return reply.status(404).send({ error: { code: "session_not_found", message: "MCP session not found." } });
      }
      if (entry.subject !== claims.subject || entry.tenantId !== tenantId) {
        return reply.status(403).send({ error: { code: "session_forbidden", message: "MCP session access denied." } });
      }
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
      const created = await createSession(claims.subject, tenantId);
      entry = {
        transport: created.transport,
        server: created.server,
        createdAt: Date.now(),
        subject: claims.subject,
        tenantId
      };
    }

    reply.hijack();
    await entry.transport.handleRequest(request.raw, reply.raw, request.body);
  });
}
