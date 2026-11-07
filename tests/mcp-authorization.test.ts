import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerMcpRoutes } from "../src/api/routes/mcp.js";
import { handleError } from "../src/api/http.js";
import { AuthService } from "../src/core/services/auth-service.js";
import { McpProxyService } from "../src/core/mcp/mcp-proxy-service.js";
import type { PlatformContext } from "../src/core/services/platform-context.js";

// Exercise real HTTP, authentication, session transport, and MCP tool dispatch.
// Only business services/upstream discovery are stubbed to isolate authorization.
describe("MCP authorization", () => {
  const app = () => Fastify();
  let server: ReturnType<typeof app>;
  let url: string;
  let auth: AuthService;
  let sequence = 0;
  const getAction = vi.fn();
  const listReceipts = vi.fn();
  const submitAction = vi.fn();
  const enforceIdentity = vi.fn();

  function token(scopes = ["actions:read", "receipts:read", "actions:write"], subject = "alice", tenantIds = ["tenant_alpha", "tenant_bravo"]) {
    return auth.issueToken({ subject, tenantIds, scopes, role: "agent" }).accessToken;
  }

  async function request(body: unknown, accessToken: string, sessionId?: string, tenant = "tenant_alpha", method = "POST") {
    return fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json, text/event-stream",
        ...(method === "POST" ? { "content-type": "application/json" } : {}),
        "mcp-protocol-version": "2025-03-26",
        "x-oars-tenant-id": tenant,
        ...(sessionId ? { "mcp-session-id": sessionId } : {})
      },
      ...(method === "POST" ? { body: JSON.stringify(body) } : {})
    });
  }

  async function initialize(accessToken: string, tenant = "tenant_alpha") {
    const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "initialize", params: {
      protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "authorization-test", version: "1" }
    } }, accessToken, undefined, tenant);
    await response.text();
    expect(response.status).toBe(200);
    const session = response.headers.get("mcp-session-id");
    expect(session).toBeTruthy();
    const initialized = await request({ jsonrpc: "2.0", method: "notifications/initialized" }, accessToken, session!, tenant);
    await initialized.text();
    expect(initialized.status).toBe(202);
    return session!;
  }

  async function call(accessToken: string, session: string, name: string, actionId = "alpha-action") {
    const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "tools/call", params: { name, arguments: { actionId } } }, accessToken, session);
    const raw = await response.text();
    expect(response.status).toBe(200);
    const data = raw.split("\n").find((line) => line.startsWith("data: "));
    return JSON.parse(data ? data.slice(6) : raw).result;
  }

  beforeEach(async () => {
    vi.spyOn(McpProxyService.prototype, "listProxyTools").mockResolvedValue([
      { name: "mcp_test__echo", upstreamId: "test", upstreamToolName: "echo", title: null, description: null }
    ]);
    getAction.mockImplementation(async (id: string) => id === "missing" ? null : ({ id, tenantId: id === "alpha-action" ? "tenant_alpha" : "tenant_bravo", state: "completed", input: { secret: "private payload" } }));
    listReceipts.mockResolvedValue([{ id: "receipt-alpha" }]);
    submitAction.mockResolvedValue({ actionId: "created-action", state: "completed" });
    auth = new AuthService({ jwtSecret: "mcp-authorization-test-secret" });
    server = app();
    server.setErrorHandler((error, _request, reply) => handleError(error, reply));
    registerMcpRoutes(server, {
      authService: auth,
      serviceIdentityService: { enforceRequestIdentity: enforceIdentity },
      actionService: { getAction, submitAction },
      store: { listReceiptsByAction: listReceipts }
    } as unknown as PlatformContext);
    url = `${await server.listen({ port: 0, host: "127.0.0.1" })}/mcp`;
  });

  afterEach(async () => {
    await server.close();
    vi.restoreAllMocks();
    vi.resetAllMocks();
  });

  it("allows read-only clients and enforces each tool's own scope", async () => {
    const reader = token(["actions:read"]);
    const session = await initialize(reader);
    expect((await call(reader, session, "oars_get_action")).structuredContent.action.id).toBe("alpha-action");
    expect((await call(reader, session, "oars_list_receipts")).isError).toBe(true);
    expect((await call(reader, session, "mcp_test__echo")).isError).toBe(true);
    expect(listReceipts).not.toHaveBeenCalled();
    expect(submitAction).not.toHaveBeenCalled();

    const receiptsReader = token(["receipts:read"]);
    expect((await call(receiptsReader, session, "oars_list_receipts")).structuredContent.receipts).toHaveLength(1);
    expect((await call(receiptsReader, session, "oars_get_action")).isError).toBe(true);
  });

  it("does not let write-only tokens read actions or receipts", async () => {
    const writer = token(["actions:write"]);
    const session = await initialize(writer);
    expect((await call(writer, session, "oars_get_action")).isError).toBe(true);
    expect((await call(writer, session, "oars_list_receipts")).isError).toBe(true);
    expect(getAction).not.toHaveBeenCalled();
    expect((await call(writer, session, "mcp_test__echo")).structuredContent.result.actionId).toBe("created-action");
    expect(submitAction).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant_alpha", agentId: "mcp:alice" }), expect.any(String));
  });

  it("denies cross-tenant objects even when the token can access both tenants", async () => {
    const accessToken = token();
    const session = await initialize(accessToken);
    for (const tool of ["oars_get_action", "oars_list_receipts"]) {
      const denied = await call(accessToken, session, tool, "bravo-action");
      expect(denied.isError).toBe(true);
      expect(JSON.stringify(denied)).not.toContain("private payload");
      expect(denied).toEqual(await call(accessToken, session, tool, "missing"));
    }
    expect(listReceipts).not.toHaveBeenCalled();
  });

  it("binds every session method to its subject and selected tenant", async () => {
    const alice = token();
    const session = await initialize(alice);
    for (const method of ["POST", "GET", "DELETE"]) {
      for (const [accessToken, tenant] of [[token(undefined, "bob"), "tenant_alpha"], [alice, "tenant_bravo"]]) {
        const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "tools/list" }, accessToken!, session, tenant!, method);
        expect(response.status).toBe(403);
        await response.text();
      }
    }
    expect((await call(alice, session, "oars_get_action")).isError).not.toBe(true);
  });

  it("rechecks token scopes and tenant membership instead of preserving initialization privileges", async () => {
    const session = await initialize(token());
    expect((await call(token([]), session, "oars_get_action")).isError).toBe(true);
    const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "tools/list" }, token(undefined, "alice", ["tenant_bravo"]), session);
    expect(response.status).toBe(403);
    await response.text();
    const invalid = await request({}, "invalid-token", session);
    expect(invalid.status).toBe(401);
    await invalid.text();
  });

  it("rejects an explicit unauthorized tenant even on single-tenant tokens", async () => {
    const response = await request({}, token(undefined, "alice", ["tenant_alpha"]), undefined, "tenant_bravo");
    expect(response.status).toBe(403);
    await response.text();
  });

  it("keeps workload identity checks on resumed sessions", async () => {
    const accessToken = token();
    const session = await initialize(accessToken);
    enforceIdentity.mockImplementationOnce(() => { throw new Error("Workload identity required."); });
    const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "tools/list" }, accessToken, session);
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("mtls_identity_required");
  });

  it("returns 404 for unknown sessions rather than silently creating a replacement", async () => {
    const response = await request({ jsonrpc: "2.0", id: ++sequence, method: "initialize", params: {} }, token(), "unknown-session");
    expect(response.status).toBe(404);
    await response.text();
  });
});
