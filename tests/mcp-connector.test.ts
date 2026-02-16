import { describe, expect, it } from "vitest";
import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod/v4";
import { McpConnector } from "../src/core/connectors/mcp-connector.js";
import { nowIso } from "../src/lib/time.js";
import type { ActionRecord } from "../src/core/types/domain.js";

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(raw.length ? JSON.parse(raw) : null);
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

async function startUpstream(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer(async (req, res) => {
    if (!req.url || !req.url.startsWith("/mcp")) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.setHeader("Allow", "POST");
      res.end("method not allowed");
      return;
    }

    const parsedBody = await readJson(req);

    const transport = new StreamableHTTPServerTransport({
      // SDK supports stateless mode when sessionIdGenerator is undefined, but the type doesn't accept it under
      // exactOptionalPropertyTypes.
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    } as any);

    const mcp = new McpServer({ name: "upstream", version: "1.0.0" });
    mcp.registerTool(
      "echo",
      {
        description: "Echo input",
        inputSchema: { text: z.string() }
      },
      async ({ text }) => {
        return {
          content: [{ type: "text", text }]
        };
      }
    );

    await mcp.connect(transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport);
    await transport.handleRequest(req, res, parsedBody);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to start upstream server.");
  }
  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    close: async () =>
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      )
  };
}

describe("McpConnector", () => {
  it("calls an upstream MCP tool over Streamable HTTP", async () => {
    const prevUpstreams = process.env.OARS_MCP_UPSTREAMS;
    const prevAllowPrivate = process.env.OARS_MCP_ALLOW_PRIVATE_NETWORK;
    const upstream = await startUpstream();

    try {
      process.env.OARS_MCP_ALLOW_PRIVATE_NETWORK = "true";
      process.env.OARS_MCP_UPSTREAMS = JSON.stringify([{ id: "local", url: upstream.url }]);

      const connector = McpConnector.fromEnv();
      expect(connector).toBeTruthy();

      const action: ActionRecord = {
        id: "act_test",
        tenantId: "tenant_alpha",
        state: "approved",
        actor: {
          userId: "user_test",
          agentId: "agent_test",
          serviceId: "oars-gateway",
          delegationChain: ["user_test", "agent_test", "oars-gateway"]
        },
        context: {
          requestedAt: nowIso()
        },
        resource: {
          toolId: "mcp",
          operation: "echo",
          target: "local"
        },
        input: {
          text: "hello"
        },
        approvalId: null,
        policyDecision: "allow",
        policySetId: "test",
        policyVersion: "1",
        policyRuleIds: [],
        policyRationale: null,
        lastError: null,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        receiptIds: []
      };

      const result = await connector!.execute(action);
      expect(result.success).toBe(true);
      expect(result.output.upstreamId).toBe("local");
      expect(result.output.tool).toBe("echo");
    } finally {
      await upstream.close();
      process.env.OARS_MCP_UPSTREAMS = prevUpstreams;
      process.env.OARS_MCP_ALLOW_PRIVATE_NETWORK = prevAllowPrivate;
    }
  }, 30_000);
});
