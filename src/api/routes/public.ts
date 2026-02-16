import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { handleError, requestIdFromHeaders } from "../http.js";

function parseBoolean(value: string | undefined): boolean | null {
  if (value === undefined) {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "true" || normalized === "1") {
    return true;
  }
  if (normalized === "false" || normalized === "0") {
    return false;
  }
  return null;
}

export function registerPublicRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.get("/health", async () => ({
    status: "ok",
    service: "oars-platform",
    timestamp: new Date().toISOString()
  }));

  // Admin dashboard UI
  const dashboardEnabled = (() => {
    const configured = parseBoolean(process.env.OARS_DASHBOARD_ENABLED);
    if (configured !== null) {
      return configured;
    }
    return process.env.NODE_ENV !== "production";
  })();
  const dashboardHtmlPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dashboard.html");
  let dashboardHtml: string | null = null;
  app.get("/dashboard", async (_request, reply) => {
    if (!dashboardEnabled) {
      return reply.status(404).send({ error: { code: "not_found", message: "Dashboard not available." } });
    }
    if (!dashboardHtml) {
      try {
        dashboardHtml = readFileSync(dashboardHtmlPath, "utf8");
      } catch {
        return reply.status(404).send({ error: { code: "not_found", message: "Dashboard not available." } });
      }
    }
    reply.header("content-type", "text/html; charset=utf-8");
    return reply.send(dashboardHtml);
  });

  app.get("/v1/trust/tenants/:tenantId/keys", async (request, reply) => {
    try {
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      return reply.send({
        tenantId: params.tenantId,
        items: context.signingKeyService.listTenantPublicKeys(params.tenantId)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}
