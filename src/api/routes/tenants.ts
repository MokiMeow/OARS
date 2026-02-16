import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { createTenantSchema } from "../../core/types/schemas.js";
import { authenticate, handleError, requestIdFromHeaders, requireRole } from "../http.js";

export function registerTenantRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.post("/v1/tenants", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const payload = createTenantSchema.parse(request.body);
      const created = await context.tenantAdminService.createTenant(
        payload.tenantId,
        payload.displayName,
        payload.ownerSubject ?? claims.subject,
        claims.subject
      );
      return reply.status(201).send(created);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:read");
      requireRole(context, claims, "admin");
      return reply.send({
        items: await context.tenantAdminService.listTenants()
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

