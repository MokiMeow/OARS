import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import {
  refreshProvidersSchema,
  serviceTokenSchema,
  startRefreshSchedulerSchema,
  tokenExchangeSchema
} from "../../core/types/schemas.js";
import {
  HttpError,
  authenticate,
  handleError,
  requestIdFromHeaders,
  requireRole,
  requireTenantAccess
} from "../http.js";

export function registerAuthRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.post("/v1/auth/service-token", async (request, reply) => {
    try {
      const payload = serviceTokenSchema.parse(request.body);
      const authentication = await context.serviceAccountService.authenticate(
        payload.clientId,
        payload.clientSecret,
        payload.tenantId
      );
      const token = context.authService.issueToken({
        subject: `service_account:${authentication.account.id}`,
        tenantIds: [payload.tenantId],
        scopes: authentication.account.scopes,
        role: "service",
        serviceAccountId: authentication.account.id,
        ...(payload.expiresInSeconds ? { expiresInSeconds: payload.expiresInSeconds } : {})
      });
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "service_token.issued",
        payload: {
          serviceAccountId: authentication.account.id
        }
      });

      return reply.send({
        tokenType: "Bearer",
        accessToken: token.accessToken,
        expiresAt: token.expiresAt,
        serviceAccountId: authentication.account.id
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/auth/token/exchange", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "token:exchange");
      const payload = tokenExchangeSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);

      const requestedSubject = payload.subject ?? claims.subject;
      if (requestedSubject !== claims.subject && !context.authService.canImpersonate(claims)) {
        throw new HttpError(403, "forbidden", "Token cannot impersonate requested subject.");
      }

      const requestedScopes =
        payload.scopes ??
        ["actions:write", "actions:read", "receipts:read", "receipts:verify", "alerts:read", "connectors:read"];
      context.authService.assertRequestedScopesWithin(claims.scopes, requestedScopes);

      const token = context.authService.issueToken({
        subject: requestedSubject,
        tenantIds: [payload.tenantId],
        scopes: requestedScopes,
        role: "agent",
        delegationChain: [claims.subject, payload.agentId, "oars-gateway"],
        ...(payload.expiresInSeconds ? { expiresInSeconds: payload.expiresInSeconds } : {})
      });
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "token.exchanged",
        payload: {
          issuedBy: claims.subject,
          issuedForSubject: requestedSubject,
          agentId: payload.agentId
        }
      });

      return reply.send({
        tokenType: "Bearer",
        accessToken: token.accessToken,
        expiresAt: token.expiresAt,
        issuedForAgentId: payload.agentId
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/auth/providers", async (request, reply) => {
    try {
      authenticate(context, request.headers as Record<string, unknown>, "auth_providers:read");
      return reply.send({
        items: context.authService.listTrustedProviders()
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/auth/providers/refresh", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "auth_providers:refresh");
      requireRole(context, claims, "admin");
      const payload = refreshProvidersSchema.parse(request.body ?? {});
      const result = await context.authService.refreshTrustedProviders(payload.issuer);
      return reply.send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/auth/providers/discover", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "auth_providers:refresh");
      requireRole(context, claims, "admin");
      const payload = refreshProvidersSchema.parse(request.body ?? {});
      if (payload.issuer) {
        const discovered = await context.jwksService.discoverIssuer(payload.issuer);
        return reply.send({
          discoveredIssuers: discovered ? [payload.issuer] : [],
          failedDiscoveries: discovered ? [] : [payload.issuer]
        });
      }
      return reply.send(await context.jwksService.discoverAll());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/auth/refresh-scheduler", async (request, reply) => {
    try {
      authenticate(context, request.headers as Record<string, unknown>, "auth_providers:read");
      return reply.send(context.jwksService.schedulerStatus());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/auth/refresh-scheduler/start", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "auth_providers:refresh");
      requireRole(context, claims, "admin");
      const payload = startRefreshSchedulerSchema.parse(request.body ?? {});
      return reply.send(
        await context.jwksService.startAutoRefresh(payload.intervalSeconds ?? 300, payload.discoverOnStart ?? true)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/auth/refresh-scheduler/stop", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "auth_providers:refresh");
      requireRole(context, claims, "admin");
      return reply.send(context.jwksService.stopAutoRefresh());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

