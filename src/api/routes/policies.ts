import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { createPolicySchema, simulatePolicySchema } from "../../core/types/schemas.js";
import { createId } from "../../lib/id.js";
import { authenticate, handleError, requestIdFromHeaders, requireRole, requireTenantAccess } from "../http.js";

export function registerPolicyRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.post("/v1/policies", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:write");
      requireRole(context, claims, "admin");
      const payload = createPolicySchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const policy = await context.policyService.createPolicy(payload.tenantId, payload.version, payload.rules);
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "policy.created",
        payload: {
          policyId: policy.id,
          version: policy.version,
          actor: claims.subject
        }
      });
      return reply.status(201).send(policy);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/policies/simulate", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:read");
      const payload = simulatePolicySchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);

      const requestedAt = payload.context?.requestedAt ?? new Date().toISOString();
      const simulatedAction = {
        id: createId("sim_act"),
        tenantId: payload.tenantId,
        state: "requested" as const,
        actor: {
          userId: payload.userId ?? null,
          agentId: payload.agentId,
          serviceId: "oars-policy-simulator",
          delegationChain: [payload.userId ?? "system", payload.agentId, "oars-policy-simulator"]
        },
        context: {
          ...payload.context,
          requestedAt
        },
        resource: payload.resource,
        input: payload.input,
        approvalId: null,
        policyDecision: null,
        policySetId: null,
        policyVersion: null,
        policyRuleIds: [],
        policyRationale: null,
        lastError: null,
        createdAt: requestedAt,
        updatedAt: requestedAt,
        receiptIds: []
      };
      const risk = context.riskService.evaluate(payload.resource);
      const evaluation = await context.policyService.evaluate(
        simulatedAction,
        risk,
        payload.policyId ? { policyId: payload.policyId } : undefined
      );

      return reply.send({
        simulationId: createId("sim"),
        tenantId: payload.tenantId,
        policySetId: evaluation.policySetId,
        policyVersion: evaluation.policyVersion,
        decision: evaluation.decision,
        rationale: evaluation.rationale,
        ruleIds: evaluation.ruleIds,
        risk
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/policies/:policyId/publish", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:write");
      requireRole(context, claims, "admin");
      const params = request.params as { policyId?: string };
      if (!params.policyId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing policyId." } });
      }

      const existing = await context.store.getPolicy(params.policyId);
      if (!existing) {
        return reply.status(404).send({ error: { code: "not_found", message: "Policy not found." } });
      }
      requireTenantAccess(context, claims, existing.tenantId);
      const policy = await context.policyService.publishPolicy(params.policyId);
      await context.securityEventService.publish({
        tenantId: existing.tenantId,
        source: "admin",
        eventType: "policy.published",
        payload: {
          policyId: policy.id,
          version: policy.version,
          actor: claims.subject
        }
      });
      return reply.send(policy);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/policies/:policyId/rollback", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:write");
      requireRole(context, claims, "admin");
      const params = request.params as { policyId?: string };
      if (!params.policyId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing policyId." } });
      }

      const target = await context.policyService.getPolicy(params.policyId);
      if (!target) {
        return reply.status(404).send({ error: { code: "not_found", message: "Policy not found." } });
      }
      requireTenantAccess(context, claims, target.tenantId);
      const result = await context.policyService.rollbackPolicy(params.policyId);
      await context.securityEventService.publish({
        tenantId: target.tenantId,
        source: "admin",
        eventType: "policy.rolled_back",
        payload: {
          policyId: result.policy.id,
          previousPublishedPolicyId: result.previousPublishedPolicyId,
          actor: claims.subject
        }
      });
      return reply.send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/policies/:policyId", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:read");
      const params = request.params as { policyId?: string };
      if (!params.policyId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing policyId." } });
      }
      const policy = await context.policyService.getPolicy(params.policyId);
      if (!policy) {
        return reply.status(404).send({ error: { code: "not_found", message: "Policy not found." } });
      }
      requireTenantAccess(context, claims, policy.tenantId);
      return reply.send(policy);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/policies", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "policies:read");
      const query = request.query as { tenantId?: string };
      if (!query.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId query param." } });
      }

      requireTenantAccess(context, claims, query.tenantId);
      const policies = await context.policyService.listPolicies(query.tenantId);
      return reply.send({ items: policies });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

