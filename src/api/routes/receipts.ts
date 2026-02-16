import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import type { ControlMappingRecord } from "../../core/types/domain.js";
import { receiptsQuerySchema, verifyReceiptSchema } from "../../core/types/schemas.js";
import { authenticate, handleError, requestIdFromHeaders, requireTenantAccess } from "../http.js";

export function registerReceiptRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.get("/v1/receipts", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "receipts:read");
      const query = receiptsQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);

      let controlMapping: ControlMappingRecord | null = null;
      let controlMappings: ControlMappingRecord[] = [];
      if (query.framework && query.controlId) {
        controlMappings = await context.store.listControlMappingsByTenant(query.tenantId, query.framework);
        controlMapping = controlMappings.find((entry) => entry.controlId === query.controlId) ?? null;
        if (!controlMapping) {
          return reply.status(404).send({ error: { code: "not_found", message: "Control mapping not found." } });
        }
      }

      const controlFilters = controlMapping?.receiptFilters ?? null;
      const candidates = await context.store.listReceiptsByTenant(query.tenantId, 500);
      const items = candidates
        .filter((receipt) => {
          if (query.toolId && receipt.resource.toolId !== query.toolId) {
            return false;
          }
          if (query.operation && receipt.resource.operation !== query.operation) {
            return false;
          }
          if (query.actorUserId && receipt.actor.userId !== query.actorUserId) {
            return false;
          }
          if (query.actorAgentId && receipt.actor.agentId !== query.actorAgentId) {
            return false;
          }
          if (query.policyDecision && receipt.policy.decision !== query.policyDecision) {
            return false;
          }
          if (query.policyVersion && receipt.policy.policyVersion !== query.policyVersion) {
            return false;
          }
          if (query.policyRuleId && !receipt.policy.ruleIds.includes(query.policyRuleId)) {
            return false;
          }

          if (controlFilters) {
            if (controlFilters.toolIds && !controlFilters.toolIds.includes(receipt.resource.toolId)) {
              return false;
            }
            if (controlFilters.operations && !controlFilters.operations.includes(receipt.resource.operation)) {
              return false;
            }
            if (controlFilters.policyDecisions && !controlFilters.policyDecisions.includes(receipt.policy.decision)) {
              return false;
            }
            if (controlFilters.actorUserIds && !controlFilters.actorUserIds.includes(receipt.actor.userId ?? "")) {
              return false;
            }
            if (controlFilters.actorAgentIds && !controlFilters.actorAgentIds.includes(receipt.actor.agentId)) {
              return false;
            }
            if (controlFilters.policyVersions && !controlFilters.policyVersions.includes(receipt.policy.policyVersion)) {
              return false;
            }
            if (
              controlFilters.policyRuleIds &&
              !controlFilters.policyRuleIds.some((ruleId) => receipt.policy.ruleIds.includes(ruleId))
            ) {
              return false;
            }
          }
          return true;
        })
        .slice(0, query.limit);
      return reply.send({
        tenantId: query.tenantId,
        ...(controlMapping
          ? {
              framework: controlMapping.framework,
              controlId: controlMapping.controlId
            }
          : {}),
        items
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/receipts/:receiptId", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "receipts:read");
      const params = request.params as { receiptId?: string };
      if (!params.receiptId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing receiptId." } });
      }

      const receipt = await context.receiptService.getReceipt(params.receiptId);
      if (!receipt) {
        return reply.status(404).send({ error: { code: "not_found", message: "Receipt not found." } });
      }

      requireTenantAccess(context, claims, receipt.tenantId);
      return reply.send(receipt);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/receipts/verify", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "receipts:verify");
      const payload = verifyReceiptSchema.parse(request.body);
      if (payload.receiptId) {
        const receipt = await context.receiptService.getReceipt(payload.receiptId);
        if (!receipt) {
          return reply.status(404).send({ error: { code: "not_found", message: "Receipt not found." } });
        }
        requireTenantAccess(context, claims, receipt.tenantId);
        const verification = await context.receiptService.verifyReceiptById(payload.receiptId);
        return reply.send(verification);
      }

      const receipt = payload.receipt as unknown;
      if (!receipt || typeof receipt !== "object") {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing receipt payload." } });
      }
      const receiptCandidate = receipt as { tenantId?: string };
      if (!receiptCandidate.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Receipt tenantId is required." } });
      }
      requireTenantAccess(context, claims, receiptCandidate.tenantId);

      const chain = payload.chain as unknown;
      const chainItems =
        Array.isArray(chain) && chain.length > 0
          ? (chain as unknown[]).filter((entry) => entry && typeof entry === "object")
          : undefined;

      const verification = context.receiptService.verifyReceiptPayload(receipt as any, {
        chain: chainItems as any,
        publicKeyPem: payload.publicKeyPem,
        publicKeys: payload.publicKeys
      });
      return reply.send(verification);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

