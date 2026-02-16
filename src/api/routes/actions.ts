import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import { actionSubmissionSchema, approvalDecisionSchema, scanApprovalEscalationsSchema } from "../../core/types/schemas.js";
import { canonicalStringify } from "../../lib/canonical-json.js";
import { sha256Hex } from "../../lib/hash.js";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import {
  HttpError,
  authenticate,
  handleError,
  idempotencyKeyFromHeaders,
  requestIdFromHeaders,
  requireRole,
  requireTenantAccess
} from "../http.js";

export function registerActionRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.post("/v1/actions", async (request, reply) => {
    try {
      const payload = actionSubmissionSchema.parse(request.body);
      const claims = authenticate(context, request.headers as Record<string, unknown>, "actions:write");
      requireTenantAccess(context, claims, payload.tenantId);
      const requestedUserId = payload.userContext?.userId;
      if (requestedUserId && requestedUserId !== claims.subject && !context.authService.canImpersonate(claims)) {
        throw new HttpError(403, "forbidden", "Token cannot submit actions for another user.");
      }

      const effectivePayload = {
        ...payload,
        userContext: {
          ...payload.userContext,
          userId: requestedUserId ?? claims.subject
        }
      };
      const endpoint = "POST /v1/actions";
      const idempotencyKey = idempotencyKeyFromHeaders(request.headers as Record<string, unknown>);
      if (idempotencyKey) {
        const requestHash = sha256Hex(
          canonicalStringify({
            endpoint,
            tenantId: effectivePayload.tenantId,
            subject: claims.subject,
            agentId: effectivePayload.agentId,
            userContext: effectivePayload.userContext ?? null,
            context: effectivePayload.context
              ? {
                  environment: effectivePayload.context.environment ?? null,
                  dataTypes: effectivePayload.context.dataTypes ?? null
                }
              : null,
            resource: effectivePayload.resource,
            input: effectivePayload.input
          })
        );
        const existing = await context.store.getIdempotencyRecord(
          effectivePayload.tenantId,
          claims.subject,
          endpoint,
          idempotencyKey
        );
        if (existing) {
          if (existing.requestHash !== requestHash) {
            throw new HttpError(
              409,
              "idempotency_conflict",
              "Idempotency-Key was already used with a different request payload."
            );
          }
          return reply.status(existing.responseStatus).send(existing.responseBody);
        }

        const requestId = requestIdFromHeaders(request.headers as Record<string, unknown>);
        const result = await context.actionService.submitAction(effectivePayload, requestId);
        await context.store.saveIdempotencyRecord({
          id: createId("idem"),
          key: idempotencyKey,
          tenantId: effectivePayload.tenantId,
          subject: claims.subject,
          endpoint,
          requestHash,
          responseStatus: 202,
          responseBody: result as unknown as Record<string, unknown>,
          createdAt: nowIso()
        });
        return reply.status(202).send(result);
      }
      const requestId = requestIdFromHeaders(request.headers as Record<string, unknown>);
      const result = await context.actionService.submitAction(effectivePayload, requestId);
      return reply.status(202).send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/actions/:actionId", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "actions:read");
      const params = request.params as { actionId?: string };
      if (!params.actionId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing actionId." } });
      }

      const action = await context.actionService.getAction(params.actionId);
      if (!action) {
        return reply.status(404).send({ error: { code: "not_found", message: "Action not found." } });
      }

      requireTenantAccess(context, claims, action.tenantId);
      const receipts = await context.store.listReceiptsByAction(params.actionId);
      return reply.send({
        action,
        receipts
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/approvals/:approvalId/decision", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "approvals:write");
      const params = request.params as { approvalId?: string };
      if (!params.approvalId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing approvalId." } });
      }

      const approval = await context.approvalService.getApproval(params.approvalId);
      if (!approval) {
        return reply.status(404).send({ error: { code: "not_found", message: "Approval not found." } });
      }
      requireTenantAccess(context, claims, approval.tenantId);

      const payload = approvalDecisionSchema.parse(request.body);
      const requestId = requestIdFromHeaders(request.headers as Record<string, unknown>);
      const result = await context.actionService.handleApprovalDecision(
        params.approvalId,
        payload.decision,
        payload.approverId,
        payload.reason,
        requestId,
        payload.stepUpCode
      );
      if (result.state === "approval_required") {
        return reply.status(202).send(result);
      }
      return reply.send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/approvals/escalations/scan", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "approvals:write");
      requireRole(context, claims, "admin");
      const payload = scanApprovalEscalationsSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const escalations = await context.approvalService.scanForEscalations(payload.tenantId, payload.nowIso);

      for (const escalation of escalations) {
        await context.securityEventService.publish({
          tenantId: escalation.tenantId,
          source: "admin",
          eventType: "approval.escalated",
          payload: {
            approvalId: escalation.approvalId,
            actionId: escalation.actionId,
            stageId: escalation.stageId,
            stageName: escalation.stageName,
            escalateTo: escalation.escalateTo,
            overdueSeconds: escalation.overdueSeconds,
            actor: claims.subject
          }
        });
      }

      return reply.send({
        scannedAt: new Date().toISOString(),
        tenantId: payload.tenantId,
        escalatedCount: escalations.length,
        items: escalations
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

