import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import type { SignedEvidenceBundle } from "../../core/services/evidence-bundle-service.js";
import {
  controlMappingsQuerySchema,
  evidenceExportSchema,
  evidenceGraphNodesQuerySchema,
  evidenceGraphStatusQuerySchema,
  scanCoverageSchema,
  upsertControlMappingSchema,
  verifyEvidenceBundleSchema
} from "../../core/types/schemas.js";
import { authenticate, handleError, requestIdFromHeaders, requireRole, requireTenantAccess } from "../http.js";

export function registerEvidenceRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.post("/v1/evidence/exports", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "evidence:export");
      const payload = evidenceExportSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const tenantActions = await context.store.listActionsByTenant(payload.tenantId);
      const receiptLists = await Promise.all(tenantActions.map((action) => context.store.listReceiptsByAction(action.id)));
      const receipts = receiptLists.flat();

      const scopedReceipts = receipts.filter(
        (receipt) => receipt.timestamp >= payload.dateFrom && receipt.timestamp <= payload.dateTo
      );
      const bundle = await context.evidenceBundleService.createBundle({
        tenantId: payload.tenantId,
        framework: payload.framework,
        actionCount: tenantActions.length,
        receipts: scopedReceipts
      });
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "evidence.bundle.generated",
        payload: {
          bundleId: bundle.bundleId,
          framework: bundle.framework,
          artifactCount: bundle.artifacts.length,
          actor: claims.subject
        }
      });
      return reply.send(bundle);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/evidence/exports/verify", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "evidence:read");
      const payload = verifyEvidenceBundleSchema.parse(request.body);
      const bundle = payload.bundle as unknown as SignedEvidenceBundle;
      requireTenantAccess(context, claims, bundle.tenantId);
      return reply.send(context.evidenceBundleService.verifyBundle(bundle));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/evidence/graph/status", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "evidence:read");
      const query = evidenceGraphStatusQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(await context.evidenceGraphService.snapshot(query.tenantId));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/evidence/graph/nodes", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "evidence:read");
      const query = evidenceGraphNodesQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(
        await context.evidenceGraphService.listNodes(query.tenantId, query.nodeType, query.page, query.pageSize)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/compliance/control-mappings", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "compliance:read");
      const query = controlMappingsQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send({
        items: await context.controlMappingService.listMappings(query.tenantId, query.framework)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/compliance/control-mappings", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "compliance:write");
      requireRole(context, claims, "admin");
      const payload = upsertControlMappingSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const mapping = await context.controlMappingService.upsertMapping({
        tenantId: payload.tenantId,
        framework: payload.framework,
        controlId: payload.controlId,
        controlDescription: payload.controlDescription,
        requiredNodeTypes: payload.requiredNodeTypes,
        receiptFilters: payload.receiptFilters,
        actor: claims.subject
      });
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "compliance.control_mapping.upserted",
        payload: {
          framework: payload.framework,
          controlId: payload.controlId,
          actor: claims.subject
        }
      });
      return reply.send(mapping);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/compliance/coverage/scan", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "compliance:read");
      const payload = scanCoverageSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      return reply.send(await context.controlMappingService.scanCoverage(payload.tenantId, payload.framework));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}

