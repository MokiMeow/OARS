import type { FastifyInstance } from "fastify";
import type { PlatformContext } from "../../core/services/platform-context.js";
import {
  applyLedgerRetentionSchema,
  backupsQuerySchema,
  createBackupSchema,
  createServiceAccountSchema,
  ledgerEntriesQuerySchema,
  ledgerRetentionQuerySchema,
  opsDashboardQuerySchema,
  paginationQuerySchema,
  replayDeadLetterSchema,
  restoreBackupSchema,
  runBackupDrillSchema,
  scimDeprovisionSchema,
  siemDeadLettersQuerySchema,
  startSiemRetrySchema,
  upsertAlertRoutingRuleSchema,
  upsertApprovalWorkflowSchema,
  upsertLedgerRetentionSchema,
  upsertScimGroupSchema,
  upsertScimRoleMappingSchema,
  upsertScimUserSchema,
  upsertTenantMemberSchema,
  upsertVaultSecretSchema,
  vaultSecretsQuerySchema
} from "../../core/types/schemas.js";
import { authenticate, handleError, requestIdFromHeaders, requireRole, requireTenantAccess } from "../http.js";

export function registerAdminRoutes(app: FastifyInstance, context: PlatformContext): void {
  app.get("/v1/alerts", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "alerts:read");
      const query = request.query as { tenantId?: string; limit?: string };
      if (!query.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId query param." } });
      }
      requireTenantAccess(context, claims, query.tenantId);
      const limit = query.limit ? Number.parseInt(query.limit, 10) : 100;
      return reply.send({
        items: await context.alertService.listAlerts(query.tenantId, Number.isNaN(limit) ? 100 : limit)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/connectors", async (request, reply) => {
    try {
      authenticate(context, request.headers as Record<string, unknown>, "connectors:read");
      return reply.send({
        items: context.connectorRegistry.listToolIds()
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/security-events", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "events:read");
      const query = request.query as { tenantId?: string; limit?: string };
      if (!query.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId query param." } });
      }
      requireTenantAccess(context, claims, query.tenantId);
      const limit = query.limit ? Number.parseInt(query.limit, 10) : 200;
      return reply.send({
        items: await context.securityEventService.listByTenant(query.tenantId, Number.isNaN(limit) ? 200 : limit)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/security/mtls/status", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "auth_providers:read");
      requireRole(context, claims, "admin");
      return reply.send(context.serviceIdentityService.status());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ops/dashboard", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "alerts:read");
      const query = opsDashboardQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(await context.operationsService.dashboard(query.tenantId));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ops/alert-routing", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "alerts:read");
      const query = opsDashboardQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send({
        tenantId: query.tenantId,
        items: await context.operationsService.listAlertRoutingRules(query.tenantId)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/ops/alert-routing", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "alerts:read");
      requireRole(context, claims, "admin");
      const payload = upsertAlertRoutingRuleSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const updated = await context.operationsService.upsertAlertRoutingRule(
        payload.tenantId,
        payload.severity,
        payload.channels,
        payload.escalationMinutes,
        claims.subject
      );
      await context.securityEventService.publish({
        tenantId: payload.tenantId,
        source: "admin",
        eventType: "ops.alert_routing.updated",
        payload: {
          severity: payload.severity,
          channels: payload.channels,
          escalationMinutes: payload.escalationMinutes,
          actor: claims.subject
        }
      });
      return reply.send(updated);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ledger/status", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      requireRole(context, claims, "admin");
      return reply.send(context.immutableLedgerService.status());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ledger/entries", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      const query = ledgerEntriesQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(
        context.immutableLedgerService.listEntriesByTenant(query.tenantId, query.limit, query.beforeSequence)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ledger/verify", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      requireRole(context, claims, "admin");
      return reply.send(context.immutableLedgerService.verifyIntegrity());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/ledger/retention", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      const query = ledgerRetentionQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(context.ledgerGovernanceService.getPolicy(query.tenantId));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/ledger/retention", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:write");
      requireRole(context, claims, "admin");
      const payload = upsertLedgerRetentionSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const policy = await context.ledgerGovernanceService.upsertPolicy(
        payload.tenantId,
        payload.retentionDays,
        payload.legalHold,
        payload.reason ?? null,
        claims.subject
      );
      return reply.send(policy);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/ledger/retention/apply", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:write");
      requireRole(context, claims, "admin");
      const payload = applyLedgerRetentionSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      const result = await context.ledgerGovernanceService.applyPolicy(payload.tenantId, claims.subject, payload.nowIso);
      return reply.send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/backups/status", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      requireRole(context, claims, "admin");
      return reply.send(context.backupRecoveryService.backupStorageStatus());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/backups", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      requireRole(context, claims, "admin");
      const query = backupsQuerySchema.parse(request.query ?? {});
      return reply.send({
        items: context.backupRecoveryService.listBackups(query.limit)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/backups", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:write");
      requireRole(context, claims, "admin");
      const payload = createBackupSchema.parse(request.body ?? {});
      const backup = context.backupRecoveryService.createBackup(claims.subject, payload.reason);
      await context.securityEventService.publish({
        tenantId: "platform",
        source: "admin",
        eventType: "backup.created",
        payload: {
          backupId: backup.backupId,
          createdBy: claims.subject,
          missingRequiredFileIds: backup.missingRequiredFileIds
        }
      });
      return reply.status(201).send(backup);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/backups/restore", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:write");
      requireRole(context, claims, "admin");
      const payload = restoreBackupSchema.parse(request.body);
      const restored = context.backupRecoveryService.restoreBackup(payload.backupId, claims.subject, payload.reason, {
        createPreRestoreSnapshot: payload.createPreRestoreSnapshot,
        pruneMissingFiles: payload.pruneMissingFiles
      });
      return reply.send({
        ...restored,
        restartRequired: true
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/backups/drills", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:read");
      requireRole(context, claims, "admin");
      const query = backupsQuerySchema.parse(request.query ?? {});
      return reply.send({
        items: context.backupRecoveryService.listDrillReports(query.limit)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/backups/drills", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "ledger:write");
      requireRole(context, claims, "admin");
      const payload = runBackupDrillSchema.parse(request.body ?? {});
      const report = context.backupRecoveryService.runBackupRestoreDrill(claims.subject, payload.reason);
      await context.securityEventService.publish({
        tenantId: "platform",
        source: "admin",
        eventType: "backup.drill.completed",
        payload: {
          drillId: report.drillId,
          backupId: report.backupId,
          status: report.status,
          failedChecks: report.checks.filter((check) => check.status === "failed").map((check) => check.name),
          triggeredBy: claims.subject
        }
      });
      return reply.send(report);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/members", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const items = await context.tenantAdminService.listMembers(params.tenantId);
      return reply.send({ items });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/keys", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      return reply.send({
        tenantId: params.tenantId,
        items: context.signingKeyService.listTenantKeys(params.tenantId)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/keys/rotate", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const rotated = context.signingKeyService.rotateTenantKey(params.tenantId);
      await context.securityEventService.publish({
        tenantId: params.tenantId,
        source: "admin",
        eventType: "keys.rotated",
        payload: {
          newKeyId: rotated.newKeyId,
          previousActiveKeyId: rotated.previousActiveKeyId,
          actor: claims.subject
        }
      });
      return reply.send({
        tenantId: params.tenantId,
        ...rotated
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/vault/secrets", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const query = vaultSecretsQuerySchema.parse(request.query ?? {});
      return reply.send({
        tenantId: params.tenantId,
        items: context.vaultSecretService.listMetadata(params.tenantId, query.connectorId)
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/vault/secrets", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertVaultSecretSchema.parse(request.body);
      const saved = context.vaultSecretService.upsertSecret(
        params.tenantId,
        payload.connectorId,
        payload.key,
        payload.value,
        claims.subject
      );
      await context.securityEventService.publish({
        tenantId: params.tenantId,
        source: "admin",
        eventType: "vault.secret.upserted",
        payload: {
          secretId: saved.id,
          connectorId: payload.connectorId,
          key: payload.key,
          actor: claims.subject
        }
      });
      return reply.send({
        id: saved.id,
        tenantId: saved.tenantId,
        connectorId: saved.connectorId,
        key: saved.key,
        updatedAt: saved.updatedAt,
        updatedBy: saved.updatedBy
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/members", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertTenantMemberSchema.parse(request.body);
      const member = await context.tenantAdminService.upsertMember(
        params.tenantId,
        payload.subject,
        payload.role,
        claims.subject
      );
      return reply.status(201).send(member);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.delete("/v1/admin/tenants/:tenantId/members/:subject", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string; subject?: string };
      if (!params.tenantId || !params.subject) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId or subject." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const deleted = await context.tenantAdminService.removeMember(params.tenantId, params.subject, claims.subject);
      if (!deleted) {
        return reply.status(404).send({ error: { code: "not_found", message: "Member not found." } });
      }
      return reply.status(204).send();
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/approval-workflow", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      return reply.send(await context.approvalService.getTenantWorkflow(params.tenantId));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/approval-workflow", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "tenant_admin:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertApprovalWorkflowSchema.parse(request.body);
      const workflow = await context.approvalService.upsertTenantWorkflow(params.tenantId, payload.stages, claims.subject);
      await context.securityEventService.publish({
        tenantId: params.tenantId,
        source: "admin",
        eventType: "approval.workflow.updated",
        payload: {
          workflowId: workflow.id,
          stageCount: workflow.stages.length,
          actor: claims.subject
        }
      });
      return reply.send(workflow);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/service-accounts", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "service_accounts:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const items = (await context.serviceAccountService.list(params.tenantId)).map((account) => ({
        id: account.id,
        tenantId: account.tenantId,
        name: account.name,
        role: account.role,
        scopes: account.scopes,
        status: account.status,
        createdAt: account.createdAt,
        updatedAt: account.updatedAt,
        createdBy: account.createdBy
      }));
      return reply.send({ items });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/service-accounts", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "service_accounts:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = createServiceAccountSchema.parse(request.body);
      const created = await context.serviceAccountService.create({
        tenantId: params.tenantId,
        name: payload.name,
        role: payload.role,
        scopes: payload.scopes,
        createdBy: claims.subject
      });
      return reply.status(201).send({
        id: created.account.id,
        tenantId: created.account.tenantId,
        name: created.account.name,
        role: created.account.role,
        scopes: created.account.scopes,
        status: created.account.status,
        createdAt: created.account.createdAt,
        updatedAt: created.account.updatedAt,
        createdBy: created.account.createdBy,
        clientSecret: created.clientSecret
      });
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/scim/users", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      const query = paginationQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, params.tenantId);
      return reply.send(await context.scimService.listUsers(params.tenantId, query.page, query.pageSize));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/scim/users", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertScimUserSchema.parse(request.body);
      const user = await context.scimService.upsertUser(params.tenantId, payload, claims.subject);
      return reply.status(201).send(user);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/scim/deprovision", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = scimDeprovisionSchema.parse(request.body);
      const user = await context.scimService.deprovisionUser(params.tenantId, payload.externalId, claims.subject);
      return reply.send(user);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/scim/groups", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      const query = paginationQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, params.tenantId);
      return reply.send(await context.scimService.listGroups(params.tenantId, query.page, query.pageSize));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/scim/groups", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertScimGroupSchema.parse(request.body);
      const group = await context.scimService.upsertGroup(params.tenantId, payload, claims.subject);
      return reply.status(201).send(group);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/tenants/:tenantId/scim/role-mappings", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:read");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      const query = paginationQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, params.tenantId);
      return reply.send(await context.scimService.listRoleMappings(params.tenantId, query.page, query.pageSize));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/scim/role-mappings", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:write");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const payload = upsertScimRoleMappingSchema.parse(request.body);
      const mapping = await context.scimService.upsertRoleMapping(
        params.tenantId,
        payload.groupDisplayName,
        payload.role,
        claims.subject
      );
      return reply.status(201).send(mapping);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/tenants/:tenantId/scim/sync", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "scim:sync");
      requireRole(context, claims, "admin");
      const params = request.params as { tenantId?: string };
      if (!params.tenantId) {
        return reply.status(400).send({ error: { code: "bad_request", message: "Missing tenantId." } });
      }
      requireTenantAccess(context, claims, params.tenantId);
      const result = await context.scimService.syncTenantMembers(params.tenantId, claims.subject);
      return reply.send(result);
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/siem/dead-letters", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:read");
      const query = siemDeadLettersQuerySchema.parse(request.query ?? {});
      requireTenantAccess(context, claims, query.tenantId);
      return reply.send(
        await context.securityEventService.listSiemDeadLetters(query.tenantId, query.status, query.page, query.pageSize)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/siem/dead-letters/replay", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:write");
      requireRole(context, claims, "admin");
      const payload = replayDeadLetterSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      return reply.send(
        await context.securityEventService.replaySiemDeadLetterForTenant(payload.tenantId, payload.deadLetterId)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/siem/dead-letters/resolve", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:write");
      requireRole(context, claims, "admin");
      const payload = replayDeadLetterSchema.parse(request.body);
      requireTenantAccess(context, claims, payload.tenantId);
      return reply.send(
        await context.securityEventService.resolveSiemDeadLetterForTenant(payload.tenantId, payload.deadLetterId)
      );
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.get("/v1/admin/siem/status", async (request, reply) => {
    try {
      authenticate(context, request.headers as Record<string, unknown>, "siem:read");
      return reply.send(context.securityEventService.siemStatus());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/siem/flush", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:write");
      requireRole(context, claims, "admin");
      return reply.send(await context.securityEventService.flushSiemQueue());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/siem/retry/start", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:write");
      requireRole(context, claims, "admin");
      const payload = startSiemRetrySchema.parse(request.body ?? {});
      return reply.send(context.securityEventService.startSiemRetryScheduler(payload.intervalSeconds, payload.maxAttempts));
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });

  app.post("/v1/admin/siem/retry/stop", async (request, reply) => {
    try {
      const claims = authenticate(context, request.headers as Record<string, unknown>, "siem:write");
      requireRole(context, claims, "admin");
      return reply.send(context.securityEventService.stopSiemRetryScheduler());
    } catch (error) {
      return handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>));
    }
  });
}
