import { z } from "zod";

const resourceSchema = z.object({
  toolId: z.string().min(1),
  operation: z.string().min(1),
  target: z.string().min(1)
});

const actionContextSchema = z.object({
  environment: z.string().min(1).optional(),
  dataTypes: z.array(z.string().min(1)).min(1).optional(),
  // Accepted for compatibility and simulations; the platform may override this value on real submissions.
  requestedAt: z.string().datetime().optional()
});

function normalizeActionSubmissionInput(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return input;
  }
  const raw = input as Record<string, unknown>;
  const tenantId = (raw.tenantId ?? raw.tenant_id) as unknown;
  const agentId = (raw.agentId ?? raw.agent_id) as unknown;
  const userContextRaw = (raw.userContext ?? raw.user_context) as unknown;
  const contextRaw = (raw.context ?? raw.actionContext ?? raw.action_context) as unknown;
  const resourceRaw = raw.resource as unknown;
  const inputRaw = raw.input as unknown;

  const userContext =
    userContextRaw && typeof userContextRaw === "object" && !Array.isArray(userContextRaw)
      ? {
          userId: ((userContextRaw as any).userId ?? (userContextRaw as any).user_id) as unknown,
          sessionId: ((userContextRaw as any).sessionId ?? (userContextRaw as any).session_id) as unknown
        }
      : undefined;

  const context =
    contextRaw && typeof contextRaw === "object" && !Array.isArray(contextRaw)
      ? {
          environment: ((contextRaw as any).environment ?? (contextRaw as any).env) as unknown,
          dataTypes: ((contextRaw as any).dataTypes ?? (contextRaw as any).data_types) as unknown,
          requestedAt: ((contextRaw as any).requestedAt ?? (contextRaw as any).requested_at) as unknown
        }
      : undefined;

  const resource =
    resourceRaw && typeof resourceRaw === "object" && !Array.isArray(resourceRaw)
      ? {
          toolId: ((resourceRaw as any).toolId ?? (resourceRaw as any).tool_id) as unknown,
          operation: (resourceRaw as any).operation as unknown,
          target: (resourceRaw as any).target as unknown
        }
      : resourceRaw;

  return {
    ...raw,
    tenantId,
    agentId,
    ...(userContext ? { userContext } : {}),
    ...(context ? { context } : {}),
    resource,
    input: inputRaw
  };
}

export const actionSubmissionSchema = z.preprocess(
  (value) => normalizeActionSubmissionInput(value),
  z.object({
    tenantId: z.string().min(1),
    agentId: z.string().min(1),
    userContext: z
      .object({
        userId: z.string().min(1).optional(),
        sessionId: z.string().min(1).optional()
      })
      .optional(),
    context: actionContextSchema.optional(),
    resource: resourceSchema,
    input: z.record(z.string(), z.unknown())
  })
);

export const approvalDecisionSchema = z.object({
  decision: z.enum(["approve", "reject"]),
  reason: z.string().min(3),
  approverId: z.string().min(1),
  stepUpCode: z.string().min(1).optional()
});

const approvalStageSchema = z.object({
  name: z.string().min(1),
  mode: z.enum(["serial", "parallel"]),
  requiredApprovals: z.number().int().min(1),
  approverIds: z.array(z.string().min(1)).default([]),
  slaSeconds: z.number().int().min(1).max(86400).optional(),
  escalateTo: z.array(z.string().min(1)).default([])
});

export const upsertApprovalWorkflowSchema = z.object({
  stages: z.array(approvalStageSchema).min(1)
});

export const scanApprovalEscalationsSchema = z.object({
  tenantId: z.string().min(1),
  nowIso: z.string().datetime().optional()
});

export const policyRuleSchema = z.object({
  id: z.string().min(1),
  description: z.string().min(1),
  priority: z.number().int().min(0),
  match: z
    .object({
      toolIds: z.array(z.string().min(1)).optional(),
      operations: z.array(z.string().min(1)).optional(),
      targetContains: z.string().min(1).optional(),
      riskTiers: z.array(z.enum(["low", "medium", "high", "critical"])).optional(),
      environments: z.array(z.string().min(1)).min(1).optional(),
      requiredDataTypes: z.array(z.string().min(1)).min(1).optional(),
      timeWindowUtc: z
        .object({
          startHour: z.number().int().min(0).max(23),
          endHour: z.number().int().min(0).max(24)
        })
        .refine((value) => value.startHour !== value.endHour, {
          message: "timeWindowUtc.startHour and timeWindowUtc.endHour must differ."
        })
        .optional()
    })
    .default({}),
  decision: z.enum(["allow", "deny", "approve", "quarantine"])
});

export const createPolicySchema = z.object({
  tenantId: z.string().min(1),
  version: z.string().min(1),
  rules: z.array(policyRuleSchema).min(1)
});

export const simulatePolicySchema = z.object({
  tenantId: z.string().min(1),
  agentId: z.string().min(1),
  userId: z.string().min(1).optional(),
  policyId: z.string().min(1).optional(),
  context: actionContextSchema.optional(),
  resource: resourceSchema,
  input: z.record(z.string(), z.unknown()).default({})
});

export const verifyReceiptSchema = z
  .preprocess((input) => {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return input;
    }
    const raw = input as Record<string, unknown>;
    const receiptId = (raw.receiptId ?? raw.receipt_id) as unknown;
    const publicKeyPem = (raw.publicKeyPem ?? raw.public_key_pem) as unknown;
    const publicKeysRaw = (raw.publicKeys ?? raw.public_keys) as unknown;
    const publicKeys =
      Array.isArray(publicKeysRaw)
        ? publicKeysRaw.map((entry) => {
            if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
              return entry;
            }
            const obj = entry as Record<string, unknown>;
            return {
              ...obj,
              keyId: obj.keyId ?? obj.key_id,
              publicKeyPem: obj.publicKeyPem ?? obj.public_key_pem
            };
          })
        : publicKeysRaw;
    return {
      ...raw,
      receiptId,
      publicKeyPem,
      publicKeys
    };
  }, z.unknown())
  .pipe(
    z.object({
      receiptId: z.string().min(1).optional(),
      receipt: z.record(z.string(), z.unknown()).optional(),
      chain: z.array(z.record(z.string(), z.unknown())).optional(),
      publicKeyPem: z.string().min(1).optional(),
      publicKeys: z
        .array(
          z.object({
            keyId: z.string().min(1),
            publicKeyPem: z.string().min(1)
          })
        )
        .optional()
    })
  )
  .refine((value) => Boolean(value.receiptId) || Boolean(value.receipt), {
    message: "Either receiptId or receipt must be provided."
  });

export const evidenceExportSchema = z.object({
  tenantId: z.string().min(1),
  framework: z.enum(["eu_ai_act", "iso_42001", "soc2"]),
  dateFrom: z.string().datetime(),
  dateTo: z.string().datetime()
});

export const upsertTenantMemberSchema = z.object({
  subject: z.string().min(1),
  role: z.enum(["owner", "admin", "operator", "auditor"])
});

export const tokenExchangeSchema = z.object({
  tenantId: z.string().min(1),
  agentId: z.string().min(1),
  subject: z.string().min(1).optional(),
  scopes: z.array(z.string().min(1)).min(1).optional(),
  expiresInSeconds: z.number().int().min(60).max(86400).optional()
});

export const createServiceAccountSchema = z.object({
  name: z.string().min(1),
  role: z.enum(["operator", "auditor", "agent"]),
  scopes: z.array(z.string().min(1)).min(1)
});

export const serviceTokenSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  tenantId: z.string().min(1),
  expiresInSeconds: z.number().int().min(60).max(86400).optional()
});

export const refreshProvidersSchema = z.object({
  issuer: z.string().min(1).optional()
});

export const startRefreshSchedulerSchema = z.object({
  intervalSeconds: z.number().int().min(30).max(86400).optional(),
  discoverOnStart: z.boolean().optional()
});

export const upsertScimUserSchema = z.object({
  externalId: z.string().min(1),
  userName: z.string().min(1),
  displayName: z.string().min(1),
  emails: z.array(z.string().email()).default([]),
  active: z.boolean().default(true)
});

export const upsertScimGroupSchema = z.object({
  externalId: z.string().min(1),
  displayName: z.string().min(1),
  memberExternalUserIds: z.array(z.string().min(1)).default([])
});

export const upsertScimRoleMappingSchema = z.object({
  groupDisplayName: z.string().min(1),
  role: z.enum(["admin", "operator", "auditor"])
});

export const startSiemRetrySchema = z.object({
  intervalSeconds: z.number().int().min(5).max(3600).optional(),
  maxAttempts: z.number().int().min(1).max(20).optional()
});

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(100)
});

export const scimDeprovisionSchema = z.object({
  externalId: z.string().min(1)
});

export const siemDeadLettersQuerySchema = z.object({
  tenantId: z.string().min(1),
  status: z.enum(["all", "open", "replayed", "resolved"]).default("all"),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(100)
});

export const replayDeadLetterSchema = z.object({
  tenantId: z.string().min(1),
  deadLetterId: z.string().min(1)
});

export const ledgerEntriesQuerySchema = z.object({
  tenantId: z.string().min(1),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  beforeSequence: z.coerce.number().int().min(1).optional()
});

export const ledgerRetentionQuerySchema = z.object({
  tenantId: z.string().min(1)
});

export const upsertLedgerRetentionSchema = z.object({
  tenantId: z.string().min(1),
  retentionDays: z.number().int().min(1).max(36500),
  legalHold: z.boolean(),
  reason: z.string().min(3).max(500).nullable().optional()
});

export const applyLedgerRetentionSchema = z.object({
  tenantId: z.string().min(1),
  nowIso: z.string().datetime().optional()
});

export const evidenceGraphStatusQuerySchema = z.object({
  tenantId: z.string().min(1)
});

export const evidenceGraphNodesQuerySchema = z.object({
  tenantId: z.string().min(1),
  nodeType: z
    .enum([
      "all",
      "action",
      "receipt",
      "policy_version",
      "approval_decision",
      "actor",
      "control_mapping",
      "evidence_bundle"
    ])
    .default("all"),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(500).default(100)
});

const frameworkSchema = z.enum(["eu_ai_act", "iso_42001", "soc2"]);
const evidenceNodeTypeSchema = z.enum([
  "action",
  "receipt",
  "policy_version",
  "approval_decision",
  "actor",
  "control_mapping",
  "evidence_bundle"
]);

export const upsertControlMappingSchema = z.object({
  tenantId: z.string().min(1),
  framework: frameworkSchema,
  controlId: z.string().min(1),
  controlDescription: z.string().min(1),
  requiredNodeTypes: z.array(evidenceNodeTypeSchema).min(1),
  receiptFilters: z
    .object({
      toolIds: z.array(z.string().min(1)).min(1).optional(),
      operations: z.array(z.string().min(1)).min(1).optional(),
      policyDecisions: z.array(z.enum(["allow", "deny", "approve", "quarantine"])).min(1).optional(),
      actorUserIds: z.array(z.string().min(1)).min(1).optional(),
      actorAgentIds: z.array(z.string().min(1)).min(1).optional(),
      policyRuleIds: z.array(z.string().min(1)).min(1).optional(),
      policyVersions: z.array(z.string().min(1)).min(1).optional()
    })
    .optional()
});

export const controlMappingsQuerySchema = z.object({
  tenantId: z.string().min(1),
  framework: frameworkSchema.optional()
});

export const scanCoverageSchema = z.object({
  tenantId: z.string().min(1),
  framework: frameworkSchema
});

export const verifyEvidenceBundleSchema = z.object({
  bundle: z.record(z.string(), z.unknown())
});

export const vaultSecretsQuerySchema = z.object({
  connectorId: z.string().min(1).optional()
});

export const upsertVaultSecretSchema = z.object({
  connectorId: z.string().min(1),
  key: z.string().min(1),
  value: z.string().min(1)
});

export const receiptsQuerySchema = z.object({
  tenantId: z.string().min(1),
  toolId: z.string().min(1).optional(),
  operation: z.string().min(1).optional(),
  actorUserId: z.string().min(1).optional(),
  actorAgentId: z.string().min(1).optional(),
  policyDecision: z.enum(["allow", "deny", "approve", "quarantine"]).optional(),
  policyVersion: z.string().min(1).optional(),
  policyRuleId: z.string().min(1).optional(),
  framework: frameworkSchema.optional(),
  controlId: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100)
})
  .refine((value) => !(value.framework && !value.controlId) && !(value.controlId && !value.framework), {
    message: "framework and controlId must be provided together."
  });

export const createTenantSchema = z.object({
  tenantId: z.string().min(1),
  displayName: z.string().min(1),
  ownerSubject: z.string().min(1).optional()
});

export const backupsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(25)
});

export const createBackupSchema = z.object({
  reason: z.string().min(3).max(500).optional()
});

export const restoreBackupSchema = z.object({
  backupId: z.string().min(1),
  reason: z.string().min(3).max(500).optional(),
  createPreRestoreSnapshot: z.boolean().optional(),
  pruneMissingFiles: z.boolean().optional()
});

export const runBackupDrillSchema = z.object({
  reason: z.string().min(3).max(500).optional()
});

export const opsDashboardQuerySchema = z.object({
  tenantId: z.string().min(1)
});

export const upsertAlertRoutingRuleSchema = z.object({
  tenantId: z.string().min(1),
  severity: z.enum(["low", "medium", "high", "critical"]),
  channels: z.array(z.string().min(1)).min(1),
  escalationMinutes: z.number().int().min(1).max(1440)
});
