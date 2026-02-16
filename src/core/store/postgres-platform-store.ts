import { createRequire } from "node:module";
import type { Pool as PgPool } from "pg";
import type { PlatformStore } from "./platform-store.js";
import { DataProtectionService } from "../services/data-protection-service.js";
import type {
  AlertRecord,
  AlertRoutingRuleRecord,
  ActionReceipt,
  ActionRecord,
  ApprovalRecord,
  ApprovalWorkflowRecord,
  ControlMappingRecord,
  EvidenceGraphEdgeRecord,
  EvidenceGraphNodeRecord,
  EvidenceNodeType,
  IdempotencyRecord,
  LedgerRetentionPolicyRecord,
  PolicyDocument,
  ScimGroupRecord,
  ScimRoleMappingRecord,
  ScimUserRecord,
  SecurityEventRecord,
  ServiceAccountRecord,
  SiemDeadLetterRecord,
  TenantMemberRecord,
  TenantRecord
} from "../types/domain.js";

const require = createRequire(import.meta.url);
const { Pool } = require("pg") as { Pool: new (opts: { connectionString: string }) => PgPool };

type PgJsonRow<T> = { data: T };

type Migration = {
  id: string;
  statements: string[];
};

function safeDate(iso: string | undefined, fallback: Date): Date {
  if (!iso) return fallback;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? fallback : new Date(ms);
}

function clampPage(value: number): number {
  if (!Number.isFinite(value) || value < 1) return 1;
  return Math.floor(value);
}

function clampPageSize(value: number): number {
  if (!Number.isFinite(value) || value < 1) return 25;
  return Math.min(200, Math.floor(value));
}

function normalizeApprovalRecord(input: ApprovalRecord): ApprovalRecord {
  const fallbackStageId = "apr_stage_1";
  const stages =
    input.stages && input.stages.length > 0
      ? input.stages.map((stage) => ({
          ...stage,
          approverIds: stage.approverIds ?? [],
          slaSeconds: stage.slaSeconds ?? null,
          escalateTo: stage.escalateTo ?? []
        }))
      : [
          {
            id: fallbackStageId,
            name: "Default Approval",
            mode: "serial" as const,
            requiredApprovals: 1,
            approverIds: [],
            slaSeconds: null,
            escalateTo: []
          }
        ];

  const currentStageIndex =
    typeof input.currentStageIndex === "number"
      ? Math.min(Math.max(input.currentStageIndex, 0), Math.max(0, stages.length - 1))
      : 0;

  const decisions = input.decisions.map((decision) => ({
    ...decision,
    stageId: decision.stageId ?? stages[currentStageIndex]?.id ?? fallbackStageId
  }));

  return {
    ...input,
    requiresStepUp: input.requiresStepUp ?? false,
    currentStageIndex,
    stageStartedAt: input.stageStartedAt ?? input.updatedAt,
    stageDeadlineAt: input.stageDeadlineAt ?? null,
    escalatedStageIds: input.escalatedStageIds ?? [],
    stages,
    decisions
  };
}

function protectAction(action: ActionRecord, dps: DataProtectionService): ActionRecord {
  return { ...action, input: dps.protect(action.input) as Record<string, unknown> };
}

function restoreAction(action: ActionRecord, dps: DataProtectionService): ActionRecord {
  return { ...action, input: dps.restore<Record<string, unknown>>(action.input) };
}

function protectSecurityEvent(event: SecurityEventRecord, dps: DataProtectionService): SecurityEventRecord {
  return { ...event, payload: dps.protect(event.payload) as Record<string, unknown> };
}

function restoreSecurityEvent(event: SecurityEventRecord, dps: DataProtectionService): SecurityEventRecord {
  return { ...event, payload: dps.restore<Record<string, unknown>>(event.payload) };
}

function protectDeadLetter(deadLetter: SiemDeadLetterRecord, dps: DataProtectionService): SiemDeadLetterRecord {
  return { ...deadLetter, payload: dps.protect(deadLetter.payload) as Record<string, unknown> };
}

function restoreDeadLetter(deadLetter: SiemDeadLetterRecord, dps: DataProtectionService): SiemDeadLetterRecord {
  return { ...deadLetter, payload: dps.restore<Record<string, unknown>>(deadLetter.payload) };
}

function protectEvidenceNode(node: EvidenceGraphNodeRecord, dps: DataProtectionService): EvidenceGraphNodeRecord {
  return { ...node, payload: dps.protect(node.payload) as Record<string, unknown> };
}

function restoreEvidenceNode(node: EvidenceGraphNodeRecord, dps: DataProtectionService): EvidenceGraphNodeRecord {
  return { ...node, payload: dps.restore<Record<string, unknown>>(node.payload) };
}

const SCHEMA_STATEMENTS: string[] = [];

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_schema_migrations (
    id TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_actions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    state TEXT NOT NULL,
    approval_id TEXT NULL,
    policy_decision TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_actions_tenant_updated ON oars_actions (tenant_id, updated_at DESC);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_actions_tenant_state ON oars_actions (tenant_id, state);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_approvals_action ON oars_approvals (action_id);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_approvals_tenant_status_updated ON oars_approvals (tenant_id, status, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_approval_workflows (
    tenant_id TEXT PRIMARY KEY,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_receipts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    type TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_receipts_action_ts ON oars_receipts (action_id, ts);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_receipts_tenant_ts ON oars_receipts (tenant_id, ts DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_policies_tenant_updated ON oars_policies (tenant_id, updated_at DESC);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_policies_tenant_status ON oars_policies (tenant_id, status);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_alerts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_alerts_tenant_created ON oars_alerts (tenant_id, created_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_tenants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_tenants_tenant_id ON oars_tenants (tenant_id);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_tenant_members (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_tenant_members_tenant_subject ON oars_tenant_members (tenant_id, subject);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_tenant_members_tenant_updated ON oars_tenant_members (tenant_id, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_security_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_security_events_tenant_occurred ON oars_security_events (tenant_id, occurred_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_service_accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_service_accounts_tenant_updated ON oars_service_accounts (tenant_id, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_scim_users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_scim_users_tenant_external ON oars_scim_users (tenant_id, external_id);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_scim_users_tenant_updated ON oars_scim_users (tenant_id, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_scim_groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_scim_groups_tenant_external ON oars_scim_groups (tenant_id, external_id);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_scim_groups_tenant_updated ON oars_scim_groups (tenant_id, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_scim_role_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    group_display_name TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_scim_role_mappings_tenant_group ON oars_scim_role_mappings (tenant_id, group_display_name);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_scim_role_mappings_tenant_updated ON oars_scim_role_mappings (tenant_id, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_siem_dead_letters (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_siem_dead_letters_tenant_status_updated ON oars_siem_dead_letters (tenant_id, status, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_ledger_retention_policies (
    tenant_id TEXT PRIMARY KEY,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_evidence_nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_evidence_nodes_tenant_type_ref ON oars_evidence_nodes (tenant_id, node_type, ref_id);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_evidence_nodes_tenant_type_updated ON oars_evidence_nodes (tenant_id, node_type, updated_at DESC);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_evidence_edges (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_evidence_edges_tenant_created ON oars_evidence_edges (tenant_id, created_at DESC);`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_evidence_edges_unique_tuple ON oars_evidence_edges (tenant_id, (data->>'fromNodeId'), (data->>'toNodeId'), (data->>'relation'));`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_control_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_control_mappings_tenant_framework_control ON oars_control_mappings (tenant_id, framework, control_id);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_alert_routing_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_alert_routing_rules_tenant_severity ON oars_alert_routing_rules (tenant_id, severity);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_idempotency_records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_idempotency_unique ON oars_idempotency_records (tenant_id, subject, endpoint, idem_key);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_idempotency_created_at ON oars_idempotency_records (created_at);`
);

SCHEMA_STATEMENTS.push(
  `CREATE TABLE IF NOT EXISTS oars_execution_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INT NOT NULL,
    max_attempts INT NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ NULL,
    locked_by TEXT NULL,
    last_error TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_status_available ON oars_execution_jobs (status, available_at ASC);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_tenant_updated ON oars_execution_jobs (tenant_id, updated_at DESC);`,
  `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_action ON oars_execution_jobs (action_id);`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_execution_jobs_action_inflight ON oars_execution_jobs (action_id) WHERE status IN ('pending','running');`
);

const MIGRATIONS: Migration[] = [
  {
    id: "2026-02-14-01-normalized-store",
    statements: SCHEMA_STATEMENTS
  },
  {
    id: "2026-02-14-02-evidence-edge-uniqueness",
    statements: [
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_evidence_edges_unique_tuple ON oars_evidence_edges (tenant_id, (data->>'fromNodeId'), (data->>'toNodeId'), (data->>'relation'));`
    ]
  },
  {
    id: "2026-02-14-03-execution-backplane",
    statements: [
      `CREATE TABLE IF NOT EXISTS oars_execution_jobs (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        action_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        status TEXT NOT NULL,
        attempt_count INT NOT NULL,
        max_attempts INT NOT NULL,
        available_at TIMESTAMPTZ NOT NULL,
        locked_at TIMESTAMPTZ NULL,
        locked_by TEXT NULL,
        last_error TEXT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        data JSONB NOT NULL
      );`,
      `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_status_available ON oars_execution_jobs (status, available_at ASC);`,
      `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_tenant_updated ON oars_execution_jobs (tenant_id, updated_at DESC);`,
      `CREATE INDEX IF NOT EXISTS idx_oars_execution_jobs_action ON oars_execution_jobs (action_id);`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_oars_execution_jobs_action_inflight ON oars_execution_jobs (action_id) WHERE status IN ('pending','running');`
    ]
  }
];

export class PostgresPlatformStore implements PlatformStore {
  private readonly pool: PgPool;
  private readonly ready: Promise<void>;
  private readonly dataProtectionService: DataProtectionService;

  constructor(connectionString: string, dataProtectionService?: DataProtectionService) {
    this.pool = new Pool({ connectionString });
    this.dataProtectionService = dataProtectionService ?? new DataProtectionService();
    this.ready = this.init();
  }

  async close(): Promise<void> {
    await this.ready.catch(() => undefined);
    await this.pool.end();
  }

  private async init(): Promise<void> {
    await this.pool.query(
      "CREATE TABLE IF NOT EXISTS oars_schema_migrations (id TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"
    );

    const appliedRows = await this.pool.query<{ id: string }>("SELECT id FROM oars_schema_migrations");
    const applied = new Set(appliedRows.rows.map((row) => row.id));
    const pending = MIGRATIONS.filter((migration) => !applied.has(migration.id));
    if (pending.length === 0) {
      return;
    }

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const migration of pending) {
        for (const statement of migration.statements) {
          await client.query(statement);
        }
        await client.query("INSERT INTO oars_schema_migrations (id) VALUES ($1) ON CONFLICT (id) DO NOTHING", [
          migration.id
        ]);
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  async getAction(actionId: string): Promise<ActionRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ActionRecord>>("SELECT data FROM oars_actions WHERE id=$1", [actionId]);
    const row = result.rows[0];
    return row ? restoreAction(row.data, this.dataProtectionService) : undefined;
  }

  async listActionsByTenant(tenantId: string): Promise<ActionRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ActionRecord>>(
      "SELECT data FROM oars_actions WHERE tenant_id=$1 ORDER BY updated_at DESC",
      [tenantId]
    );
    return result.rows.map((row) => restoreAction(row.data, this.dataProtectionService));
  }

  async saveAction(action: ActionRecord): Promise<void> {
    await this.ensureReady();
    const protectedAction = protectAction(action, this.dataProtectionService);
    const createdAt = safeDate(action.createdAt, new Date());
    const updatedAt = safeDate(action.updatedAt, createdAt);
    await this.pool.query(
      `INSERT INTO oars_actions (id, tenant_id, state, approval_id, policy_decision, created_at, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, state=EXCLUDED.state, approval_id=EXCLUDED.approval_id, policy_decision=EXCLUDED.policy_decision,
                     created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [
        protectedAction.id,
        protectedAction.tenantId,
        protectedAction.state,
        protectedAction.approvalId,
        protectedAction.policyDecision,
        createdAt,
        updatedAt,
        JSON.stringify(protectedAction)
      ]
    );
  }

  async getApproval(approvalId: string): Promise<ApprovalRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ApprovalRecord>>("SELECT data FROM oars_approvals WHERE id=$1", [approvalId]);
    const row = result.rows[0];
    return row ? normalizeApprovalRecord(row.data) : undefined;
  }

  async getApprovalByAction(actionId: string): Promise<ApprovalRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ApprovalRecord>>("SELECT data FROM oars_approvals WHERE action_id=$1", [actionId]);
    const row = result.rows[0];
    return row ? normalizeApprovalRecord(row.data) : undefined;
  }

  async listApprovalsByTenant(tenantId: string, status?: ApprovalRecord["status"]): Promise<ApprovalRecord[]> {
    await this.ensureReady();
    const result = status
      ? await this.pool.query<PgJsonRow<ApprovalRecord>>(
          "SELECT data FROM oars_approvals WHERE tenant_id=$1 AND status=$2 ORDER BY updated_at DESC",
          [tenantId, status]
        )
      : await this.pool.query<PgJsonRow<ApprovalRecord>>(
          "SELECT data FROM oars_approvals WHERE tenant_id=$1 ORDER BY updated_at DESC",
          [tenantId]
        );
    return result.rows.map((row) => normalizeApprovalRecord(row.data));
  }

  async saveApproval(approval: ApprovalRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(approval.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_approvals (id, tenant_id, action_id, status, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, action_id=EXCLUDED.action_id, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [approval.id, approval.tenantId, approval.actionId, approval.status, updatedAt, JSON.stringify(approval)]
    );
  }

  async saveApprovalWorkflow(workflow: ApprovalWorkflowRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(workflow.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_approval_workflows (tenant_id, updated_at, data)
       VALUES ($1,$2,$3::jsonb)
       ON CONFLICT (tenant_id)
       DO UPDATE SET updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [workflow.tenantId, updatedAt, JSON.stringify(workflow)]
    );
  }

  async getApprovalWorkflowByTenant(tenantId: string): Promise<ApprovalWorkflowRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ApprovalWorkflowRecord>>("SELECT data FROM oars_approval_workflows WHERE tenant_id=$1", [
      tenantId
    ]);
    return result.rows[0]?.data;
  }

  async saveReceipt(receipt: ActionReceipt): Promise<void> {
    await this.ensureReady();
    const ts = safeDate(receipt.timestamp, new Date());
    await this.pool.query(
      `INSERT INTO oars_receipts (id, tenant_id, action_id, type, ts, data)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, action_id=EXCLUDED.action_id, type=EXCLUDED.type, ts=EXCLUDED.ts, data=EXCLUDED.data`,
      [receipt.receiptId, receipt.tenantId, receipt.actionId, receipt.type, ts, JSON.stringify(receipt)]
    );
  }

  async getReceipt(receiptId: string): Promise<ActionReceipt | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ActionReceipt>>("SELECT data FROM oars_receipts WHERE id=$1", [receiptId]);
    return result.rows[0]?.data;
  }

  async listReceiptsByAction(actionId: string): Promise<ActionReceipt[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ActionReceipt>>("SELECT data FROM oars_receipts WHERE action_id=$1 ORDER BY ts ASC", [actionId]);
    return result.rows.map((row) => row.data);
  }

  async listReceiptsByTenant(tenantId: string, limit = 100): Promise<ActionReceipt[]> {
    await this.ensureReady();
    const safeLimit = Math.min(500, Math.max(1, limit));
    const result = await this.pool.query<PgJsonRow<ActionReceipt>>(
      "SELECT data FROM oars_receipts WHERE tenant_id=$1 ORDER BY ts DESC LIMIT $2",
      [tenantId, safeLimit]
    );
    return result.rows.map((row) => row.data);
  }

  async savePolicy(policy: PolicyDocument): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(policy.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_policies (id, tenant_id, status, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [policy.id, policy.tenantId, policy.status, updatedAt, JSON.stringify(policy)]
    );
  }

  async getPolicy(policyId: string): Promise<PolicyDocument | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<PolicyDocument>>("SELECT data FROM oars_policies WHERE id=$1", [policyId]);
    return result.rows[0]?.data;
  }

  async listPoliciesByTenant(tenantId: string): Promise<PolicyDocument[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<PolicyDocument>>("SELECT data FROM oars_policies WHERE tenant_id=$1 ORDER BY updated_at DESC", [
      tenantId
    ]);
    return result.rows.map((row) => row.data);
  }

  async getPublishedPolicy(tenantId: string): Promise<PolicyDocument | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<PolicyDocument>>(
      "SELECT data FROM oars_policies WHERE tenant_id=$1 AND status='published' ORDER BY updated_at DESC LIMIT 1",
      [tenantId]
    );
    return result.rows[0]?.data;
  }

  async saveAlert(alert: AlertRecord): Promise<void> {
    await this.ensureReady();
    const createdAt = safeDate(alert.createdAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_alerts (id, tenant_id, severity, created_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, severity=EXCLUDED.severity, created_at=EXCLUDED.created_at, data=EXCLUDED.data`,
      [alert.id, alert.tenantId, alert.severity, createdAt, JSON.stringify(alert)]
    );
  }

  async listAlertsByTenant(tenantId: string, limit = 100): Promise<AlertRecord[]> {
    await this.ensureReady();
    const safeLimit = Math.min(500, Math.max(1, limit));
    const result = await this.pool.query<PgJsonRow<AlertRecord>>("SELECT data FROM oars_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2", [
      tenantId,
      safeLimit
    ]);
    return result.rows.map((row) => row.data);
  }

  async saveTenant(tenant: TenantRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(tenant.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_tenants (id, tenant_id, updated_at, data)
       VALUES ($1,$2,$3,$4::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [tenant.id, tenant.tenantId, updatedAt, JSON.stringify(tenant)]
    );
  }

  async getTenant(tenantId: string): Promise<TenantRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<TenantRecord>>("SELECT data FROM oars_tenants WHERE tenant_id=$1", [tenantId]);
    return result.rows[0]?.data;
  }

  async listTenants(): Promise<TenantRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<TenantRecord>>("SELECT data FROM oars_tenants ORDER BY updated_at DESC");
    return result.rows.map((row) => row.data);
  }

  async saveTenantMember(member: TenantMemberRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(member.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_tenant_members (id, tenant_id, subject, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, subject=EXCLUDED.subject, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [member.id, member.tenantId, member.subject, updatedAt, JSON.stringify(member)]
    );
  }

  async getTenantMember(tenantId: string, subject: string): Promise<TenantMemberRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<TenantMemberRecord>>("SELECT data FROM oars_tenant_members WHERE tenant_id=$1 AND subject=$2", [
      tenantId,
      subject
    ]);
    return result.rows[0]?.data;
  }

  async listTenantMembers(tenantId: string): Promise<TenantMemberRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<TenantMemberRecord>>("SELECT data FROM oars_tenant_members WHERE tenant_id=$1 ORDER BY updated_at DESC", [
      tenantId
    ]);
    return result.rows.map((row) => row.data);
  }

  async deleteTenantMember(tenantId: string, subject: string): Promise<boolean> {
    await this.ensureReady();
    const result = await this.pool.query("DELETE FROM oars_tenant_members WHERE tenant_id=$1 AND subject=$2", [tenantId, subject]);
    return (result.rowCount ?? 0) > 0;
  }

  async saveSecurityEvent(event: SecurityEventRecord): Promise<void> {
    await this.ensureReady();
    const protectedEvent = protectSecurityEvent(event, this.dataProtectionService);
    const occurredAt = safeDate(event.occurredAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_security_events (id, tenant_id, occurred_at, event_type, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, occurred_at=EXCLUDED.occurred_at, event_type=EXCLUDED.event_type, data=EXCLUDED.data`,
      [protectedEvent.id, protectedEvent.tenantId, occurredAt, protectedEvent.eventType, JSON.stringify(protectedEvent)]
    );
  }

  async listSecurityEventsByTenant(tenantId: string, limit = 200): Promise<SecurityEventRecord[]> {
    await this.ensureReady();
    const safeLimit = Math.min(500, Math.max(1, limit));
    const result = await this.pool.query<PgJsonRow<SecurityEventRecord>>(
      "SELECT data FROM oars_security_events WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT $2",
      [tenantId, safeLimit]
    );
    return result.rows.map((row) => restoreSecurityEvent(row.data, this.dataProtectionService));
  }

  async saveServiceAccount(account: ServiceAccountRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(account.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_service_accounts (id, tenant_id, status, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [account.id, account.tenantId, account.status, updatedAt, JSON.stringify(account)]
    );
  }

  async getServiceAccount(accountId: string): Promise<ServiceAccountRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ServiceAccountRecord>>("SELECT data FROM oars_service_accounts WHERE id=$1", [accountId]);
    return result.rows[0]?.data;
  }

  async listServiceAccountsByTenant(tenantId: string): Promise<ServiceAccountRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ServiceAccountRecord>>("SELECT data FROM oars_service_accounts WHERE tenant_id=$1 ORDER BY updated_at DESC", [
      tenantId
    ]);
    return result.rows.map((row) => row.data);
  }

  async saveScimUser(user: ScimUserRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(user.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_scim_users (id, tenant_id, external_id, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, external_id=EXCLUDED.external_id, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [user.id, user.tenantId, user.externalId, updatedAt, JSON.stringify(user)]
    );
  }

  async listScimUsersByTenant(tenantId: string): Promise<ScimUserRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ScimUserRecord>>("SELECT data FROM oars_scim_users WHERE tenant_id=$1 ORDER BY updated_at DESC", [
      tenantId
    ]);
    return result.rows.map((row) => row.data);
  }

  async listScimUsersByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimUserRecord[]; total: number; page: number; pageSize: number }> {
    await this.ensureReady();
    const safePage = clampPage(page);
    const safePageSize = clampPageSize(pageSize);
    const offset = (safePage - 1) * safePageSize;

    const totalResult = await this.pool.query<{ count: string }>("SELECT COUNT(*)::text as count FROM oars_scim_users WHERE tenant_id=$1", [
      tenantId
    ]);
    const total = Number.parseInt(totalResult.rows[0]?.count ?? "0", 10);

    const result = await this.pool.query<PgJsonRow<ScimUserRecord>>(
      "SELECT data FROM oars_scim_users WHERE tenant_id=$1 ORDER BY updated_at DESC OFFSET $2 LIMIT $3",
      [tenantId, offset, safePageSize]
    );
    return { items: result.rows.map((row) => row.data), total, page: safePage, pageSize: safePageSize };
  }

  async getScimUserByExternalId(tenantId: string, externalId: string): Promise<ScimUserRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ScimUserRecord>>(
      "SELECT data FROM oars_scim_users WHERE tenant_id=$1 AND external_id=$2",
      [tenantId, externalId]
    );
    return result.rows[0]?.data;
  }

  async saveScimGroup(group: ScimGroupRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(group.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_scim_groups (id, tenant_id, external_id, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, external_id=EXCLUDED.external_id, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [group.id, group.tenantId, group.externalId, updatedAt, JSON.stringify(group)]
    );
  }

  async listScimGroupsByTenant(tenantId: string): Promise<ScimGroupRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ScimGroupRecord>>("SELECT data FROM oars_scim_groups WHERE tenant_id=$1 ORDER BY updated_at DESC", [
      tenantId
    ]);
    return result.rows.map((row) => row.data);
  }

  async listScimGroupsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimGroupRecord[]; total: number; page: number; pageSize: number }> {
    await this.ensureReady();
    const safePage = clampPage(page);
    const safePageSize = clampPageSize(pageSize);
    const offset = (safePage - 1) * safePageSize;

    const totalResult = await this.pool.query<{ count: string }>("SELECT COUNT(*)::text as count FROM oars_scim_groups WHERE tenant_id=$1", [
      tenantId
    ]);
    const total = Number.parseInt(totalResult.rows[0]?.count ?? "0", 10);

    const result = await this.pool.query<PgJsonRow<ScimGroupRecord>>(
      "SELECT data FROM oars_scim_groups WHERE tenant_id=$1 ORDER BY updated_at DESC OFFSET $2 LIMIT $3",
      [tenantId, offset, safePageSize]
    );
    return { items: result.rows.map((row) => row.data), total, page: safePage, pageSize: safePageSize };
  }

  async saveScimRoleMapping(mapping: ScimRoleMappingRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(mapping.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_scim_role_mappings (id, tenant_id, group_display_name, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, group_display_name=EXCLUDED.group_display_name, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [mapping.id, mapping.tenantId, mapping.groupDisplayName, updatedAt, JSON.stringify(mapping)]
    );
  }

  async listScimRoleMappingsByTenant(tenantId: string): Promise<ScimRoleMappingRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ScimRoleMappingRecord>>(
      "SELECT data FROM oars_scim_role_mappings WHERE tenant_id=$1 ORDER BY updated_at DESC",
      [tenantId]
    );
    return result.rows.map((row) => row.data);
  }

  async listScimRoleMappingsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimRoleMappingRecord[]; total: number; page: number; pageSize: number }> {
    await this.ensureReady();
    const safePage = clampPage(page);
    const safePageSize = clampPageSize(pageSize);
    const offset = (safePage - 1) * safePageSize;

    const totalResult = await this.pool.query<{ count: string }>(
      "SELECT COUNT(*)::text as count FROM oars_scim_role_mappings WHERE tenant_id=$1",
      [tenantId]
    );
    const total = Number.parseInt(totalResult.rows[0]?.count ?? "0", 10);

    const result = await this.pool.query<PgJsonRow<ScimRoleMappingRecord>>(
      "SELECT data FROM oars_scim_role_mappings WHERE tenant_id=$1 ORDER BY updated_at DESC OFFSET $2 LIMIT $3",
      [tenantId, offset, safePageSize]
    );
    return { items: result.rows.map((row) => row.data), total, page: safePage, pageSize: safePageSize };
  }

  async saveSiemDeadLetter(deadLetter: SiemDeadLetterRecord): Promise<void> {
    await this.ensureReady();
    const protectedDeadLetter = protectDeadLetter(deadLetter, this.dataProtectionService);
    const failedAt = safeDate(deadLetter.failedAt, new Date());
    const updatedAt = safeDate(deadLetter.updatedAt, failedAt);
    await this.pool.query(
      `INSERT INTO oars_siem_dead_letters (id, tenant_id, status, failed_at, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, status=EXCLUDED.status, failed_at=EXCLUDED.failed_at, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [
        protectedDeadLetter.id,
        protectedDeadLetter.tenantId,
        protectedDeadLetter.status,
        failedAt,
        updatedAt,
        JSON.stringify(protectedDeadLetter)
      ]
    );
  }

  async getSiemDeadLetter(deadLetterId: string): Promise<SiemDeadLetterRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<SiemDeadLetterRecord>>("SELECT data FROM oars_siem_dead_letters WHERE id=$1", [deadLetterId]);
    const row = result.rows[0];
    return row ? restoreDeadLetter(row.data, this.dataProtectionService) : undefined;
  }

  async getSiemDeadLetterForTenant(deadLetterId: string, tenantId: string): Promise<SiemDeadLetterRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<SiemDeadLetterRecord>>("SELECT data FROM oars_siem_dead_letters WHERE id=$1 AND tenant_id=$2", [
      deadLetterId,
      tenantId
    ]);
    const row = result.rows[0];
    return row ? restoreDeadLetter(row.data, this.dataProtectionService) : undefined;
  }

  async listSiemDeadLettersPaged(
    tenantId: string,
    status: SiemDeadLetterRecord["status"] | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: SiemDeadLetterRecord[]; total: number; page: number; pageSize: number }> {
    await this.ensureReady();
    const safePage = clampPage(page);
    const safePageSize = clampPageSize(pageSize);
    const offset = (safePage - 1) * safePageSize;

    const where = status === "all" ? "tenant_id=$1" : "tenant_id=$1 AND status=$2";
    const totalArgs = status === "all" ? [tenantId] : [tenantId, status];
    const totalResult = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text as count FROM oars_siem_dead_letters WHERE ${where}`,
      totalArgs
    );
    const total = Number.parseInt(totalResult.rows[0]?.count ?? "0", 10);

    const listArgs = status === "all" ? [tenantId, offset, safePageSize] : [tenantId, status, offset, safePageSize];
    const listSql =
      status === "all"
        ? "SELECT data FROM oars_siem_dead_letters WHERE tenant_id=$1 ORDER BY updated_at DESC OFFSET $2 LIMIT $3"
        : "SELECT data FROM oars_siem_dead_letters WHERE tenant_id=$1 AND status=$2 ORDER BY updated_at DESC OFFSET $3 LIMIT $4";
    const result = await this.pool.query<PgJsonRow<SiemDeadLetterRecord>>(listSql, listArgs);
    return {
      items: result.rows.map((row) => restoreDeadLetter(row.data, this.dataProtectionService)),
      total,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveLedgerRetentionPolicy(policy: LedgerRetentionPolicyRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(policy.updatedAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_ledger_retention_policies (tenant_id, updated_at, data)
       VALUES ($1,$2,$3::jsonb)
       ON CONFLICT (tenant_id)
       DO UPDATE SET updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [policy.tenantId, updatedAt, JSON.stringify(policy)]
    );
  }

  async getLedgerRetentionPolicy(tenantId: string): Promise<LedgerRetentionPolicyRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<LedgerRetentionPolicyRecord>>(
      "SELECT data FROM oars_ledger_retention_policies WHERE tenant_id=$1",
      [tenantId]
    );
    return result.rows[0]?.data;
  }

  async listLedgerRetentionPolicies(): Promise<LedgerRetentionPolicyRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<LedgerRetentionPolicyRecord>>(
      "SELECT data FROM oars_ledger_retention_policies ORDER BY tenant_id ASC"
    );
    return result.rows.map((row) => row.data);
  }

  async saveEvidenceNode(node: EvidenceGraphNodeRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(node.updatedAt, new Date());
    const existing = await this.pool.query<PgJsonRow<EvidenceGraphNodeRecord>>(
      "SELECT data FROM oars_evidence_nodes WHERE tenant_id=$1 AND node_type=$2 AND ref_id=$3",
      [node.tenantId, node.nodeType, node.refId]
    );
    const persisted = existing.rows[0]?.data;
    const stableId = persisted?.id ?? node.id;
    const protectedNode = protectEvidenceNode({ ...node, id: stableId }, this.dataProtectionService);

    await this.pool.query(
      `INSERT INTO oars_evidence_nodes (id, tenant_id, node_type, ref_id, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, node_type=EXCLUDED.node_type, ref_id=EXCLUDED.ref_id, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [
        protectedNode.id,
        protectedNode.tenantId,
        protectedNode.nodeType,
        protectedNode.refId,
        updatedAt,
        JSON.stringify(protectedNode)
      ]
    );
  }

  async getEvidenceNodeByRef(
    tenantId: string,
    nodeType: EvidenceNodeType,
    refId: string
  ): Promise<EvidenceGraphNodeRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<EvidenceGraphNodeRecord>>(
      "SELECT data FROM oars_evidence_nodes WHERE tenant_id=$1 AND node_type=$2 AND ref_id=$3",
      [tenantId, nodeType, refId]
    );
    const row = result.rows[0];
    return row ? restoreEvidenceNode(row.data, this.dataProtectionService) : undefined;
  }

  async listEvidenceNodesByTenantPaged(
    tenantId: string,
    nodeType: EvidenceNodeType | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: EvidenceGraphNodeRecord[]; total: number; page: number; pageSize: number }> {
    await this.ensureReady();
    const safePage = clampPage(page);
    const safePageSize = clampPageSize(pageSize);
    const offset = (safePage - 1) * safePageSize;

    const where = nodeType === "all" ? "tenant_id=$1" : "tenant_id=$1 AND node_type=$2";
    const countArgs = nodeType === "all" ? [tenantId] : [tenantId, nodeType];
    const totalResult = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text as count FROM oars_evidence_nodes WHERE ${where}`,
      countArgs
    );
    const total = Number.parseInt(totalResult.rows[0]?.count ?? "0", 10);

    const listArgs = nodeType === "all" ? [tenantId, offset, safePageSize] : [tenantId, nodeType, offset, safePageSize];
    const listSql =
      nodeType === "all"
        ? "SELECT data FROM oars_evidence_nodes WHERE tenant_id=$1 ORDER BY updated_at DESC OFFSET $2 LIMIT $3"
        : "SELECT data FROM oars_evidence_nodes WHERE tenant_id=$1 AND node_type=$2 ORDER BY updated_at DESC OFFSET $3 LIMIT $4";
    const result = await this.pool.query<PgJsonRow<EvidenceGraphNodeRecord>>(listSql, listArgs);
    return {
      items: result.rows.map((row) => restoreEvidenceNode(row.data, this.dataProtectionService)),
      total,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveEvidenceEdge(edge: EvidenceGraphEdgeRecord): Promise<void> {
    await this.ensureReady();
    const createdAt = safeDate(edge.createdAt, new Date());
    try {
      await this.pool.query(
        `INSERT INTO oars_evidence_edges (id, tenant_id, created_at, data)
         VALUES ($1,$2,$3,$4::jsonb)`,
        [edge.id, edge.tenantId, createdAt, JSON.stringify(edge)]
      );
    } catch (error) {
      const code = typeof error === "object" && error && "code" in error ? String((error as { code?: unknown }).code) : null;
      if (code === "23505") {
        return;
      }
      throw error;
    }
  }

  async listEvidenceEdgesByTenant(tenantId: string): Promise<EvidenceGraphEdgeRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<EvidenceGraphEdgeRecord>>(
      "SELECT data FROM oars_evidence_edges WHERE tenant_id=$1 ORDER BY created_at DESC",
      [tenantId]
    );
    return result.rows.map((row) => row.data);
  }

  async saveControlMapping(mapping: ControlMappingRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(mapping.updatedAt, new Date());
    const existing = await this.pool.query<PgJsonRow<ControlMappingRecord>>(
      "SELECT data FROM oars_control_mappings WHERE tenant_id=$1 AND framework=$2 AND control_id=$3",
      [mapping.tenantId, mapping.framework, mapping.controlId]
    );
    const persisted = existing.rows[0]?.data;
    const stableId = persisted?.id ?? mapping.id;
    const stored = { ...mapping, id: stableId };

    await this.pool.query(
      `INSERT INTO oars_control_mappings (id, tenant_id, framework, control_id, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, framework=EXCLUDED.framework, control_id=EXCLUDED.control_id, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [stored.id, stored.tenantId, stored.framework, stored.controlId, updatedAt, JSON.stringify(stored)]
    );
  }

  async listControlMappingsByTenant(
    tenantId: string,
    framework?: ControlMappingRecord["framework"]
  ): Promise<ControlMappingRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<ControlMappingRecord>>(
      framework
        ? "SELECT data FROM oars_control_mappings WHERE tenant_id=$1 AND framework=$2 ORDER BY control_id ASC"
        : "SELECT data FROM oars_control_mappings WHERE tenant_id=$1 ORDER BY control_id ASC",
      framework ? [tenantId, framework] : [tenantId]
    );
    return result.rows.map((row) => row.data);
  }

  async saveAlertRoutingRule(rule: AlertRoutingRuleRecord): Promise<void> {
    await this.ensureReady();
    const updatedAt = safeDate(rule.updatedAt, new Date());
    const existing = await this.pool.query<PgJsonRow<AlertRoutingRuleRecord>>(
      "SELECT data FROM oars_alert_routing_rules WHERE tenant_id=$1 AND severity=$2",
      [rule.tenantId, rule.severity]
    );
    const persisted = existing.rows[0]?.data;
    const stableId = persisted?.id ?? rule.id;
    const stored = { ...rule, id: stableId };

    await this.pool.query(
      `INSERT INTO oars_alert_routing_rules (id, tenant_id, severity, updated_at, data)
       VALUES ($1,$2,$3,$4,$5::jsonb)
       ON CONFLICT (id)
       DO UPDATE SET tenant_id=EXCLUDED.tenant_id, severity=EXCLUDED.severity, updated_at=EXCLUDED.updated_at, data=EXCLUDED.data`,
      [stored.id, stored.tenantId, stored.severity, updatedAt, JSON.stringify(stored)]
    );
  }

  async listAlertRoutingRulesByTenant(tenantId: string): Promise<AlertRoutingRuleRecord[]> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<AlertRoutingRuleRecord>>(
      "SELECT data FROM oars_alert_routing_rules WHERE tenant_id=$1 ORDER BY severity ASC",
      [tenantId]
    );
    return result.rows.map((row) => row.data);
  }

  async getIdempotencyRecord(
    tenantId: string,
    subject: string,
    endpoint: string,
    key: string
  ): Promise<IdempotencyRecord | undefined> {
    await this.ensureReady();
    const result = await this.pool.query<PgJsonRow<IdempotencyRecord>>(
      "SELECT data FROM oars_idempotency_records WHERE tenant_id=$1 AND subject=$2 AND endpoint=$3 AND idem_key=$4",
      [tenantId, subject, endpoint, key]
    );
    return result.rows[0]?.data;
  }

  async saveIdempotencyRecord(record: IdempotencyRecord): Promise<void> {
    await this.ensureReady();
    const createdAt = safeDate(record.createdAt, new Date());
    await this.pool.query(
      `INSERT INTO oars_idempotency_records (id, tenant_id, subject, endpoint, idem_key, created_at, data)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
       ON CONFLICT (tenant_id, subject, endpoint, idem_key)
       DO NOTHING`,
      [record.id, record.tenantId, record.subject, record.endpoint, record.key, createdAt, JSON.stringify(record)]
    );
  }

  async pruneIdempotencyRecords(olderThanIso: string): Promise<number> {
    await this.ensureReady();
    const cutoffMs = Date.parse(olderThanIso);
    if (Number.isNaN(cutoffMs)) {
      return 0;
    }
    const cutoff = new Date(cutoffMs);
    const result = await this.pool.query("DELETE FROM oars_idempotency_records WHERE created_at < $1", [cutoff]);
    return result.rowCount ?? 0;
  }
}
