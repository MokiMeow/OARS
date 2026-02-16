export type ActionState =
  | "requested"
  | "denied"
  | "approval_required"
  | "approved"
  | "executed"
  | "failed"
  | "quarantined"
  | "canceled";

export type PolicyDecision = "allow" | "deny" | "approve" | "quarantine";

export interface ActorContext {
  userId: string | null;
  agentId: string;
  serviceId: string | null;
  delegationChain: string[];
}

export interface ResourceContext {
  toolId: string;
  operation: string;
  target: string;
}

export interface ActionContext {
  environment?: string | undefined;
  dataTypes?: string[] | undefined;
  requestedAt?: string | undefined;
}

export interface ActionRequest {
  tenantId: string;
  agentId: string;
  userContext?: {
    userId?: string | undefined;
    sessionId?: string | undefined;
  } | undefined;
  context?: ActionContext | undefined;
  resource: ResourceContext;
  input: Record<string, unknown>;
}

export interface ActionRecord {
  id: string;
  tenantId: string;
  state: ActionState;
  actor: ActorContext;
  context?: ActionContext | undefined;
  resource: ResourceContext;
  input: Record<string, unknown>;
  approvalId: string | null;
  policyDecision: PolicyDecision | null;
  policySetId: string | null;
  policyVersion: string | null;
  policyRuleIds: string[];
  policyRationale: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
  receiptIds: string[];
}

export type AlertSeverity = "low" | "medium" | "high" | "critical";

export interface AlertRecord {
  id: string;
  tenantId: string;
  actionId: string | null;
  severity: AlertSeverity;
  code: string;
  message: string;
  createdAt: string;
  metadata: Record<string, unknown>;
}

export type TenantRole = "owner" | "admin" | "operator" | "auditor";

export interface TenantMemberRecord {
  id: string;
  tenantId: string;
  subject: string;
  role: TenantRole;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface TenantRecord {
  id: string;
  tenantId: string;
  displayName: string;
  status: "active" | "suspended";
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface SecurityEventRecord {
  id: string;
  tenantId: string;
  source: "receipt" | "alert" | "admin";
  eventType: string;
  occurredAt: string;
  payload: Record<string, unknown>;
}

export interface ServiceAccountRecord {
  id: string;
  tenantId: string;
  name: string;
  role: "operator" | "auditor" | "agent";
  scopes: string[];
  secretHash: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  status: "active" | "disabled";
}

export interface ScimUserRecord {
  id: string;
  tenantId: string;
  externalId: string;
  userName: string;
  displayName: string;
  emails: string[];
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ScimGroupRecord {
  id: string;
  tenantId: string;
  externalId: string;
  displayName: string;
  memberExternalUserIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ScimRoleMappingRecord {
  id: string;
  tenantId: string;
  groupDisplayName: string;
  role: Exclude<TenantRole, "owner">;
  createdAt: string;
  updatedAt: string;
}

export interface SiemDeadLetterRecord {
  id: string;
  targetId: string;
  tenantId: string;
  eventId: string;
  eventType: string;
  source: SecurityEventRecord["source"];
  occurredAt: string;
  payload: Record<string, unknown>;
  attempts: number;
  lastError: string;
  failedAt: string;
  replayCount: number;
  status: "open" | "replayed" | "resolved";
  updatedAt: string;
}

export interface LedgerRetentionPolicyRecord {
  id: string;
  tenantId: string;
  retentionDays: number;
  legalHold: boolean;
  reason: string | null;
  updatedAt: string;
  updatedBy: string;
}

export type EvidenceNodeType =
  | "action"
  | "receipt"
  | "policy_version"
  | "approval_decision"
  | "actor"
  | "control_mapping"
  | "evidence_bundle";

export interface EvidenceGraphNodeRecord {
  id: string;
  tenantId: string;
  nodeType: EvidenceNodeType;
  refId: string;
  payload: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceGraphEdgeRecord {
  id: string;
  tenantId: string;
  fromNodeId: string;
  toNodeId: string;
  relation: string;
  createdAt: string;
}

export interface ControlMappingRecord {
  id: string;
  tenantId: string;
  framework: "eu_ai_act" | "iso_42001" | "soc2";
  controlId: string;
  controlDescription: string;
  requiredNodeTypes: EvidenceNodeType[];
  receiptFilters?:
    | {
        toolIds?: string[] | undefined;
        operations?: string[] | undefined;
        policyDecisions?: PolicyDecision[] | undefined;
        actorUserIds?: string[] | undefined;
        actorAgentIds?: string[] | undefined;
        policyRuleIds?: string[] | undefined;
        policyVersions?: string[] | undefined;
      }
    | undefined;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface AlertRoutingRuleRecord {
  id: string;
  tenantId: string;
  severity: AlertSeverity;
  channels: string[];
  escalationMinutes: number;
  updatedAt: string;
  updatedBy: string;
}

export interface IdempotencyRecord {
  id: string;
  key: string;
  tenantId: string;
  subject: string;
  endpoint: string;
  requestHash: string;
  responseStatus: number;
  responseBody: Record<string, unknown>;
  createdAt: string;
}

export interface PolicyRule {
  id: string;
  description: string;
  priority: number;
  match: {
    toolIds?: string[] | undefined;
    operations?: string[] | undefined;
    targetContains?: string | undefined;
    riskTiers?: RiskTier[] | undefined;
    environments?: string[] | undefined;
    requiredDataTypes?: string[] | undefined;
    timeWindowUtc?: { startHour: number; endHour: number } | undefined;
  };
  decision: PolicyDecision;
}

export interface PolicyDocument {
  id: string;
  tenantId: string;
  version: string;
  status: "draft" | "published";
  createdAt: string;
  updatedAt: string;
  rules: PolicyRule[];
}

export type RiskTier = "low" | "medium" | "high" | "critical";

export interface RiskContext {
  score: number;
  tier: RiskTier;
  signals: string[];
}

export interface PolicyEvaluation {
  decision: PolicyDecision;
  policySetId: string;
  policyVersion: string;
  ruleIds: string[];
  rationale: string;
}

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired";

export interface ApprovalDecisionRecord {
  decision: "approve" | "reject";
  approverId: string;
  reason: string;
  stageId: string;
  decidedAt: string;
}

export interface ApprovalStageRecord {
  id: string;
  name: string;
  mode: "serial" | "parallel";
  requiredApprovals: number;
  approverIds: string[];
  slaSeconds: number | null;
  escalateTo: string[];
}

export interface ApprovalRecord {
  id: string;
  actionId: string;
  tenantId: string;
  status: ApprovalStatus;
  requiresStepUp: boolean;
  currentStageIndex: number;
  stages: ApprovalStageRecord[];
  stageStartedAt: string;
  stageDeadlineAt: string | null;
  escalatedStageIds: string[];
  createdAt: string;
  updatedAt: string;
  decisions: ApprovalDecisionRecord[];
}

export interface ApprovalWorkflowRecord {
  id: string;
  tenantId: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  stages: ApprovalStageRecord[];
}

export type ReceiptType =
  | "action.requested"
  | "action.denied"
  | "action.approval_required"
  | "action.approved"
  | "action.executed"
  | "action.failed"
  | "action.quarantined"
  | "action.canceled";

export interface ActionReceipt {
  receiptId: string;
  version: string;
  tenantId: string;
  actionId: string;
  type: ReceiptType;
  timestamp: string;
  actor: {
    userId: string | null;
    agentId: string;
    serviceId: string | null;
    delegationChain: string[];
  };
  resource: {
    toolId: string;
    operation: string;
    target: string;
  };
  policy: {
    policySetId: string;
    policyVersion: string;
    decision: PolicyDecision;
    ruleIds: string[];
    rationale: string;
  };
  risk: RiskContext;
  integrity: {
    prevReceiptHash: string | null;
    receiptHash: string;
    signature: string;
    signingKeyId: string;
    signatureAlg: "Ed25519";
  };
  telemetry: {
    traceId: string;
    spanId: string;
    requestId: string;
  };
}

export interface PersistedState {
  actions: ActionRecord[];
  approvals: ApprovalRecord[];
  approvalWorkflows: ApprovalWorkflowRecord[];
  receipts: ActionReceipt[];
  policies: PolicyDocument[];
  alerts: AlertRecord[];
  tenants: TenantRecord[];
  tenantMembers: TenantMemberRecord[];
  securityEvents: SecurityEventRecord[];
  serviceAccounts: ServiceAccountRecord[];
  scimUsers: ScimUserRecord[];
  scimGroups: ScimGroupRecord[];
  scimRoleMappings: ScimRoleMappingRecord[];
  siemDeadLetters: SiemDeadLetterRecord[];
  ledgerRetentionPolicies: LedgerRetentionPolicyRecord[];
  evidenceNodes: EvidenceGraphNodeRecord[];
  evidenceEdges: EvidenceGraphEdgeRecord[];
  controlMappings: ControlMappingRecord[];
  alertRoutingRules: AlertRoutingRuleRecord[];
  idempotencyRecords: IdempotencyRecord[];
}
