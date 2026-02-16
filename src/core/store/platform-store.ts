import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type {
  AlertRecord,
  ActionReceipt,
  ActionRecord,
  ApprovalRecord,
  ApprovalWorkflowRecord,
  PersistedState,
  PolicyDocument,
  SiemDeadLetterRecord,
  LedgerRetentionPolicyRecord,
  EvidenceGraphNodeRecord,
  EvidenceGraphEdgeRecord,
  EvidenceNodeType,
  ControlMappingRecord,
  ScimGroupRecord,
  ScimRoleMappingRecord,
  ScimUserRecord,
  SecurityEventRecord,
  ServiceAccountRecord,
  AlertRoutingRuleRecord,
  TenantRecord,
  IdempotencyRecord,
  TenantMemberRecord
} from "../types/domain.js";
import { DataProtectionService } from "../services/data-protection-service.js";

const defaultState: PersistedState = {
  actions: [],
  approvals: [],
  approvalWorkflows: [],
  receipts: [],
  policies: [],
  alerts: [],
  tenants: [],
  tenantMembers: [],
  securityEvents: [],
  serviceAccounts: [],
  scimUsers: [],
  scimGroups: [],
  scimRoleMappings: [],
  siemDeadLetters: [],
  ledgerRetentionPolicies: [],
  evidenceNodes: [],
  evidenceEdges: [],
  controlMappings: [],
  alertRoutingRules: [],
  idempotencyRecords: []
};

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

export interface PlatformStore {
  close?(): Promise<void>;

  getAction(actionId: string): Promise<ActionRecord | undefined>;
  listActionsByTenant(tenantId: string): Promise<ActionRecord[]>;
  saveAction(action: ActionRecord): Promise<void>;

  getApproval(approvalId: string): Promise<ApprovalRecord | undefined>;
  getApprovalByAction(actionId: string): Promise<ApprovalRecord | undefined>;
  listApprovalsByTenant(tenantId: string, status?: ApprovalRecord["status"]): Promise<ApprovalRecord[]>;
  saveApproval(approval: ApprovalRecord): Promise<void>;

  saveApprovalWorkflow(workflow: ApprovalWorkflowRecord): Promise<void>;
  getApprovalWorkflowByTenant(tenantId: string): Promise<ApprovalWorkflowRecord | undefined>;

  saveReceipt(receipt: ActionReceipt): Promise<void>;
  getReceipt(receiptId: string): Promise<ActionReceipt | undefined>;
  listReceiptsByAction(actionId: string): Promise<ActionReceipt[]>;
  listReceiptsByTenant(tenantId: string, limit?: number): Promise<ActionReceipt[]>;

  savePolicy(policy: PolicyDocument): Promise<void>;
  getPolicy(policyId: string): Promise<PolicyDocument | undefined>;
  listPoliciesByTenant(tenantId: string): Promise<PolicyDocument[]>;
  getPublishedPolicy(tenantId: string): Promise<PolicyDocument | undefined>;

  saveAlert(alert: AlertRecord): Promise<void>;
  listAlertsByTenant(tenantId: string, limit?: number): Promise<AlertRecord[]>;

  saveTenant(tenant: TenantRecord): Promise<void>;
  getTenant(tenantId: string): Promise<TenantRecord | undefined>;
  listTenants(): Promise<TenantRecord[]>;

  saveTenantMember(member: TenantMemberRecord): Promise<void>;
  getTenantMember(tenantId: string, subject: string): Promise<TenantMemberRecord | undefined>;
  listTenantMembers(tenantId: string): Promise<TenantMemberRecord[]>;
  deleteTenantMember(tenantId: string, subject: string): Promise<boolean>;

  saveSecurityEvent(event: SecurityEventRecord): Promise<void>;
  listSecurityEventsByTenant(tenantId: string, limit?: number): Promise<SecurityEventRecord[]>;

  saveServiceAccount(account: ServiceAccountRecord): Promise<void>;
  getServiceAccount(accountId: string): Promise<ServiceAccountRecord | undefined>;
  listServiceAccountsByTenant(tenantId: string): Promise<ServiceAccountRecord[]>;

  saveScimUser(user: ScimUserRecord): Promise<void>;
  listScimUsersByTenant(tenantId: string): Promise<ScimUserRecord[]>;
  listScimUsersByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimUserRecord[]; total: number; page: number; pageSize: number }>;
  getScimUserByExternalId(tenantId: string, externalId: string): Promise<ScimUserRecord | undefined>;

  saveScimGroup(group: ScimGroupRecord): Promise<void>;
  listScimGroupsByTenant(tenantId: string): Promise<ScimGroupRecord[]>;
  listScimGroupsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimGroupRecord[]; total: number; page: number; pageSize: number }>;

  saveScimRoleMapping(mapping: ScimRoleMappingRecord): Promise<void>;
  listScimRoleMappingsByTenant(tenantId: string): Promise<ScimRoleMappingRecord[]>;
  listScimRoleMappingsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimRoleMappingRecord[]; total: number; page: number; pageSize: number }>;

  saveSiemDeadLetter(deadLetter: SiemDeadLetterRecord): Promise<void>;
  getSiemDeadLetter(deadLetterId: string): Promise<SiemDeadLetterRecord | undefined>;
  getSiemDeadLetterForTenant(deadLetterId: string, tenantId: string): Promise<SiemDeadLetterRecord | undefined>;
  listSiemDeadLettersPaged(
    tenantId: string,
    status: SiemDeadLetterRecord["status"] | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: SiemDeadLetterRecord[]; total: number; page: number; pageSize: number }>;

  saveLedgerRetentionPolicy(policy: LedgerRetentionPolicyRecord): Promise<void>;
  getLedgerRetentionPolicy(tenantId: string): Promise<LedgerRetentionPolicyRecord | undefined>;
  listLedgerRetentionPolicies(): Promise<LedgerRetentionPolicyRecord[]>;

  saveEvidenceNode(node: EvidenceGraphNodeRecord): Promise<void>;
  getEvidenceNodeByRef(
    tenantId: string,
    nodeType: EvidenceNodeType,
    refId: string
  ): Promise<EvidenceGraphNodeRecord | undefined>;
  listEvidenceNodesByTenantPaged(
    tenantId: string,
    nodeType: EvidenceNodeType | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: EvidenceGraphNodeRecord[]; total: number; page: number; pageSize: number }>;

  saveEvidenceEdge(edge: EvidenceGraphEdgeRecord): Promise<void>;
  listEvidenceEdgesByTenant(tenantId: string): Promise<EvidenceGraphEdgeRecord[]>;

  saveControlMapping(mapping: ControlMappingRecord): Promise<void>;
  listControlMappingsByTenant(tenantId: string, framework?: ControlMappingRecord["framework"]): Promise<ControlMappingRecord[]>;

  saveAlertRoutingRule(rule: AlertRoutingRuleRecord): Promise<void>;
  listAlertRoutingRulesByTenant(tenantId: string): Promise<AlertRoutingRuleRecord[]>;

  getIdempotencyRecord(
    tenantId: string,
    subject: string,
    endpoint: string,
    key: string
  ): Promise<IdempotencyRecord | undefined>;
  saveIdempotencyRecord(record: IdempotencyRecord): Promise<void>;
  pruneIdempotencyRecords(olderThanIso: string): Promise<number>;
}

export class FilePlatformStore implements PlatformStore {
  private state: PersistedState;
  private readonly dataProtectionService: DataProtectionService;
  private readonly filePath: string;

  constructor(filePath: string, dataProtectionService?: DataProtectionService) {
    this.filePath = filePath;
    this.dataProtectionService = dataProtectionService ?? new DataProtectionService();
    this.state = this.load();
  }

  async close(): Promise<void> {
    // File-backed store holds no external resources.
  }

  private load(): PersistedState {
    if (!existsSync(this.filePath)) {
      return structuredClone(defaultState);
    }

    const raw = readFileSync(this.filePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PersistedState>;
    const restoredActions = (parsed.actions ?? []).map((action) => ({
      ...action,
      input: this.dataProtectionService.restore<Record<string, unknown>>(action.input)
    }));
    const restoredSecurityEvents = (parsed.securityEvents ?? []).map((event) => ({
      ...event,
      payload: this.dataProtectionService.restore<Record<string, unknown>>(event.payload)
    }));
    const restoredSiemDeadLetters = (parsed.siemDeadLetters ?? []).map((deadLetter) => ({
      ...deadLetter,
      payload: this.dataProtectionService.restore<Record<string, unknown>>(deadLetter.payload)
    }));
    const restoredEvidenceNodes = (parsed.evidenceNodes ?? []).map((node) => ({
      ...node,
      payload: this.dataProtectionService.restore<Record<string, unknown>>(node.payload)
    }));
    return {
      actions: restoredActions,
      approvals: (parsed.approvals ?? []).map((approval) => normalizeApprovalRecord(approval)),
      approvalWorkflows: parsed.approvalWorkflows ?? [],
      receipts: parsed.receipts ?? [],
      policies: parsed.policies ?? [],
      alerts: parsed.alerts ?? [],
      tenants: parsed.tenants ?? [],
      tenantMembers: parsed.tenantMembers ?? [],
      securityEvents: restoredSecurityEvents,
      serviceAccounts: parsed.serviceAccounts ?? [],
      scimUsers: parsed.scimUsers ?? [],
      scimGroups: parsed.scimGroups ?? [],
      scimRoleMappings: parsed.scimRoleMappings ?? [],
      siemDeadLetters: restoredSiemDeadLetters,
      ledgerRetentionPolicies: parsed.ledgerRetentionPolicies ?? [],
      evidenceNodes: restoredEvidenceNodes,
      evidenceEdges: parsed.evidenceEdges ?? [],
      controlMappings: parsed.controlMappings ?? [],
      alertRoutingRules: parsed.alertRoutingRules ?? [],
      idempotencyRecords: parsed.idempotencyRecords ?? []
    };
  }

  private persist(): void {
    const folder = dirname(this.filePath);
    if (!existsSync(folder)) {
      mkdirSync(folder, { recursive: true });
    }
    const protectedState: PersistedState = {
      ...this.state,
      actions: this.state.actions.map((action) => ({
        ...action,
        input: this.dataProtectionService.protect(action.input) as Record<string, unknown>
      })),
      securityEvents: this.state.securityEvents.map((event) => ({
        ...event,
        payload: this.dataProtectionService.protect(event.payload) as Record<string, unknown>
      })),
      siemDeadLetters: this.state.siemDeadLetters.map((deadLetter) => ({
        ...deadLetter,
        payload: this.dataProtectionService.protect(deadLetter.payload) as Record<string, unknown>
      })),
      evidenceNodes: this.state.evidenceNodes.map((node) => ({
        ...node,
        payload: this.dataProtectionService.protect(node.payload) as Record<string, unknown>
      }))
    };
    writeFileSync(this.filePath, JSON.stringify(protectedState, null, 2), "utf8");
  }

  async getAction(actionId: string): Promise<ActionRecord | undefined> {
    return this.state.actions.find((action) => action.id === actionId);
  }

  async listActionsByTenant(tenantId: string): Promise<ActionRecord[]> {
    return this.state.actions.filter((action) => action.tenantId === tenantId);
  }

  async saveAction(action: ActionRecord): Promise<void> {
    const index = this.state.actions.findIndex((entry) => entry.id === action.id);
    if (index >= 0) {
      this.state.actions[index] = action;
    } else {
      this.state.actions.push(action);
    }
    this.persist();
  }

  async getApproval(approvalId: string): Promise<ApprovalRecord | undefined> {
    return this.state.approvals.find((approval) => approval.id === approvalId);
  }

  async getApprovalByAction(actionId: string): Promise<ApprovalRecord | undefined> {
    return this.state.approvals.find((approval) => approval.actionId === actionId);
  }

  async listApprovalsByTenant(tenantId: string, status?: ApprovalRecord["status"]): Promise<ApprovalRecord[]> {
    return this.state.approvals
      .filter((approval) => approval.tenantId === tenantId)
      .filter((approval) => (status ? approval.status === status : true))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  async saveApproval(approval: ApprovalRecord): Promise<void> {
    const index = this.state.approvals.findIndex((entry) => entry.id === approval.id);
    if (index >= 0) {
      this.state.approvals[index] = approval;
    } else {
      this.state.approvals.push(approval);
    }
    this.persist();
  }

  async saveApprovalWorkflow(workflow: ApprovalWorkflowRecord): Promise<void> {
    const index = this.state.approvalWorkflows.findIndex((entry) => entry.tenantId === workflow.tenantId);
    if (index >= 0) {
      this.state.approvalWorkflows[index] = workflow;
    } else {
      this.state.approvalWorkflows.push(workflow);
    }
    this.persist();
  }

  async getApprovalWorkflowByTenant(tenantId: string): Promise<ApprovalWorkflowRecord | undefined> {
    return this.state.approvalWorkflows.find((entry) => entry.tenantId === tenantId);
  }

  async saveReceipt(receipt: ActionReceipt): Promise<void> {
    const index = this.state.receipts.findIndex((entry) => entry.receiptId === receipt.receiptId);
    if (index >= 0) {
      this.state.receipts[index] = receipt;
    } else {
      this.state.receipts.push(receipt);
    }
    this.persist();
  }

  async getReceipt(receiptId: string): Promise<ActionReceipt | undefined> {
    return this.state.receipts.find((receipt) => receipt.receiptId === receiptId);
  }

  async listReceiptsByAction(actionId: string): Promise<ActionReceipt[]> {
    return this.state.receipts
      .filter((receipt) => receipt.actionId === actionId)
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  async listReceiptsByTenant(tenantId: string, limit = 200): Promise<ActionReceipt[]> {
    const safeLimit = Math.min(500, Math.max(1, limit));
    return this.state.receipts
      .filter((receipt) => receipt.tenantId === tenantId)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, safeLimit);
  }

  async savePolicy(policy: PolicyDocument): Promise<void> {
    const index = this.state.policies.findIndex((entry) => entry.id === policy.id);
    if (index >= 0) {
      this.state.policies[index] = policy;
    } else {
      this.state.policies.push(policy);
    }
    this.persist();
  }

  async getPolicy(policyId: string): Promise<PolicyDocument | undefined> {
    return this.state.policies.find((policy) => policy.id === policyId);
  }

  async listPoliciesByTenant(tenantId: string): Promise<PolicyDocument[]> {
    return this.state.policies.filter((policy) => policy.tenantId === tenantId);
  }

  async getPublishedPolicy(tenantId: string): Promise<PolicyDocument | undefined> {
    return this.state.policies.find((policy) => policy.tenantId === tenantId && policy.status === "published");
  }

  async saveAlert(alert: AlertRecord): Promise<void> {
    const index = this.state.alerts.findIndex((entry) => entry.id === alert.id);
    if (index >= 0) {
      this.state.alerts[index] = alert;
    } else {
      this.state.alerts.push(alert);
    }
    this.persist();
  }

  async saveTenant(tenant: TenantRecord): Promise<void> {
    const index = this.state.tenants.findIndex((entry) => entry.tenantId === tenant.tenantId);
    if (index >= 0) {
      this.state.tenants[index] = tenant;
    } else {
      this.state.tenants.push(tenant);
    }
    this.persist();
  }

  async getTenant(tenantId: string): Promise<TenantRecord | undefined> {
    return this.state.tenants.find((entry) => entry.tenantId === tenantId);
  }

  async listTenants(): Promise<TenantRecord[]> {
    return [...this.state.tenants].sort((a, b) => a.tenantId.localeCompare(b.tenantId));
  }

  async listAlertsByTenant(tenantId: string, limit = 100): Promise<AlertRecord[]> {
    const safeLimit = Math.min(500, Math.max(1, limit));
    return this.state.alerts
      .filter((alert) => alert.tenantId === tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, safeLimit);
  }

  async saveTenantMember(member: TenantMemberRecord): Promise<void> {
    const index = this.state.tenantMembers.findIndex(
      (entry) => entry.tenantId === member.tenantId && entry.subject === member.subject
    );
    if (index >= 0) {
      this.state.tenantMembers[index] = member;
    } else {
      this.state.tenantMembers.push(member);
    }
    this.persist();
  }

  async getTenantMember(tenantId: string, subject: string): Promise<TenantMemberRecord | undefined> {
    return this.state.tenantMembers.find((entry) => entry.tenantId === tenantId && entry.subject === subject);
  }

  async listTenantMembers(tenantId: string): Promise<TenantMemberRecord[]> {
    return this.state.tenantMembers
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => a.subject.localeCompare(b.subject));
  }

  async deleteTenantMember(tenantId: string, subject: string): Promise<boolean> {
    const before = this.state.tenantMembers.length;
    this.state.tenantMembers = this.state.tenantMembers.filter(
      (entry) => !(entry.tenantId === tenantId && entry.subject === subject)
    );
    const after = this.state.tenantMembers.length;
    if (after < before) {
      this.persist();
    }
    return after < before;
  }

  async saveSecurityEvent(event: SecurityEventRecord): Promise<void> {
    const index = this.state.securityEvents.findIndex((entry) => entry.id === event.id);
    if (index >= 0) {
      this.state.securityEvents[index] = event;
    } else {
      this.state.securityEvents.push(event);
    }
    this.persist();
  }

  async listSecurityEventsByTenant(tenantId: string, limit = 200): Promise<SecurityEventRecord[]> {
    const safeLimit = Math.min(500, Math.max(1, limit));
    return this.state.securityEvents
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => b.occurredAt.localeCompare(a.occurredAt))
      .slice(0, safeLimit);
  }

  async saveServiceAccount(account: ServiceAccountRecord): Promise<void> {
    const index = this.state.serviceAccounts.findIndex((entry) => entry.id === account.id);
    if (index >= 0) {
      this.state.serviceAccounts[index] = account;
    } else {
      this.state.serviceAccounts.push(account);
    }
    this.persist();
  }

  async getServiceAccount(accountId: string): Promise<ServiceAccountRecord | undefined> {
    return this.state.serviceAccounts.find((entry) => entry.id === accountId);
  }

  async listServiceAccountsByTenant(tenantId: string): Promise<ServiceAccountRecord[]> {
    return this.state.serviceAccounts
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async saveScimUser(user: ScimUserRecord): Promise<void> {
    const index = this.state.scimUsers.findIndex(
      (entry) => entry.tenantId === user.tenantId && entry.externalId === user.externalId
    );
    if (index >= 0) {
      this.state.scimUsers[index] = user;
    } else {
      this.state.scimUsers.push(user);
    }
    this.persist();
  }

  async listScimUsersByTenant(tenantId: string): Promise<ScimUserRecord[]> {
    return this.state.scimUsers
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => a.userName.localeCompare(b.userName));
  }

  async listScimUsersByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimUserRecord[]; total: number; page: number; pageSize: number }> {
    const all = await this.listScimUsersByTenant(tenantId);
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const offset = (safePage - 1) * safePageSize;
    return {
      items: all.slice(offset, offset + safePageSize),
      total: all.length,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async getScimUserByExternalId(tenantId: string, externalId: string): Promise<ScimUserRecord | undefined> {
    return this.state.scimUsers.find((entry) => entry.tenantId === tenantId && entry.externalId === externalId);
  }

  async saveScimGroup(group: ScimGroupRecord): Promise<void> {
    const index = this.state.scimGroups.findIndex(
      (entry) => entry.tenantId === group.tenantId && entry.externalId === group.externalId
    );
    if (index >= 0) {
      this.state.scimGroups[index] = group;
    } else {
      this.state.scimGroups.push(group);
    }
    this.persist();
  }

  async listScimGroupsByTenant(tenantId: string): Promise<ScimGroupRecord[]> {
    return this.state.scimGroups
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
  }

  async listScimGroupsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimGroupRecord[]; total: number; page: number; pageSize: number }> {
    const all = await this.listScimGroupsByTenant(tenantId);
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const offset = (safePage - 1) * safePageSize;
    return {
      items: all.slice(offset, offset + safePageSize),
      total: all.length,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveScimRoleMapping(mapping: ScimRoleMappingRecord): Promise<void> {
    const index = this.state.scimRoleMappings.findIndex(
      (entry) => entry.tenantId === mapping.tenantId && entry.groupDisplayName === mapping.groupDisplayName
    );
    if (index >= 0) {
      this.state.scimRoleMappings[index] = mapping;
    } else {
      this.state.scimRoleMappings.push(mapping);
    }
    this.persist();
  }

  async listScimRoleMappingsByTenant(tenantId: string): Promise<ScimRoleMappingRecord[]> {
    return this.state.scimRoleMappings
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => a.groupDisplayName.localeCompare(b.groupDisplayName));
  }

  async listScimRoleMappingsByTenantPaged(
    tenantId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScimRoleMappingRecord[]; total: number; page: number; pageSize: number }> {
    const all = await this.listScimRoleMappingsByTenant(tenantId);
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const offset = (safePage - 1) * safePageSize;
    return {
      items: all.slice(offset, offset + safePageSize),
      total: all.length,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveSiemDeadLetter(deadLetter: SiemDeadLetterRecord): Promise<void> {
    const index = this.state.siemDeadLetters.findIndex((entry) => entry.id === deadLetter.id);
    if (index >= 0) {
      this.state.siemDeadLetters[index] = deadLetter;
    } else {
      this.state.siemDeadLetters.push(deadLetter);
    }
    this.persist();
  }

  async getSiemDeadLetter(deadLetterId: string): Promise<SiemDeadLetterRecord | undefined> {
    return this.state.siemDeadLetters.find((entry) => entry.id === deadLetterId);
  }

  async getSiemDeadLetterForTenant(deadLetterId: string, tenantId: string): Promise<SiemDeadLetterRecord | undefined> {
    const deadLetter = await this.getSiemDeadLetter(deadLetterId);
    if (!deadLetter) {
      return undefined;
    }
    if (deadLetter.tenantId !== tenantId) {
      return undefined;
    }
    return deadLetter;
  }

  async listSiemDeadLettersPaged(
    tenantId: string,
    status: SiemDeadLetterRecord["status"] | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: SiemDeadLetterRecord[]; total: number; page: number; pageSize: number }> {
    const filtered =
      status === "all"
        ? this.state.siemDeadLetters.filter((entry) => entry.tenantId === tenantId)
        : this.state.siemDeadLetters.filter((entry) => entry.tenantId === tenantId && entry.status === status);
    const all = filtered.sort((a, b) => b.failedAt.localeCompare(a.failedAt));
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const offset = (safePage - 1) * safePageSize;
    return {
      items: all.slice(offset, offset + safePageSize),
      total: all.length,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveLedgerRetentionPolicy(policy: LedgerRetentionPolicyRecord): Promise<void> {
    const index = this.state.ledgerRetentionPolicies.findIndex((entry) => entry.tenantId === policy.tenantId);
    if (index >= 0) {
      this.state.ledgerRetentionPolicies[index] = policy;
    } else {
      this.state.ledgerRetentionPolicies.push(policy);
    }
    this.persist();
  }

  async getLedgerRetentionPolicy(tenantId: string): Promise<LedgerRetentionPolicyRecord | undefined> {
    return this.state.ledgerRetentionPolicies.find((entry) => entry.tenantId === tenantId);
  }

  async listLedgerRetentionPolicies(): Promise<LedgerRetentionPolicyRecord[]> {
    return [...this.state.ledgerRetentionPolicies].sort((a, b) => a.tenantId.localeCompare(b.tenantId));
  }

  async saveEvidenceNode(node: EvidenceGraphNodeRecord): Promise<void> {
    const index = this.state.evidenceNodes.findIndex(
      (entry) => entry.tenantId === node.tenantId && entry.nodeType === node.nodeType && entry.refId === node.refId
    );
    if (index >= 0) {
      this.state.evidenceNodes[index] = node;
    } else {
      this.state.evidenceNodes.push(node);
    }
    this.persist();
  }

  async getEvidenceNodeByRef(
    tenantId: string,
    nodeType: EvidenceNodeType,
    refId: string
  ): Promise<EvidenceGraphNodeRecord | undefined> {
    return this.state.evidenceNodes.find(
      (entry) => entry.tenantId === tenantId && entry.nodeType === nodeType && entry.refId === refId
    );
  }

  async listEvidenceNodesByTenantPaged(
    tenantId: string,
    nodeType: EvidenceNodeType | "all",
    page: number,
    pageSize: number
  ): Promise<{ items: EvidenceGraphNodeRecord[]; total: number; page: number; pageSize: number }> {
    const filtered =
      nodeType === "all"
        ? this.state.evidenceNodes.filter((entry) => entry.tenantId === tenantId)
        : this.state.evidenceNodes.filter((entry) => entry.tenantId === tenantId && entry.nodeType === nodeType);
    const all = filtered.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const offset = (safePage - 1) * safePageSize;
    return {
      items: all.slice(offset, offset + safePageSize),
      total: all.length,
      page: safePage,
      pageSize: safePageSize
    };
  }

  async saveEvidenceEdge(edge: EvidenceGraphEdgeRecord): Promise<void> {
    const exists = this.state.evidenceEdges.some(
      (entry) =>
        entry.tenantId === edge.tenantId &&
        entry.fromNodeId === edge.fromNodeId &&
        entry.toNodeId === edge.toNodeId &&
        entry.relation === edge.relation
    );
    if (!exists) {
      this.state.evidenceEdges.push(edge);
      this.persist();
    }
  }

  async listEvidenceEdgesByTenant(tenantId: string): Promise<EvidenceGraphEdgeRecord[]> {
    return this.state.evidenceEdges
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async saveControlMapping(mapping: ControlMappingRecord): Promise<void> {
    const index = this.state.controlMappings.findIndex(
      (entry) =>
        entry.tenantId === mapping.tenantId &&
        entry.framework === mapping.framework &&
        entry.controlId === mapping.controlId
    );
    if (index >= 0) {
      this.state.controlMappings[index] = mapping;
    } else {
      this.state.controlMappings.push(mapping);
    }
    this.persist();
  }

  async listControlMappingsByTenant(
    tenantId: string,
    framework?: ControlMappingRecord["framework"]
  ): Promise<ControlMappingRecord[]> {
    return this.state.controlMappings
      .filter((entry) => entry.tenantId === tenantId)
      .filter((entry) => (framework ? entry.framework === framework : true))
      .sort((a, b) => a.controlId.localeCompare(b.controlId));
  }

  async saveAlertRoutingRule(rule: AlertRoutingRuleRecord): Promise<void> {
    const index = this.state.alertRoutingRules.findIndex(
      (entry) => entry.tenantId === rule.tenantId && entry.severity === rule.severity
    );
    if (index >= 0) {
      this.state.alertRoutingRules[index] = rule;
    } else {
      this.state.alertRoutingRules.push(rule);
    }
    this.persist();
  }

  async listAlertRoutingRulesByTenant(tenantId: string): Promise<AlertRoutingRuleRecord[]> {
    return this.state.alertRoutingRules
      .filter((entry) => entry.tenantId === tenantId)
      .sort((a, b) => a.severity.localeCompare(b.severity));
  }

  async getIdempotencyRecord(
    tenantId: string,
    subject: string,
    endpoint: string,
    key: string
  ): Promise<IdempotencyRecord | undefined> {
    return this.state.idempotencyRecords.find(
      (entry) =>
        entry.tenantId === tenantId &&
        entry.subject === subject &&
        entry.endpoint === endpoint &&
        entry.key === key
    );
  }

  async saveIdempotencyRecord(record: IdempotencyRecord): Promise<void> {
    const index = this.state.idempotencyRecords.findIndex((entry) => entry.id === record.id);
    if (index >= 0) {
      this.state.idempotencyRecords[index] = record;
    } else {
      this.state.idempotencyRecords.push(record);
    }
    this.persist();
  }

  async pruneIdempotencyRecords(olderThanIso: string): Promise<number> {
    const cutoff = Date.parse(olderThanIso);
    if (Number.isNaN(cutoff)) {
      return 0;
    }
    const before = this.state.idempotencyRecords.length;
    this.state.idempotencyRecords = this.state.idempotencyRecords.filter((entry) => {
      const createdAt = Date.parse(entry.createdAt);
      return Number.isNaN(createdAt) ? true : createdAt >= cutoff;
    });
    const pruned = before - this.state.idempotencyRecords.length;
    if (pruned > 0) {
      this.persist();
    }
    return pruned;
  }
}
