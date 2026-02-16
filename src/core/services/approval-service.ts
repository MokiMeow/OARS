import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import type {
  ApprovalDecisionRecord,
  ApprovalRecord,
  ApprovalStageRecord,
  ApprovalWorkflowRecord
} from "../types/domain.js";
import { PlatformStore } from "../store/platform-store.js";

interface ApprovalStageInput {
  name: string;
  mode: "serial" | "parallel";
  requiredApprovals: number;
  approverIds: string[];
  slaSeconds?: number | null | undefined;
  escalateTo?: string[] | undefined;
}

function defaultStages(): ApprovalStageRecord[] {
  return [
    {
      id: createId("apr_stage"),
      name: "Primary Approval",
      mode: "serial",
      requiredApprovals: 1,
      approverIds: [],
      slaSeconds: null,
      escalateTo: []
    }
  ];
}

function computeStageDeadline(stage: ApprovalStageRecord, startedAt: string): string | null {
  if (!stage.slaSeconds || stage.slaSeconds <= 0) {
    return null;
  }
  const ms = Date.parse(startedAt);
  if (Number.isNaN(ms)) {
    return null;
  }
  return new Date(ms + stage.slaSeconds * 1000).toISOString();
}

function normalizeStageInput(input: ApprovalStageInput): ApprovalStageRecord {
  if (input.mode === "serial" && input.requiredApprovals !== 1) {
    throw new Error("Serial approval stages must use requiredApprovals = 1.");
  }
  const approverIds = [...new Set(input.approverIds)].sort((a, b) => a.localeCompare(b));
  if (approverIds.length > 0 && input.requiredApprovals > approverIds.length) {
    throw new Error("Stage requiredApprovals cannot exceed number of scoped approverIds.");
  }
  const escalateTo = [...new Set(input.escalateTo ?? [])].sort((a, b) => a.localeCompare(b));
  return {
    id: createId("apr_stage"),
    name: input.name,
    mode: input.mode,
    requiredApprovals: Math.max(1, input.requiredApprovals),
    approverIds,
    slaSeconds: input.slaSeconds ?? null,
    escalateTo
  };
}

const DEFAULT_STEP_UP_SECRET = "stepup_dev_code";

export class ApprovalService {
  constructor(
    private readonly store: PlatformStore,
    private readonly stepUpSecret = process.env.OARS_APPROVAL_STEP_UP_SECRET ?? DEFAULT_STEP_UP_SECRET
  ) {
    const allowInsecureDefaults =
      process.env.OARS_ALLOW_INSECURE_DEFAULTS === "true" || process.env.OARS_ALLOW_INSECURE_DEFAULTS === "1";
    if (process.env.NODE_ENV === "production" && !allowInsecureDefaults) {
      if (this.stepUpSecret === DEFAULT_STEP_UP_SECRET) {
        throw new Error(
          "OARS_APPROVAL_STEP_UP_SECRET must be set in production (development default is not allowed)."
        );
      }
    }
  }

  async upsertTenantWorkflow(tenantId: string, stages: ApprovalStageInput[], actor: string): Promise<ApprovalWorkflowRecord> {
    if (stages.length === 0) {
      throw new Error("Approval workflow must include at least one stage.");
    }

    const normalizedStages = stages.map((stage) => normalizeStageInput(stage));
    const existing = await this.store.getApprovalWorkflowByTenant(tenantId);
    if (existing) {
      existing.stages = normalizedStages;
      existing.updatedAt = nowIso();
      await this.store.saveApprovalWorkflow(existing);
      return existing;
    }

    const workflow: ApprovalWorkflowRecord = {
      id: createId("apr_wf"),
      tenantId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      createdBy: actor,
      stages: normalizedStages
    };
    await this.store.saveApprovalWorkflow(workflow);
    return workflow;
  }

  async getTenantWorkflow(tenantId: string): Promise<ApprovalWorkflowRecord> {
    const existing = await this.store.getApprovalWorkflowByTenant(tenantId);
    if (existing) {
      existing.stages = existing.stages.map((stage) => ({
        ...stage,
        approverIds: stage.approverIds ?? [],
        slaSeconds: stage.slaSeconds ?? null,
        escalateTo: stage.escalateTo ?? []
      }));
      return existing;
    }
    return {
      id: "default_workflow",
      tenantId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      createdBy: "system",
      stages: defaultStages()
    };
  }

  async createPendingApproval(actionId: string, tenantId: string, requiresStepUp = false): Promise<ApprovalRecord> {
    const workflow = await this.getTenantWorkflow(tenantId);
    const createdAt = nowIso();
    const initialStage = workflow.stages[0];
    const approval: ApprovalRecord = {
      id: createId("apr"),
      actionId,
      tenantId,
      status: "pending",
      requiresStepUp,
      currentStageIndex: 0,
      stages: workflow.stages.map((stage) => ({
        ...stage,
        approverIds: [...stage.approverIds],
        escalateTo: [...stage.escalateTo]
      })),
      stageStartedAt: createdAt,
      stageDeadlineAt: initialStage ? computeStageDeadline(initialStage, createdAt) : null,
      escalatedStageIds: [],
      createdAt,
      updatedAt: createdAt,
      decisions: []
    };
    await this.store.saveApproval(approval);
    return approval;
  }

  async getApproval(approvalId: string): Promise<ApprovalRecord | undefined> {
    return this.store.getApproval(approvalId);
  }

  async recordDecision(
    approvalId: string,
    decision: ApprovalDecisionRecord["decision"],
    approverId: string,
    reason: string,
    stepUpCode?: string
  ): Promise<ApprovalRecord> {
    const approval = await this.store.getApproval(approvalId);
    if (!approval) {
      throw new Error(`Approval not found: ${approvalId}`);
    }

    if (approval.status !== "pending") {
      throw new Error(`Approval is not pending: ${approvalId}`);
    }

    const currentStage = approval.stages[approval.currentStageIndex];
    if (!currentStage) {
      throw new Error(`Approval stage not found: ${approvalId} stage ${approval.currentStageIndex}`);
    }

    if (currentStage.approverIds.length > 0 && !currentStage.approverIds.includes(approverId)) {
      throw new Error(`Approver is not authorized for current stage: ${approverId}`);
    }

    const duplicate = approval.decisions.some(
      (entry) => entry.stageId === currentStage.id && entry.approverId === approverId
    );
    if (duplicate) {
      throw new Error("Approver already submitted a decision for the current stage.");
    }

    if (decision === "approve" && approval.requiresStepUp && stepUpCode !== this.stepUpSecret) {
      throw new Error("Step-up authentication required for critical approval.");
    }

    approval.decisions.push({
      decision,
      approverId,
      reason,
      stageId: currentStage.id,
      decidedAt: nowIso()
    });

    if (decision === "reject") {
      approval.status = "rejected";
      approval.stageDeadlineAt = null;
      approval.updatedAt = nowIso();
      await this.store.saveApproval(approval);
      return approval;
    }

    const stageApprovals = approval.decisions.filter(
      (entry) => entry.stageId === currentStage.id && entry.decision === "approve"
    ).length;
    if (stageApprovals < currentStage.requiredApprovals) {
      approval.status = "pending";
      approval.updatedAt = nowIso();
      await this.store.saveApproval(approval);
      return approval;
    }

    if (approval.currentStageIndex < approval.stages.length - 1) {
      approval.currentStageIndex += 1;
      approval.stageStartedAt = nowIso();
      const nextStage = approval.stages[approval.currentStageIndex];
      approval.stageDeadlineAt = nextStage ? computeStageDeadline(nextStage, approval.stageStartedAt) : null;
      approval.status = "pending";
      approval.updatedAt = nowIso();
      await this.store.saveApproval(approval);
      return approval;
    }

    approval.status = "approved";
    approval.stageDeadlineAt = null;
    approval.updatedAt = nowIso();
    await this.store.saveApproval(approval);
    return approval;
  }

  async scanForEscalations(tenantId: string, now = nowIso()): Promise<Array<{
    approvalId: string;
    actionId: string;
    tenantId: string;
    stageId: string;
    stageName: string;
    escalateTo: string[];
    overdueSeconds: number;
  }>> {
    const nowMs = Date.parse(now);
    if (Number.isNaN(nowMs)) {
      throw new Error("Invalid escalation scan timestamp.");
    }

    const pendingApprovals = await this.store.listApprovalsByTenant(tenantId, "pending");
    const escalations: Array<{
      approvalId: string;
      actionId: string;
      tenantId: string;
      stageId: string;
      stageName: string;
      escalateTo: string[];
      overdueSeconds: number;
    }> = [];

    for (const approval of pendingApprovals) {
      if (!approval.stageDeadlineAt) {
        continue;
      }
      const stage = approval.stages[approval.currentStageIndex];
      if (!stage) {
        continue;
      }
      if (approval.escalatedStageIds.includes(stage.id)) {
        continue;
      }

      const deadlineMs = Date.parse(approval.stageDeadlineAt);
      if (Number.isNaN(deadlineMs) || nowMs <= deadlineMs) {
        continue;
      }

      const overdueSeconds = Math.floor((nowMs - deadlineMs) / 1000);
      approval.escalatedStageIds.push(stage.id);
      approval.updatedAt = nowIso();
      await this.store.saveApproval(approval);
      escalations.push({
        approvalId: approval.id,
        actionId: approval.actionId,
        tenantId: approval.tenantId,
        stageId: stage.id,
        stageName: stage.name,
        escalateTo: [...stage.escalateTo],
        overdueSeconds
      });
    }

    return escalations;
  }
}
