import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import type { ActionRecord, ActionRequest, ApprovalRecord, PolicyEvaluation, RiskContext } from "../types/domain.js";
import { PlatformStore } from "../store/platform-store.js";
import { ApprovalService } from "./approval-service.js";
import { AlertService } from "./alert-service.js";
import { ExecutionService } from "./execution-service.js";
import { PolicyService, decisionToState } from "./policy-service.js";
import { ReceiptService } from "./receipt-service.js";
import { RiskService } from "./risk-service.js";
import type { ExecutionBackplane } from "../backplane/execution-backplane.js";

export interface ActionResponse {
  actionId: string;
  state: string;
  receiptId: string;
  approvalId?: string;
  stepUpRequired?: boolean;
  approvalProgress?: {
    currentStageIndex: number;
    totalStages: number;
    currentStageName: string | null;
  };
  output?: Record<string, unknown>;
  error?: string | null;
}

export class ActionService {
  constructor(
    private readonly store: PlatformStore,
    private readonly executionBackplane: ExecutionBackplane | null,
    private readonly policyService: PolicyService,
    private readonly approvalService: ApprovalService,
    private readonly executionService: ExecutionService,
    private readonly riskService: RiskService,
    private readonly receiptService: ReceiptService,
    private readonly alertService: AlertService
  ) {}

  async submitAction(request: ActionRequest, requestId: string): Promise<ActionResponse> {
    const action = this.createActionRecord(request);
    await this.store.saveAction(action);

    const risk = this.riskService.evaluate(action.resource);
    const evaluation = await this.policyService.evaluate(action, risk);
    action.policyDecision = evaluation.decision;
    action.policySetId = evaluation.policySetId;
    action.policyVersion = evaluation.policyVersion;
    action.policyRuleIds = evaluation.ruleIds;
    action.policyRationale = evaluation.rationale;
    action.updatedAt = nowIso();
    await this.store.saveAction(action);

    const requestedReceipt = await this.createReceipt(action, "action.requested", evaluation, risk, requestId);
    await this.linkReceipt(action, requestedReceipt.receiptId);

    const decisionState = decisionToState(evaluation.decision);
    if (decisionState === "denied") {
      await this.transitionState(action, "denied");
      const deniedReceipt = await this.createReceipt(action, "action.denied", evaluation, risk, requestId);
      await this.linkReceipt(action, deniedReceipt.receiptId);
      await this.alertService.evaluateActionOutcome(action, risk);
      return {
        actionId: action.id,
        state: action.state,
        receiptId: deniedReceipt.receiptId,
        error: "Action denied by policy."
      };
    }

    if (decisionState === "quarantined") {
      await this.transitionState(action, "quarantined");
      const quarantinedReceipt = await this.createReceipt(
        action,
        "action.quarantined",
        evaluation,
        risk,
        requestId
      );
      await this.linkReceipt(action, quarantinedReceipt.receiptId);
      await this.alertService.evaluateActionOutcome(action, risk);
      return {
        actionId: action.id,
        state: action.state,
        receiptId: quarantinedReceipt.receiptId,
        error: "Action quarantined by policy."
      };
    }

    if (decisionState === "approval_required") {
      const approval = await this.approvalService.createPendingApproval(
        action.id,
        action.tenantId,
        risk.tier === "critical"
      );
      action.approvalId = approval.id;
      await this.transitionState(action, "approval_required");
      const approvalReceipt = await this.createReceipt(
        action,
        "action.approval_required",
        evaluation,
        risk,
        requestId
      );
      await this.linkReceipt(action, approvalReceipt.receiptId);
      return {
        actionId: action.id,
        state: action.state,
        receiptId: approvalReceipt.receiptId,
        approvalId: approval.id,
        stepUpRequired: approval.requiresStepUp,
        approvalProgress: this.approvalProgress(approval)
      };
    }

    await this.transitionState(action, "approved");
    const approvedReceipt = await this.createReceipt(action, "action.approved", evaluation, risk, requestId);
    await this.linkReceipt(action, approvedReceipt.receiptId);

    if (this.executionBackplane) {
      await this.executionBackplane.enqueue({ tenantId: action.tenantId, actionId: action.id, requestId });
      return {
        actionId: action.id,
        state: action.state,
        receiptId: approvedReceipt.receiptId
      };
    }

    return this.executeAction(action, evaluation, risk, requestId);
  }

  async handleApprovalDecision(
    approvalId: string,
    decision: "approve" | "reject",
    approverId: string,
    reason: string,
    requestId: string,
    stepUpCode?: string
  ): Promise<ActionResponse> {
    const approval = await this.approvalService.recordDecision(approvalId, decision, approverId, reason, stepUpCode);
    const action = await this.store.getAction(approval.actionId);
    if (!action) {
      throw new Error(`Action not found for approval ${approvalId}`);
    }

    const risk = this.riskService.evaluate(action.resource);
    const evaluation = this.currentPolicyEvaluation(action);

    if (decision === "reject") {
      await this.transitionState(action, "denied");
      action.lastError = `Approval rejected by ${approverId}: ${reason}`;
      await this.store.saveAction(action);
      const deniedReceipt = await this.createReceipt(action, "action.denied", evaluation, risk, requestId);
      await this.linkReceipt(action, deniedReceipt.receiptId);
      await this.alertService.evaluateActionOutcome(action, risk);
      return {
        actionId: action.id,
        state: action.state,
        receiptId: deniedReceipt.receiptId,
        error: action.lastError
      };
    }

    if (approval.status === "pending") {
      const lastReceiptId = action.receiptIds[action.receiptIds.length - 1];
      return {
        actionId: action.id,
        state: action.state,
        receiptId: lastReceiptId ?? "",
        approvalId: approval.id,
        stepUpRequired: approval.requiresStepUp,
        approvalProgress: this.approvalProgress(approval)
      };
    }

    await this.transitionState(action, "approved");
    const approvedReceipt = await this.createReceipt(action, "action.approved", evaluation, risk, requestId);
    await this.linkReceipt(action, approvedReceipt.receiptId);
    if (this.executionBackplane) {
      await this.executionBackplane.enqueue({ tenantId: action.tenantId, actionId: action.id, requestId });
      return {
        actionId: action.id,
        state: action.state,
        receiptId: approvedReceipt.receiptId
      };
    }

    return this.executeAction(action, evaluation, risk, requestId);
  }

  async getAction(actionId: string): Promise<ActionRecord | undefined> {
    return this.store.getAction(actionId);
  }

  async executeApprovedAction(actionId: string, requestId: string): Promise<ActionResponse> {
    const action = await this.store.getAction(actionId);
    if (!action) {
      throw new Error(`Action not found: ${actionId}`);
    }

    const lastReceiptId = action.receiptIds[action.receiptIds.length - 1] ?? "";
    if (action.state === "executed") {
      return { actionId: action.id, state: action.state, receiptId: lastReceiptId };
    }
    if (action.state === "failed") {
      return { actionId: action.id, state: action.state, receiptId: lastReceiptId, error: action.lastError };
    }
    if (action.state !== "approved") {
      return {
        actionId: action.id,
        state: action.state,
        receiptId: lastReceiptId,
        error: `Action is not executable from state: ${action.state}`
      };
    }

    const risk = this.riskService.evaluate(action.resource);
    const evaluation = this.currentPolicyEvaluation(action);
    return this.executeAction(action, evaluation, risk, requestId);
  }

  private createActionRecord(request: ActionRequest): ActionRecord {
    const now = nowIso();
    return {
      id: createId("act"),
      tenantId: request.tenantId,
      state: "requested",
      actor: {
        userId: request.userContext?.userId ?? null,
        agentId: request.agentId,
        serviceId: "oars-gateway",
        delegationChain: [request.userContext?.userId ?? "system", request.agentId, "oars-gateway"]
      },
      context: {
        ...request.context,
        // Ensure policy evaluation is anchored to platform time unless explicitly simulated elsewhere.
        requestedAt: now
      },
      resource: request.resource,
      input: request.input,
      approvalId: null,
      policyDecision: null,
      policySetId: null,
      policyVersion: null,
      policyRuleIds: [],
      policyRationale: null,
      lastError: null,
      createdAt: now,
      updatedAt: now,
      receiptIds: []
    };
  }

  private async transitionState(action: ActionRecord, nextState: ActionRecord["state"]): Promise<void> {
    action.state = nextState;
    action.updatedAt = nowIso();
    await this.store.saveAction(action);
  }

  private async linkReceipt(action: ActionRecord, receiptId: string): Promise<void> {
    action.receiptIds.push(receiptId);
    action.updatedAt = nowIso();
    await this.store.saveAction(action);
  }

  private currentPolicyEvaluation(action: ActionRecord): PolicyEvaluation {
    return {
      decision: action.policyDecision ?? "allow",
      policySetId: action.policySetId ?? "unknown",
      policyVersion: action.policyVersion ?? "unknown",
      ruleIds: action.policyRuleIds,
      rationale: action.policyRationale ?? "No stored rationale."
    };
  }

  private approvalProgress(approval: ApprovalRecord): {
    currentStageIndex: number;
    totalStages: number;
    currentStageName: string | null;
  } {
    const currentStage = approval.stages[approval.currentStageIndex];
    return {
      currentStageIndex: approval.currentStageIndex,
      totalStages: approval.stages.length,
      currentStageName: currentStage?.name ?? null
    };
  }

  private async executeAction(
    action: ActionRecord,
    evaluation: PolicyEvaluation,
    risk: RiskContext,
    requestId: string
  ): Promise<ActionResponse> {
    const result = await this.executionService.execute(action);
    if (result.success) {
      await this.transitionState(action, "executed");
      const executedReceipt = await this.createReceipt(action, "action.executed", evaluation, risk, requestId);
      await this.linkReceipt(action, executedReceipt.receiptId);
      await this.alertService.evaluateActionOutcome(action, risk);
      return {
        actionId: action.id,
        state: action.state,
        receiptId: executedReceipt.receiptId,
        output: result.output
      };
    }

    await this.transitionState(action, "failed");
    action.lastError = result.error;
    await this.store.saveAction(action);
    const failedReceipt = await this.createReceipt(action, "action.failed", evaluation, risk, requestId);
    await this.linkReceipt(action, failedReceipt.receiptId);
    await this.alertService.evaluateActionOutcome(action, risk);
    return {
      actionId: action.id,
      state: action.state,
      receiptId: failedReceipt.receiptId,
      error: result.error
    };
  }

  private createReceipt(
    action: ActionRecord,
    type: Parameters<ReceiptService["createReceipt"]>[0]["type"],
    evaluation: PolicyEvaluation,
    risk: RiskContext,
    requestId: string
  ): ReturnType<ReceiptService["createReceipt"]> {
    return this.receiptService.createReceipt({
      action,
      type,
      policySetId: evaluation.policySetId,
      policyVersion: evaluation.policyVersion,
      policyDecision: evaluation.decision,
      policyRuleIds: evaluation.ruleIds,
      policyRationale: evaluation.rationale,
      risk,
      requestId
    });
  }
}
