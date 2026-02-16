import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { ActionReceipt, EvidenceGraphNodeRecord, EvidenceNodeType } from "../types/domain.js";

export class EvidenceGraphService {
  constructor(private readonly store: PlatformStore) {}

  async ingestReceipt(receipt: ActionReceipt): Promise<void> {
    const actionNode = await this.upsertNode(receipt.tenantId, "action", receipt.actionId, {
      actionId: receipt.actionId,
      lastReceiptType: receipt.type,
      lastReceiptAt: receipt.timestamp
    });

    const receiptNode = await this.upsertNode(receipt.tenantId, "receipt", receipt.receiptId, {
      receiptId: receipt.receiptId,
      actionId: receipt.actionId,
      type: receipt.type,
      decision: receipt.policy.decision,
      timestamp: receipt.timestamp
    });

    const policyNode = await this.upsertNode(
      receipt.tenantId,
      "policy_version",
      `${receipt.policy.policySetId}:${receipt.policy.policyVersion}`,
      {
        policySetId: receipt.policy.policySetId,
        policyVersion: receipt.policy.policyVersion,
        decision: receipt.policy.decision
      }
    );

    const actorRef = receipt.actor.userId ? `user:${receipt.actor.userId}` : `agent:${receipt.actor.agentId}`;
    const actorNode = await this.upsertNode(receipt.tenantId, "actor", actorRef, {
      userId: receipt.actor.userId,
      agentId: receipt.actor.agentId,
      serviceId: receipt.actor.serviceId,
      delegationChain: receipt.actor.delegationChain
    });

    await this.link(receipt.tenantId, actionNode.id, receiptNode.id, "HAS_RECEIPT");
    await this.link(receipt.tenantId, receiptNode.id, policyNode.id, "EVALUATED_BY_POLICY");
    await this.link(receipt.tenantId, receiptNode.id, actorNode.id, "ACTED_BY");

    if (receipt.type === "action.approved") {
      const approvalNode = await this.upsertNode(
        receipt.tenantId,
        "approval_decision",
        `${receipt.actionId}:${receipt.timestamp}`,
        {
          actionId: receipt.actionId,
          approvedAt: receipt.timestamp
        }
      );
      await this.link(receipt.tenantId, receiptNode.id, approvalNode.id, "RECORDED_APPROVAL");
    }
  }

  async ingestEvidenceBundle(input: {
    bundleId: string;
    tenantId: string;
    framework: "eu_ai_act" | "iso_42001" | "soc2";
    generatedAt: string;
    bundleHash: string;
    receiptIds: string[];
  }): Promise<void> {
    const bundleNode = await this.upsertNode(input.tenantId, "evidence_bundle", input.bundleId, {
      bundleId: input.bundleId,
      framework: input.framework,
      generatedAt: input.generatedAt,
      bundleHash: input.bundleHash,
      receiptCount: input.receiptIds.length
    });

    for (const receiptId of input.receiptIds) {
      const receiptNode = await this.store.getEvidenceNodeByRef(input.tenantId, "receipt", receiptId);
      if (receiptNode) {
        await this.link(input.tenantId, bundleNode.id, receiptNode.id, "BUNDLE_INCLUDES");
      }
    }
  }

  async listNodes(tenantId: string, nodeType: EvidenceNodeType | "all", page = 1, pageSize = 100) {
    return this.store.listEvidenceNodesByTenantPaged(tenantId, nodeType, page, pageSize);
  }

  async snapshot(tenantId: string): Promise<{
    tenantId: string;
    nodeCounts: Record<string, number>;
    edgeCount: number;
    generatedAt: string;
  }> {
    const nodes = (await this.store.listEvidenceNodesByTenantPaged(tenantId, "all", 1, 100_000)).items;
    const counts: Record<string, number> = {};
    for (const node of nodes) {
      counts[node.nodeType] = (counts[node.nodeType] ?? 0) + 1;
    }
    const edges = await this.store.listEvidenceEdgesByTenant(tenantId);
    return {
      tenantId,
      nodeCounts: counts,
      edgeCount: edges.length,
      generatedAt: nowIso()
    };
  }

  private async upsertNode(
    tenantId: string,
    nodeType: EvidenceNodeType,
    refId: string,
    payload: Record<string, unknown>
  ): Promise<EvidenceGraphNodeRecord> {
    const existing = await this.store.getEvidenceNodeByRef(tenantId, nodeType, refId);
    if (existing) {
      existing.payload = payload;
      existing.updatedAt = nowIso();
      await this.store.saveEvidenceNode(existing);
      return existing;
    }

    const node: EvidenceGraphNodeRecord = {
      id: createId("evn"),
      tenantId,
      nodeType,
      refId,
      payload,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    await this.store.saveEvidenceNode(node);
    return node;
  }

  private async link(tenantId: string, fromNodeId: string, toNodeId: string, relation: string): Promise<void> {
    await this.store.saveEvidenceEdge({
      id: createId("eve"),
      tenantId,
      fromNodeId,
      toNodeId,
      relation,
      createdAt: nowIso()
    });
  }
}
