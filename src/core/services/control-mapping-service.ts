import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { ControlMappingRecord, EvidenceNodeType, PolicyDecision } from "../types/domain.js";
import { EvidenceGraphService } from "./evidence-graph-service.js";

function normalizeStringArray(values: unknown): string[] | undefined {
  if (!Array.isArray(values)) {
    return undefined;
  }
  const normalized = values.filter((value): value is string => typeof value === "string" && value.trim().length > 0);
  if (normalized.length === 0) {
    return undefined;
  }
  return [...new Set(normalized.map((value) => value.trim()))].sort((a, b) => a.localeCompare(b));
}

function normalizeDecisionArray(values: unknown): PolicyDecision[] | undefined {
  if (!Array.isArray(values)) {
    return undefined;
  }
  const allowed: PolicyDecision[] = ["allow", "deny", "approve", "quarantine"];
  const normalized = values.filter((value): value is PolicyDecision => allowed.includes(value as PolicyDecision));
  if (normalized.length === 0) {
    return undefined;
  }
  return [...new Set(normalized)].sort((a, b) => a.localeCompare(b));
}

function normalizeReceiptFilters(
  filters: ControlMappingRecord["receiptFilters"]
): ControlMappingRecord["receiptFilters"] | undefined {
  if (!filters) {
    return undefined;
  }
  const toolIds = normalizeStringArray(filters.toolIds);
  const operations = normalizeStringArray(filters.operations);
  const actorUserIds = normalizeStringArray(filters.actorUserIds);
  const actorAgentIds = normalizeStringArray(filters.actorAgentIds);
  const policyRuleIds = normalizeStringArray(filters.policyRuleIds);
  const policyVersions = normalizeStringArray(filters.policyVersions);
  const policyDecisions = normalizeDecisionArray(filters.policyDecisions);

  const hasAny =
    Boolean(toolIds) ||
    Boolean(operations) ||
    Boolean(actorUserIds) ||
    Boolean(actorAgentIds) ||
    Boolean(policyRuleIds) ||
    Boolean(policyVersions) ||
    Boolean(policyDecisions);
  if (!hasAny) {
    return undefined;
  }

  return {
    ...(toolIds ? { toolIds } : {}),
    ...(operations ? { operations } : {}),
    ...(policyDecisions ? { policyDecisions } : {}),
    ...(actorUserIds ? { actorUserIds } : {}),
    ...(actorAgentIds ? { actorAgentIds } : {}),
    ...(policyRuleIds ? { policyRuleIds } : {}),
    ...(policyVersions ? { policyVersions } : {})
  };
}

export class ControlMappingService {
  constructor(
    private readonly store: PlatformStore,
    private readonly evidenceGraphService: EvidenceGraphService
  ) {}

  async upsertMapping(input: {
    tenantId: string;
    framework: ControlMappingRecord["framework"];
    controlId: string;
    controlDescription: string;
    requiredNodeTypes: EvidenceNodeType[];
    receiptFilters?: ControlMappingRecord["receiptFilters"] | undefined;
    actor: string;
  }): Promise<ControlMappingRecord> {
    const existing = (await this.store.listControlMappingsByTenant(input.tenantId, input.framework)).find(
      (entry) => entry.controlId === input.controlId
    );
    const requiredNodeTypes = [...new Set(input.requiredNodeTypes)].sort((a, b) => a.localeCompare(b));
    const receiptFilters = normalizeReceiptFilters(input.receiptFilters);
    if (existing) {
      existing.controlDescription = input.controlDescription;
      existing.requiredNodeTypes = requiredNodeTypes;
      existing.receiptFilters = receiptFilters;
      existing.updatedAt = nowIso();
      await this.store.saveControlMapping(existing);
      return existing;
    }

    const mapping: ControlMappingRecord = {
      id: createId("ctl"),
      tenantId: input.tenantId,
      framework: input.framework,
      controlId: input.controlId,
      controlDescription: input.controlDescription,
      requiredNodeTypes,
      ...(receiptFilters ? { receiptFilters } : {}),
      createdAt: nowIso(),
      updatedAt: nowIso(),
      createdBy: input.actor
    };
    await this.store.saveControlMapping(mapping);
    return mapping;
  }

  async listMappings(tenantId: string, framework?: ControlMappingRecord["framework"]): Promise<ControlMappingRecord[]> {
    return this.store.listControlMappingsByTenant(tenantId, framework);
  }

  async scanCoverage(tenantId: string, framework: ControlMappingRecord["framework"]): Promise<{
    tenantId: string;
    framework: ControlMappingRecord["framework"];
    totalControls: number;
    coveredControls: number;
    missingControls: Array<{
      controlId: string;
      controlDescription: string;
      missingNodeTypes: EvidenceNodeType[];
    }>;
    generatedAt: string;
  }> {
    const mappings = await this.listMappings(tenantId, framework);
    const snapshot = await this.evidenceGraphService.snapshot(tenantId);
    const missingControls: Array<{
      controlId: string;
      controlDescription: string;
      missingNodeTypes: EvidenceNodeType[];
    }> = [];

    for (const mapping of mappings) {
      const missingNodeTypes = mapping.requiredNodeTypes.filter((nodeType) => (snapshot.nodeCounts[nodeType] ?? 0) === 0);
      if (missingNodeTypes.length > 0) {
        missingControls.push({
          controlId: mapping.controlId,
          controlDescription: mapping.controlDescription,
          missingNodeTypes
        });
      }
    }

    const totalControls = mappings.length;
    const coveredControls = totalControls - missingControls.length;
    return {
      tenantId,
      framework,
      totalControls,
      coveredControls,
      missingControls,
      generatedAt: nowIso()
    };
  }
}
