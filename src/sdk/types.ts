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

export interface ActionSubmission {
  tenantId: string;
  agentId: string;
  userContext?: {
    userId?: string | undefined;
    sessionId?: string | undefined;
  };
  context?: ActionContext | undefined;
  resource: ResourceContext;
  input: Record<string, unknown>;
}

export interface ActionResponse {
  actionId: string;
  state: string;
  receiptId: string;
  approvalId?: string | undefined;
  stepUpRequired?: boolean | undefined;
  approvalProgress?: {
    currentStageIndex: number;
    totalStages: number;
    currentStageName: string | null;
  };
  output?: Record<string, unknown> | undefined;
  error?: string | null | undefined;
}

export type PolicyDecision = "allow" | "deny" | "approve" | "quarantine";

export interface ReceiptVerificationResult {
  isSignatureValid: boolean;
  isChainValid: boolean;
  isSchemaValid: boolean;
  verificationErrors: string[];
}

export type VerifyReceiptInput =
  | { receiptId: string }
  | {
      receipt: Record<string, unknown>;
      chain?: Array<Record<string, unknown>> | undefined;
      publicKeyPem?: string | undefined;
      publicKeys?: Array<{ keyId: string; publicKeyPem: string }> | undefined;
    };

export interface ReceiptQuery {
  tenantId: string;
  toolId?: string | undefined;
  operation?: string | undefined;
  actorUserId?: string | undefined;
  actorAgentId?: string | undefined;
  policyDecision?: PolicyDecision | undefined;
  policyVersion?: string | undefined;
  policyRuleId?: string | undefined;
  limit?: number | undefined;
  framework?: "eu_ai_act" | "iso_42001" | "soc2" | undefined;
  controlId?: string | undefined;
}

export interface ReceiptListResponse {
  tenantId: string;
  items: Array<Record<string, unknown>>;
}

