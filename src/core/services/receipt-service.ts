import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { canonicalStringify } from "../../lib/canonical-json.js";
import { sha256Hex } from "../../lib/hash.js";
import type { ActionReceipt, ActionRecord, PolicyDecision, ReceiptType, RiskContext } from "../types/domain.js";
import { PlatformStore } from "../store/platform-store.js";
import { EvidenceGraphService } from "./evidence-graph-service.js";
import { ImmutableLedgerService } from "./immutable-ledger-service.js";
import { SigningKeyService } from "./signing-key-service.js";
import { SecurityEventService } from "./security-event-service.js";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

export interface ReceiptVerificationResult {
  isSignatureValid: boolean;
  isChainValid: boolean;
  isSchemaValid: boolean;
  verificationErrors: string[];
}

interface CreateReceiptArgs {
  action: ActionRecord;
  type: ReceiptType;
  policySetId: string;
  policyVersion: string;
  policyDecision: PolicyDecision;
  policyRuleIds: string[];
  policyRationale: string;
  risk: RiskContext;
  requestId: string;
}

export class ReceiptService {
  constructor(
    private readonly store: PlatformStore,
    private readonly signingKeyService: SigningKeyService,
    private readonly securityEventService: SecurityEventService,
    private readonly immutableLedgerService?: ImmutableLedgerService,
    private readonly evidenceGraphService?: EvidenceGraphService
  ) {}

  async createReceipt(args: CreateReceiptArgs): Promise<ActionReceipt> {
    const previousReceipts = await this.store.listReceiptsByAction(args.action.id);
    const prevReceipt = previousReceipts.at(-1);
    const receiptId = createId("rcpt");
    const timestamp = nowIso();
    const traceId = createId("trc");
    const spanId = createId("spn");
    const prevReceiptHash = prevReceipt?.integrity.receiptHash ?? null;

    const hashPayload = {
      receiptId,
      version: "1.0.0",
      tenantId: args.action.tenantId,
      actionId: args.action.id,
      type: args.type,
      timestamp,
      actor: {
        userId: args.action.actor.userId,
        agentId: args.action.actor.agentId,
        serviceId: args.action.actor.serviceId,
        delegationChain: args.action.actor.delegationChain
      },
      resource: {
        toolId: args.action.resource.toolId,
        operation: args.action.resource.operation,
        target: args.action.resource.target
      },
      policy: {
        policySetId: args.policySetId,
        policyVersion: args.policyVersion,
        decision: args.policyDecision,
        ruleIds: args.policyRuleIds,
        rationale: args.policyRationale
      },
      risk: args.risk,
      telemetry: {
        traceId,
        spanId,
        requestId: args.requestId
      },
      prevReceiptHash
    };

    const receiptHash = sha256Hex(canonicalStringify(hashPayload));
    const signing = this.signingKeyService.sign(args.action.tenantId, receiptHash);

    const receipt: ActionReceipt = {
      receiptId,
      version: "1.0.0",
      tenantId: args.action.tenantId,
      actionId: args.action.id,
      type: args.type,
      timestamp,
      actor: hashPayload.actor,
      resource: hashPayload.resource,
      policy: hashPayload.policy,
      risk: args.risk,
      integrity: {
        prevReceiptHash,
        receiptHash,
        signature: signing.signature,
        signingKeyId: signing.keyId,
        signatureAlg: "Ed25519"
      },
      telemetry: hashPayload.telemetry
    };

    this.immutableLedgerService?.appendReceipt(receipt);
    await this.store.saveReceipt(receipt);
    if (this.evidenceGraphService) {
      await this.evidenceGraphService.ingestReceipt(receipt);
    }
    await this.securityEventService.publish({
      tenantId: receipt.tenantId,
      source: "receipt",
      eventType: "receipt.created",
      payload: {
        receiptId: receipt.receiptId,
        actionId: receipt.actionId,
        type: receipt.type,
        decision: receipt.policy.decision
      }
    });
    return receipt;
  }

  async getReceipt(receiptId: string): Promise<ActionReceipt | undefined> {
    return this.store.getReceipt(receiptId);
  }

  async verifyReceiptById(receiptId: string): Promise<ReceiptVerificationResult> {
    const receipt = await this.store.getReceipt(receiptId);
    if (!receipt) {
      return {
        isSignatureValid: false,
        isChainValid: false,
        isSchemaValid: false,
        verificationErrors: ["Receipt not found."]
      };
    }

    return this.verifyReceipt(receipt);
  }

  verifyReceiptPayload(
    receipt: ActionReceipt,
    options?: {
      chain?: ActionReceipt[] | undefined;
      publicKeyPem?: string | undefined;
      publicKeys?: Array<{ keyId: string; publicKeyPem: string }> | undefined;
    }
  ): ReceiptVerificationResult {
    const errors: string[] = [];

    const hashPayload = {
      receiptId: receipt.receiptId,
      version: receipt.version,
      tenantId: receipt.tenantId,
      actionId: receipt.actionId,
      type: receipt.type,
      timestamp: receipt.timestamp,
      actor: receipt.actor,
      resource: receipt.resource,
      policy: receipt.policy,
      risk: receipt.risk,
      telemetry: receipt.telemetry,
      prevReceiptHash: receipt.integrity.prevReceiptHash
    };

    const recomputedHash = sha256Hex(canonicalStringify(hashPayload));
    const hashMatches = recomputedHash === receipt.integrity.receiptHash;
    if (!hashMatches) {
      errors.push("Receipt hash mismatch.");
    }

    const keyFromList = options?.publicKeys?.find((entry) => entry.keyId === receipt.integrity.signingKeyId)?.publicKeyPem;
    const publicKeyPem = keyFromList ?? options?.publicKeyPem ?? this.signingKeyService.getPublicKey(receipt.integrity.signingKeyId) ?? null;

    let isSignatureValid = false;
    if (hashMatches && publicKeyPem) {
      try {
        const publicKey = createPublicKey(publicKeyPem);
        const signature = Buffer.from(receipt.integrity.signature, "base64");
        isSignatureValid = cryptoVerify(null, Buffer.from(receipt.integrity.receiptHash), publicKey, signature);
      } catch {
        isSignatureValid = false;
      }
    } else if (hashMatches) {
      isSignatureValid = this.signingKeyService.verify(
        receipt.integrity.receiptHash,
        receipt.integrity.signature,
        receipt.integrity.signingKeyId
      );
    }
    if (!isSignatureValid) {
      errors.push("Receipt signature verification failed.");
    }

    const chain = options?.chain;
    let isChainValid = true;
    if (chain && chain.length > 0) {
      const sorted = [...chain].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      for (let index = 0; index < sorted.length; index += 1) {
        const current = sorted[index];
        const previous = sorted[index - 1];
        if (!current) {
          continue;
        }
        if (!previous) {
          if (current.integrity.prevReceiptHash !== null) {
            isChainValid = false;
            errors.push("First receipt has non-null prev hash.");
            break;
          }
          continue;
        }
        if (current.integrity.prevReceiptHash !== previous.integrity.receiptHash) {
          isChainValid = false;
          errors.push("Receipt hash chain broken.");
          break;
        }
      }
    }

    const isSchemaValid = Boolean(receipt.receiptId && receipt.actionId && receipt.type && receipt.timestamp);
    if (!isSchemaValid) {
      errors.push("Receipt schema fields missing.");
    }

    return {
      isSignatureValid,
      isChainValid,
      isSchemaValid,
      verificationErrors: errors
    };
  }

  async verifyReceipt(receipt: ActionReceipt): Promise<ReceiptVerificationResult> {
    const errors: string[] = [];

    const hashPayload = {
      receiptId: receipt.receiptId,
      version: receipt.version,
      tenantId: receipt.tenantId,
      actionId: receipt.actionId,
      type: receipt.type,
      timestamp: receipt.timestamp,
      actor: receipt.actor,
      resource: receipt.resource,
      policy: receipt.policy,
      risk: receipt.risk,
      telemetry: receipt.telemetry,
      prevReceiptHash: receipt.integrity.prevReceiptHash
    };

    const recomputedHash = sha256Hex(canonicalStringify(hashPayload));
    const hashMatches = recomputedHash === receipt.integrity.receiptHash;
    if (!hashMatches) {
      errors.push("Receipt hash mismatch.");
    }

    const isSignatureValid =
      hashMatches &&
      this.signingKeyService.verify(
        receipt.integrity.receiptHash,
        receipt.integrity.signature,
        receipt.integrity.signingKeyId
      );
    if (!isSignatureValid) {
      errors.push("Receipt signature verification failed.");
    }

    const actionReceipts = await this.store.listReceiptsByAction(receipt.actionId);
    const sorted = actionReceipts.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    let isChainValid = true;

    for (let index = 0; index < sorted.length; index += 1) {
      const current = sorted[index];
      const previous = sorted[index - 1];
      if (!current) {
        continue;
      }

      if (!previous) {
        if (current.integrity.prevReceiptHash !== null) {
          isChainValid = false;
          errors.push("First receipt has non-null prev hash.");
          break;
        }
        continue;
      }

      if (current.integrity.prevReceiptHash !== previous.integrity.receiptHash) {
        isChainValid = false;
        errors.push("Receipt hash chain broken.");
        break;
      }
    }

    const isSchemaValid = Boolean(receipt.receiptId && receipt.actionId && receipt.type && receipt.timestamp);
    if (!isSchemaValid) {
      errors.push("Receipt schema fields missing.");
    }

    return {
      isSignatureValid,
      isChainValid,
      isSchemaValid,
      verificationErrors: errors
    };
  }
}
