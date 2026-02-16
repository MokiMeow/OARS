import { canonicalStringify } from "../../lib/canonical-json.js";
import { sha256Hex } from "../../lib/hash.js";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import type { ActionReceipt } from "../types/domain.js";
import { EvidenceGraphService } from "./evidence-graph-service.js";
import { SigningKeyService } from "./signing-key-service.js";

export interface SignedEvidenceBundle {
  bundleId: string;
  tenantId: string;
  framework: "eu_ai_act" | "iso_42001" | "soc2";
  generatedAt: string;
  summary: {
    actionCount: number;
    receiptCount: number;
  };
  artifactHashes: string[];
  artifacts: Array<{
    receiptId: string;
    type: string;
    actionId: string;
    timestamp: string;
    decision: string;
    receiptHash: string;
  }>;
  integrity: {
    bundleHash: string;
    signature: string;
    signingKeyId: string;
    signatureAlg: "Ed25519";
  };
}

export class EvidenceBundleService {
  constructor(
    private readonly signingKeyService: SigningKeyService,
    private readonly evidenceGraphService: EvidenceGraphService
  ) {}

  async createBundle(input: {
    tenantId: string;
    framework: "eu_ai_act" | "iso_42001" | "soc2";
    actionCount: number;
    receipts: ActionReceipt[];
  }): Promise<SignedEvidenceBundle> {
    const artifacts = input.receipts.map((receipt) => ({
      receiptId: receipt.receiptId,
      type: receipt.type,
      actionId: receipt.actionId,
      timestamp: receipt.timestamp,
      decision: receipt.policy.decision,
      receiptHash: receipt.integrity.receiptHash
    }));
    const artifactHashes = artifacts.map((artifact) => artifact.receiptHash);
    const bundleId = createId("evb");
    const generatedAt = nowIso();
    const bundleHash = sha256Hex(
      canonicalStringify({
        bundleId,
        tenantId: input.tenantId,
        framework: input.framework,
        generatedAt,
        summary: {
          actionCount: input.actionCount,
          receiptCount: artifacts.length
        },
        artifactHashes
      })
    );
    const signing = this.signingKeyService.sign(input.tenantId, bundleHash);

    const bundle: SignedEvidenceBundle = {
      bundleId,
      tenantId: input.tenantId,
      framework: input.framework,
      generatedAt,
      summary: {
        actionCount: input.actionCount,
        receiptCount: artifacts.length
      },
      artifactHashes,
      artifacts,
      integrity: {
        bundleHash,
        signature: signing.signature,
        signingKeyId: signing.keyId,
        signatureAlg: "Ed25519"
      }
    };

    await this.evidenceGraphService.ingestEvidenceBundle({
      bundleId: bundle.bundleId,
      tenantId: bundle.tenantId,
      framework: bundle.framework,
      generatedAt: bundle.generatedAt,
      bundleHash: bundle.integrity.bundleHash,
      receiptIds: bundle.artifacts.map((artifact) => artifact.receiptId)
    });

    return bundle;
  }

  verifyBundle(bundle: SignedEvidenceBundle): {
    isHashValid: boolean;
    isSignatureValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    const recomputedHash = sha256Hex(
      canonicalStringify({
        bundleId: bundle.bundleId,
        tenantId: bundle.tenantId,
        framework: bundle.framework,
        generatedAt: bundle.generatedAt,
        summary: bundle.summary,
        artifactHashes: bundle.artifactHashes
      })
    );
    const isHashValid = recomputedHash === bundle.integrity.bundleHash;
    if (!isHashValid) {
      errors.push("Bundle hash mismatch.");
    }

    const isSignatureValid =
      isHashValid &&
      this.signingKeyService.verify(
        bundle.integrity.bundleHash,
        bundle.integrity.signature,
        bundle.integrity.signingKeyId
      );
    if (!isSignatureValid) {
      errors.push("Bundle signature verification failed.");
    }

    return {
      isHashValid,
      isSignatureValid,
      errors
    };
  }
}
