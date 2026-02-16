import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";
import type { PlatformContextOptions } from "../src/core/services/platform-context.js";

const adminAuthHeader = {
  authorization: "Bearer dev_admin_token"
};

const operatorAuthHeader = {
  authorization: "Bearer dev_operator_token"
};

const auditorAuthHeader = {
  authorization: "Bearer dev_auditor_token"
};

function createTestServer(options?: PlatformContextOptions) {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const dataFilePath = join(baseDir, `${suffix}-state.json`);
  const keyFilePath = join(baseDir, `${suffix}-keys.json`);
  const ledgerFilePath = join(baseDir, `${suffix}-ledger.ndjson`);
  const vaultFilePath = join(baseDir, `${suffix}-vault.json`);
  const backupRootPath = options?.backupRootPath ?? join(baseDir, `${suffix}-backups`);
  const drillReportsPath = options?.drillReportsPath ?? join(baseDir, `${suffix}-drill-reports`);
  const drillWorkspacePath = options?.drillWorkspacePath ?? join(baseDir, `${suffix}-drill-workspace`);
  const context = createPlatformContext({
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    backupRootPath,
    drillReportsPath,
    drillWorkspacePath,
    ...options
  });
  const app = buildServer(context);
  return {
    app,
    baseDir,
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    backupRootPath,
    drillReportsPath,
    drillWorkspacePath
  };
}

function signRs256Token(input: {
  privateKeyPem: string;
  kid: string;
  issuer: string;
  audience: string;
  subject: string;
  tenantIds: string[];
  scopes: string[];
  role: "admin" | "operator" | "auditor" | "agent" | "service";
  expiresInSeconds?: number;
}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti: createId("ext"),
    iss: input.issuer,
    aud: input.audience,
    sub: input.subject,
    iat: now,
    exp: now + (input.expiresInSeconds ?? 1800),
    tid: input.tenantIds,
    scp: input.scopes,
    role: input.role
  };
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: input.kid
  };
  const headerSegment = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = cryptoSign(
    "RSA-SHA256",
    Buffer.from(`${headerSegment}.${payloadSegment}`),
    input.privateKeyPem
  ).toString("base64url");
  return `${headerSegment}.${payloadSegment}.${signature}`;
}

function cleanup(paths: string[]): void {
  const tmpRoot = resolve(tmpdir());
  const tempDirs = new Set<string>();

  for (const candidate of paths) {
    const resolved = resolve(candidate);
    if (!resolved.startsWith(tmpRoot + sep)) {
      continue;
    }
    const suffix = resolved.slice(tmpRoot.length + sep.length);
    const firstSegment = suffix.split(sep)[0];
    if (firstSegment && firstSegment.startsWith("oars-test_")) {
      tempDirs.add(join(tmpRoot, firstSegment));
    }
  }

  for (const dir of tempDirs) {
    if (existsSync(dir)) {
      rmSync(dir, { force: true, recursive: true });
    }
  }

  for (const path of paths) {
    if (existsSync(path)) {
      rmSync(path, { force: true, recursive: true });
    }
  }
}

describe("OARS API", () => {
  it("executes low-risk action without approval and emits verifiable receipt chain", async () => {
    const { app, baseDir, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_finops",
          userContext: {
            userId: "user_123"
          },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Investigate suspicious egress traffic"
          }
        }
      });

      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.state).toBe("executed");
      expect(actionPayload.actionId).toBeTruthy();
      expect(actionPayload.receiptId).toBeTruthy();

      const statusResponse = await app.inject({
        method: "GET",
        url: `/v1/actions/${actionPayload.actionId}`,
        headers: adminAuthHeader
      });
      expect(statusResponse.statusCode).toBe(200);
      const statusPayload = statusResponse.json();
      expect(statusPayload.action.state).toBe("executed");
      expect(statusPayload.receipts).toHaveLength(3);
      expect(statusPayload.receipts[0].type).toBe("action.requested");
      expect(statusPayload.receipts[1].type).toBe("action.approved");
      expect(statusPayload.receipts[2].type).toBe("action.executed");

      const verifyResponse = await app.inject({
        method: "POST",
        url: "/v1/receipts/verify",
        headers: adminAuthHeader,
        payload: {
          receiptId: actionPayload.receiptId
        }
      });
      expect(verifyResponse.statusCode).toBe(200);
      const verifyPayload = verifyResponse.json();
      expect(verifyPayload.isSignatureValid).toBe(true);
      expect(verifyPayload.isChainValid).toBe(true);
      expect(verifyPayload.isSchemaValid).toBe(true);

      const receiptResponse = await app.inject({
        method: "GET",
        url: `/v1/receipts/${actionPayload.receiptId}`,
        headers: adminAuthHeader
      });
      expect(receiptResponse.statusCode).toBe(200);
      const receipt = receiptResponse.json();

      const trustResponse = await app.inject({
        method: "GET",
        url: "/v1/trust/tenants/tenant_alpha/keys",
        headers: adminAuthHeader
      });
      expect(trustResponse.statusCode).toBe(200);
      const trustItems = trustResponse.json().items as Array<{ keyId: string; publicKeyPem: string }>;
      const matchingKey = trustItems.find((item) => item.keyId === receipt.integrity.signingKeyId);
      expect(matchingKey).toBeTruthy();
      const publicKeyPem = (matchingKey as { publicKeyPem: string }).publicKeyPem;
      expect(publicKeyPem).toBeTruthy();

      const verifyPayloadOnly = await app.inject({
        method: "POST",
        url: "/v1/receipts/verify",
        headers: adminAuthHeader,
        payload: {
          receipt,
          publicKeyPem
        }
      });
      expect(verifyPayloadOnly.statusCode).toBe(200);
      const verifyPayloadOnlyJson = verifyPayloadOnly.json();
      expect(verifyPayloadOnlyJson.isSignatureValid).toBe(true);
      expect(verifyPayloadOnlyJson.isSchemaValid).toBe(true);
    } finally {
      await app.close();
      cleanup([baseDir]);
    }
  });

  it("accepts snake_case action submission payloads for compatibility", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenant_id: "tenant_alpha",
          agent_id: "agent_snake",
          user_context: {
            user_id: "user_snake"
          },
          resource: {
            tool_id: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Snake case compatible request"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      expect(actionResponse.json().actionId).toBeTruthy();
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports Idempotency-Key for action submission replay and rejects mismatched replays", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const idempotencyKey = "idem_actions_1";
      const first = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "idempotency-key": idempotencyKey
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_idem",
          userContext: {
            userId: "user_idem"
          },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Idempotency check"
          }
        }
      });
      expect(first.statusCode).toBe(202);
      const firstPayload = first.json();
      expect(firstPayload.actionId).toBeTruthy();

      const replay = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "idempotency-key": idempotencyKey
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_idem",
          userContext: {
            userId: "user_idem"
          },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Idempotency check"
          }
        }
      });
      expect(replay.statusCode).toBe(202);
      const replayPayload = replay.json();
      expect(replayPayload.actionId).toBe(firstPayload.actionId);

      const conflict = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "idempotency-key": idempotencyKey
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_idem",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Different request should conflict"
          }
        }
      });
      expect(conflict.statusCode).toBe(409);
      expect(conflict.json().error.code).toBe("idempotency_conflict");

      const persisted = JSON.parse(readFileSync(dataFilePath, "utf8")) as { actions?: unknown[]; idempotencyRecords?: unknown[] };
      expect(Array.isArray(persisted.actions)).toBe(true);
      expect((persisted.actions ?? []).length).toBe(1);
      expect(Array.isArray(persisted.idempotencyRecords)).toBe(true);
      expect((persisted.idempotencyRecords ?? []).length).toBe(1);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports tenant-scoped receipt search filters", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_receipt_query",
          userContext: {
            userId: "user_query"
          },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Receipt query seed"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const receiptId = actionResponse.json().receiptId as string;

      const listResponse = await app.inject({
        method: "GET",
        url: "/v1/receipts?tenantId=tenant_alpha&toolId=jira&actorUserId=user_query&limit=50",
        headers: adminAuthHeader
      });
      expect(listResponse.statusCode).toBe(200);
      const listed = listResponse.json();
      expect(listed.items.length).toBeGreaterThan(0);
      expect(listed.items.some((receipt: { receiptId: string }) => receipt.receiptId === receiptId)).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("requires approval for high-risk action and executes after approval", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_bravo",
          agentId: "agent_secops",
          userContext: {
            userId: "user_999"
          },
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });

      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.state).toBe("approval_required");
      expect(actionPayload.approvalId).toBeTruthy();

      const approveResponse = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "security_manager",
          reason: "Emergency remediation approved",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(approveResponse.statusCode).toBe(200);
      const approvePayload = approveResponse.json();
      expect(approvePayload.state).toBe("executed");

      const statusResponse = await app.inject({
        method: "GET",
        url: `/v1/actions/${actionPayload.actionId}`,
        headers: adminAuthHeader
      });
      expect(statusResponse.statusCode).toBe(200);
      const statusPayload = statusResponse.json();
      expect(statusPayload.receipts.some((receipt: { type: string }) => receipt.type === "action.approval_required")).toBe(
        true
      );

      const alertsResponse = await app.inject({
        method: "GET",
        url: "/v1/alerts?tenantId=tenant_bravo",
        headers: adminAuthHeader
      });
      expect(alertsResponse.statusCode).toBe(200);
      const alertsPayload = alertsResponse.json();
      expect(alertsPayload.items.some((alert: { code: string }) => alert.code === "HIGH_RISK_EXECUTED")).toBe(true);

      const eventsResponse = await app.inject({
        method: "GET",
        url: "/v1/security-events?tenantId=tenant_bravo",
        headers: adminAuthHeader
      });
      expect(eventsResponse.statusCode).toBe(200);
      const eventsPayload = eventsResponse.json();
      expect(eventsPayload.items.some((event: { eventType: string }) => event.eventType === "receipt.created")).toBe(
        true
      );
      expect(eventsPayload.items.some((event: { eventType: string }) => event.eventType === "alert.emitted")).toBe(
        true
      );
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("encrypts sensitive persisted payload fields at rest and restores them in runtime", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer({
      dataProtectionOptions: {
        encryptionKey: "test_data_encryption_key"
      }
    });
    try {
      const secretValue = "super_secret_api_token_123";
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_encrypt",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Encryption at rest test",
            credential: secretValue
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionId = actionResponse.json().actionId as string;

      const rawState = readFileSync(dataFilePath, "utf8");
      expect(rawState.includes(secretValue)).toBe(false);
      expect(rawState.includes("__oarsEncrypted")).toBe(true);

      await app.close();

      const replayApp = buildServer(
        createPlatformContext({
          dataFilePath,
          keyFilePath,
          dataProtectionOptions: {
            encryptionKey: "test_data_encryption_key"
          },
          siemOptions: {
            autoStartRetry: false
          }
        })
      );

      const statusResponse = await replayApp.inject({
        method: "GET",
        url: `/v1/actions/${actionId}`,
        headers: adminAuthHeader
      });
      expect(statusResponse.statusCode).toBe(200);
      const payload = statusResponse.json();
      expect(payload.action.input.credential).toBe(secretValue);
      await replayApp.close();
    } finally {
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports multi-stage approval chains with scoped approvers", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const forbiddenWorkflowWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_bravo/approval-workflow",
        headers: operatorAuthHeader,
        payload: {
          stages: [
            {
              name: "Denied",
              mode: "serial",
              requiredApprovals: 1,
              approverIds: []
            }
          ]
        }
      });
      expect(forbiddenWorkflowWrite.statusCode).toBe(403);

      const setWorkflow = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_bravo/approval-workflow",
        headers: adminAuthHeader,
        payload: {
          stages: [
            {
              name: "Security review",
              mode: "serial",
              requiredApprovals: 1,
              approverIds: ["sec_lead"]
            },
            {
              name: "Business approval",
              mode: "serial",
              requiredApprovals: 1,
              approverIds: ["business_owner"]
            }
          ]
        }
      });
      expect(setWorkflow.statusCode).toBe(200);
      const workflowPayload = setWorkflow.json();
      expect(workflowPayload.stages).toHaveLength(2);

      const getWorkflow = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_bravo/approval-workflow",
        headers: adminAuthHeader
      });
      expect(getWorkflow.statusCode).toBe(200);
      expect(getWorkflow.json().stages).toHaveLength(2);

      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_bravo",
          agentId: "agent_secops",
          userContext: {
            userId: "user_999"
          },
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });

      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.state).toBe("approval_required");
      expect(actionPayload.approvalId).toBeTruthy();

      const unauthorizedApprover = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "random_user",
          reason: "Attempt unauthorized stage approval"
        }
      });
      expect(unauthorizedApprover.statusCode).toBe(400);

      const stage1Approve = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "sec_lead",
          reason: "Security checks passed",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(stage1Approve.statusCode).toBe(202);
      const stage1Payload = stage1Approve.json();
      expect(stage1Payload.state).toBe("approval_required");
      expect(stage1Payload.approvalProgress.currentStageIndex).toBe(1);
      expect(stage1Payload.approvalProgress.totalStages).toBe(2);

      const statusAfterStage1 = await app.inject({
        method: "GET",
        url: `/v1/actions/${actionPayload.actionId}`,
        headers: adminAuthHeader
      });
      expect(statusAfterStage1.statusCode).toBe(200);
      expect(statusAfterStage1.json().action.state).toBe("approval_required");

      const stage2Approve = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "business_owner",
          reason: "Business owner approved",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(stage2Approve.statusCode).toBe(200);
      const stage2Payload = stage2Approve.json();
      expect(stage2Payload.state).toBe("executed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports parallel approval stages with required approval threshold", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const setWorkflow = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_bravo/approval-workflow",
        headers: adminAuthHeader,
        payload: {
          stages: [
            {
              name: "Security quorum",
              mode: "parallel",
              requiredApprovals: 2,
              approverIds: ["sec_a", "sec_b", "sec_c"]
            },
            {
              name: "Business approval",
              mode: "serial",
              requiredApprovals: 1,
              approverIds: ["business_owner"]
            }
          ]
        }
      });
      expect(setWorkflow.statusCode).toBe(200);

      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_bravo",
          agentId: "agent_parallel",
          userContext: {
            userId: "user_parallel"
          },
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();

      const firstParallelApprove = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "sec_a",
          reason: "First security approval",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(firstParallelApprove.statusCode).toBe(202);
      expect(firstParallelApprove.json().approvalProgress.currentStageIndex).toBe(0);

      const secondParallelApprove = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "sec_b",
          reason: "Second security approval",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(secondParallelApprove.statusCode).toBe(202);
      expect(secondParallelApprove.json().approvalProgress.currentStageIndex).toBe(1);

      const finalApprove = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "business_owner",
          reason: "Final approval",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(finalApprove.statusCode).toBe(200);
      expect(finalApprove.json().state).toBe("executed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("requires step-up authentication for critical approval decisions", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_stepup",
          userContext: {
            userId: "user_stepup"
          },
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.stepUpRequired).toBe(true);

      const withoutStepUp = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "security_manager",
          reason: "Attempt without step-up"
        }
      });
      expect(withoutStepUp.statusCode).toBe(400);

      const withStepUp = await app.inject({
        method: "POST",
        url: `/v1/approvals/${actionPayload.approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "security_manager",
          reason: "Approved with step-up",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(withStepUp.statusCode).toBe(200);
      expect(withStepUp.json().state).toBe("executed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("scans and escalates overdue approval stages", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const workflowResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/approval-workflow",
        headers: adminAuthHeader,
        payload: {
          stages: [
            {
              name: "Security approval",
              mode: "serial",
              requiredApprovals: 1,
              approverIds: ["sec_lead"],
              slaSeconds: 30,
              escalateTo: ["oncall_manager"]
            }
          ]
        }
      });
      expect(workflowResponse.statusCode).toBe(200);

      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_escalation",
          userContext: {
            userId: "user_escalation"
          },
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();

      const unauthorizedScan = await app.inject({
        method: "POST",
        url: "/v1/admin/approvals/escalations/scan",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha"
        }
      });
      expect(unauthorizedScan.statusCode).toBe(403);

      const scanTime = new Date(Date.now() + 120_000).toISOString();
      const scanResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/approvals/escalations/scan",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          nowIso: scanTime
        }
      });
      expect(scanResponse.statusCode).toBe(200);
      const scanPayload = scanResponse.json();
      expect(scanPayload.escalatedCount).toBe(1);
      expect(scanPayload.items[0].actionId).toBe(actionPayload.actionId);
      expect(scanPayload.items[0].escalateTo).toContain("oncall_manager");

      const secondScan = await app.inject({
        method: "POST",
        url: "/v1/admin/approvals/escalations/scan",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          nowIso: scanTime
        }
      });
      expect(secondScan.statusCode).toBe(200);
      expect(secondScan.json().escalatedCount).toBe(0);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("rejects unauthorized requests", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/v1/actions",
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_test",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Should fail auth"
          }
        }
      });

      expect(response.statusCode).toBe(401);
      const body = response.json();
      expect(body.error.code).toBe("unauthorized");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("rejects malformed bearer authorization headers (auth bypass fuzz matrix)", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const malformedHeaders: Array<Record<string, string>> = [
        {},
        { authorization: "" },
        { authorization: "Basic abc" },
        { authorization: "Bearer" },
        { authorization: "Bearer    " },
        { authorization: "Token dev_admin_token" },
        { authorization: "bearer" }
      ];

      for (const headers of malformedHeaders) {
        const response = await app.inject({
          method: "GET",
          url: "/v1/connectors",
          headers
        });
        expect(response.statusCode).toBe(401);
      }
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("blocks tenant isolation bypass attempts across admin and runtime endpoints", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const checks: Array<{ method: "GET" | "POST"; url: string; payload?: Record<string, unknown> }> = [
        {
          method: "GET",
          url: "/v1/alerts?tenantId=tenant_enterprise&limit=20"
        },
        {
          method: "GET",
          url: "/v1/security-events?tenantId=tenant_enterprise&limit=20"
        },
        {
          method: "GET",
          url: "/v1/admin/ledger/entries?tenantId=tenant_enterprise&limit=20"
        },
        {
          method: "GET",
          url: "/v1/admin/ops/dashboard?tenantId=tenant_enterprise"
        },
        {
          method: "POST",
          url: "/v1/admin/ops/alert-routing",
          payload: {
            tenantId: "tenant_enterprise",
            severity: "critical",
            channels: ["pagerduty"],
            escalationMinutes: 5
          }
        }
      ];

      for (const check of checks) {
        const response = await app.inject(
          check.payload
            ? {
                method: check.method,
                url: check.url,
                headers: operatorAuthHeader,
                payload: check.payload
              }
            : {
                method: check.method,
                url: check.url,
                headers: operatorAuthHeader
              }
        );
        expect(response.statusCode).toBe(403);
      }
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports expanded connector set including confluence and database policies", async () => {
    const { app, dataFilePath, keyFilePath, vaultFilePath } = createTestServer();
    try {
      const connectorsResponse = await app.inject({
        method: "GET",
        url: "/v1/connectors",
        headers: adminAuthHeader
      });
      expect(connectorsResponse.statusCode).toBe(200);
      const connectorItems = connectorsResponse.json().items as string[];
      expect(connectorItems).toContain("confluence");
      expect(connectorItems).toContain("database");

      const confluenceAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_docs",
          resource: {
            toolId: "confluence",
            operation: "create_page",
            target: "space:SEC"
          },
          input: {
            title: "Security Ops Runbook"
          }
        }
      });
      expect(confluenceAction.statusCode).toBe(202);
      expect(confluenceAction.json().state).toBe("executed");

      const databaseActionWithoutSecret = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_db",
          resource: {
            toolId: "database",
            operation: "run_query",
            target: "db:analytics"
          },
          input: {
            sql: "select 1"
          }
        }
      });
      expect(databaseActionWithoutSecret.statusCode).toBe(202);
      expect(databaseActionWithoutSecret.json().state).toBe("failed");

      const forbiddenSecretWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/vault/secrets",
        headers: operatorAuthHeader,
        payload: {
          connectorId: "database",
          key: "connection",
          value: "postgres://user:pass@db.example.local/main"
        }
      });
      expect(forbiddenSecretWrite.statusCode).toBe(403);

      const secretWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/vault/secrets",
        headers: adminAuthHeader,
        payload: {
          connectorId: "database",
          key: "connection",
          value: "postgres://user:pass@db.example.local/main"
        }
      });
      expect(secretWrite.statusCode).toBe(200);

      const databaseAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_db",
          resource: {
            toolId: "database",
            operation: "run_query",
            target: "db:analytics"
          },
          input: {
            sql: "select 1"
          }
        }
      });
      expect(databaseAction.statusCode).toBe(202);
      expect(databaseAction.json().state).toBe("executed");

      const blockedDatabaseAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_db",
          resource: {
            toolId: "database",
            operation: "run_query",
            target: "db:analytics"
          },
          input: {
            sql: "drop table users"
          }
        }
      });
      expect(blockedDatabaseAction.statusCode).toBe(202);
      expect(blockedDatabaseAction.json().state).toBe("failed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath, vaultFilePath]);
    }
  });

  it("enforces admin-only tenant member write operations", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const forbiddenResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/members",
        headers: operatorAuthHeader,
        payload: {
          subject: "new_user",
          role: "operator"
        }
      });
      expect(forbiddenResponse.statusCode).toBe(403);

      const createResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/members",
        headers: adminAuthHeader,
        payload: {
          subject: "new_user",
          role: "operator"
        }
      });
      expect(createResponse.statusCode).toBe(201);
      const created = createResponse.json();
      expect(created.subject).toBe("new_user");
      expect(created.role).toBe("operator");

      const listResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/members",
        headers: adminAuthHeader
      });
      expect(listResponse.statusCode).toBe(200);
      const listPayload = listResponse.json();
      expect(listPayload.items.some((member: { subject: string }) => member.subject === "new_user")).toBe(true);

      const deleteResponse = await app.inject({
        method: "DELETE",
        url: "/v1/admin/tenants/tenant_alpha/members/new_user",
        headers: adminAuthHeader
      });
      expect(deleteResponse.statusCode).toBe(204);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("bootstraps tenants through admin API and persists owner assignment", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const forbidden = await app.inject({
        method: "POST",
        url: "/v1/tenants",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_new_bootstrap",
          displayName: "Tenant Bootstrap"
        }
      });
      expect(forbidden.statusCode).toBe(403);

      const created = await app.inject({
        method: "POST",
        url: "/v1/tenants",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_new_bootstrap",
          displayName: "Tenant Bootstrap",
          ownerSubject: "bootstrap_owner"
        }
      });
      expect(created.statusCode).toBe(201);
      const createPayload = created.json();
      expect(createPayload.tenant.tenantId).toBe("tenant_new_bootstrap");
      expect(createPayload.owner.subject).toBe("bootstrap_owner");
      expect(createPayload.owner.role).toBe("owner");

      const duplicate = await app.inject({
        method: "POST",
        url: "/v1/tenants",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_new_bootstrap",
          displayName: "Duplicate Tenant"
        }
      });
      expect(duplicate.statusCode).toBe(400);

      const listTenants = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants",
        headers: adminAuthHeader
      });
      expect(listTenants.statusCode).toBe(200);
      expect(
        listTenants.json().items.some((tenant: { tenantId: string }) => tenant.tenantId === "tenant_new_bootstrap")
      ).toBe(true);

      const state = JSON.parse(readFileSync(dataFilePath, "utf8")) as {
        tenantMembers?: Array<{ tenantId: string; subject: string; role: string }>;
      };
      expect(
        (state.tenantMembers ?? []).some(
          (member) =>
            member.tenantId === "tenant_new_bootstrap" &&
            member.subject === "bootstrap_owner" &&
            member.role === "owner"
        )
      ).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("issues delegated jwt via token exchange and executes action with exchanged token", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const exchangeResponse = await app.inject({
        method: "POST",
        url: "/v1/auth/token/exchange",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_delegate",
          scopes: ["actions:write", "actions:read", "receipts:read", "receipts:verify", "alerts:read"]
        }
      });
      expect(exchangeResponse.statusCode).toBe(200);
      const exchanged = exchangeResponse.json();
      expect(exchanged.accessToken).toBeTruthy();

      const delegatedHeader = {
        authorization: `Bearer ${exchanged.accessToken}`
      };
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: delegatedHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_delegate",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Delegated token action"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.state).toBe("executed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("creates service account and executes action using service token", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const createAccountResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/service-accounts",
        headers: adminAuthHeader,
        payload: {
          name: "ops-automation",
          role: "operator",
          scopes: ["actions:write", "actions:read", "receipts:read", "receipts:verify", "alerts:read"]
        }
      });
      expect(createAccountResponse.statusCode).toBe(201);
      const created = createAccountResponse.json();
      expect(created.id).toBeTruthy();
      expect(created.clientSecret).toBeTruthy();

      const serviceTokenResponse = await app.inject({
        method: "POST",
        url: "/v1/auth/service-token",
        payload: {
          clientId: created.id,
          clientSecret: created.clientSecret,
          tenantId: "tenant_alpha"
        }
      });
      expect(serviceTokenResponse.statusCode).toBe(200);
      const tokenPayload = serviceTokenResponse.json();
      expect(tokenPayload.accessToken).toBeTruthy();

      const serviceHeader = {
        authorization: `Bearer ${tokenPayload.accessToken}`
      };
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: serviceHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_service",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Service token action"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const actionPayload = actionResponse.json();
      expect(actionPayload.state).toBe("executed");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("enforces mTLS workload identity for service-role tokens", async () => {
    const attestationSecret = "test_mtls_attestation_secret";
    const serviceSubject = "svc_policy_worker";
    const serviceToken = "dev_mtls_service_token";
    const fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const { app, dataFilePath, keyFilePath } = createTestServer({
      authOptions: {
        rawConfig: JSON.stringify([
          {
            token: serviceToken,
            tokenId: "tok_mtls_service",
            subject: serviceSubject,
            tenantIds: ["tenant_alpha"],
            scopes: ["actions:write", "actions:read", "receipts:read"],
            role: "service"
          }
        ])
      },
      serviceIdentityOptions: {
        enabled: true,
        attestationSecret,
        trustedIdentities: [
          {
            subject: serviceSubject,
            fingerprintSha256: fingerprint,
            tenantIds: ["tenant_alpha"]
          }
        ]
      }
    });
    try {
      const noMtlsHeaders = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${serviceToken}`,
          "x-request-id": "req_missing_mtls"
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_mtls",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "mTLS enforcement negative case"
          }
        }
      });
      expect(noMtlsHeaders.statusCode).toBe(403);
      expect(noMtlsHeaders.json().error.code).toBe("mtls_identity_required");
      expect(noMtlsHeaders.json().error.requestId).toBe("req_missing_mtls");

      const issuedAt = new Date().toISOString();
      const invalidSignature = "deadbeef";
      const invalidMtls = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${serviceToken}`,
          "x-oars-mtls-subject": serviceSubject,
          "x-oars-mtls-fingerprint": fingerprint,
          "x-oars-mtls-issued-at": issuedAt,
          "x-oars-mtls-signature": invalidSignature
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_mtls",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "mTLS signature mismatch case"
          }
        }
      });
      expect(invalidMtls.statusCode).toBe(403);
      expect(invalidMtls.json().error.code).toBe("mtls_identity_required");

      const validSignature = createHmac("sha256", attestationSecret)
        .update(`${serviceSubject}\n${fingerprint}\n${issuedAt}`, "utf8")
        .digest("hex");
      const validMtls = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${serviceToken}`,
          "x-oars-mtls-subject": serviceSubject,
          "x-oars-mtls-fingerprint": fingerprint,
          "x-oars-mtls-issued-at": issuedAt,
          "x-oars-mtls-signature": validSignature
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_mtls",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "mTLS success case"
          }
        }
      });
      expect(validMtls.statusCode).toBe(202);
      expect(validMtls.json().actionId).toBeTruthy();
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("provides ops dashboard metrics and supports alert routing updates", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_bravo",
          agentId: "agent_ops",
          resource: {
            toolId: "iam",
            operation: "change_permissions",
            target: "prod:finance"
          },
          input: {
            change: "grant_admin"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const approvalId = actionResponse.json().approvalId as string;
      expect(approvalId).toBeTruthy();

      const approve = await app.inject({
        method: "POST",
        url: `/v1/approvals/${approvalId}/decision`,
        headers: adminAuthHeader,
        payload: {
          decision: "approve",
          approverId: "ops_security_manager",
          reason: "Approved for operations test",
          stepUpCode: "stepup_dev_code"
        }
      });
      expect(approve.statusCode).toBe(200);

      const dashboard = await app.inject({
        method: "GET",
        url: "/v1/admin/ops/dashboard?tenantId=tenant_bravo",
        headers: operatorAuthHeader
      });
      expect(dashboard.statusCode).toBe(200);
      const dashboardPayload = dashboard.json();
      expect(dashboardPayload.tenantId).toBe("tenant_bravo");
      expect(dashboardPayload.actions.total).toBeGreaterThan(0);
      expect(
        (dashboardPayload.alerts.bySeverity.high as number) + (dashboardPayload.alerts.bySeverity.critical as number)
      ).toBeGreaterThanOrEqual(1);

      const routingDefaults = await app.inject({
        method: "GET",
        url: "/v1/admin/ops/alert-routing?tenantId=tenant_bravo",
        headers: operatorAuthHeader
      });
      expect(routingDefaults.statusCode).toBe(200);
      expect(routingDefaults.json().items.length).toBe(4);

      const updateRouting = await app.inject({
        method: "POST",
        url: "/v1/admin/ops/alert-routing",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_bravo",
          severity: "critical",
          channels: ["pagerduty", "email_soc"],
          escalationMinutes: 3
        }
      });
      expect(updateRouting.statusCode).toBe(200);
      expect(updateRouting.json().channels).toEqual(["pagerduty", "email_soc"]);

      const routingAfter = await app.inject({
        method: "GET",
        url: "/v1/admin/ops/alert-routing?tenantId=tenant_bravo",
        headers: operatorAuthHeader
      });
      expect(routingAfter.statusCode).toBe(200);
      const critical = routingAfter
        .json()
        .items.find((entry: { severity: string }) => entry.severity === "critical") as {
        escalationMinutes: number;
      };
      expect(critical.escalationMinutes).toBe(3);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("exposes mTLS enforcement status to admins only", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer({
      serviceIdentityOptions: {
        enabled: true,
        trustedIdentities: [
          {
            subject: "svc_status",
            fingerprintSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          }
        ]
      }
    });
    try {
      const forbidden = await app.inject({
        method: "GET",
        url: "/v1/admin/security/mtls/status",
        headers: operatorAuthHeader
      });
      expect(forbidden.statusCode).toBe(403);

      const allowed = await app.inject({
        method: "GET",
        url: "/v1/admin/security/mtls/status",
        headers: adminAuthHeader
      });
      expect(allowed.statusCode).toBe(200);
      const payload = allowed.json();
      expect(payload.enabled).toBe(true);
      expect(payload.trustedIdentityCount).toBe(1);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("rotates tenant signing keys and keeps historical receipt verification valid", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionBeforeRotation = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_key_rotation",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Before rotation"
          }
        }
      });
      expect(actionBeforeRotation.statusCode).toBe(202);
      const beforePayload = actionBeforeRotation.json();

      const beforeReceiptResponse = await app.inject({
        method: "GET",
        url: `/v1/receipts/${beforePayload.receiptId}`,
        headers: adminAuthHeader
      });
      expect(beforeReceiptResponse.statusCode).toBe(200);
      const beforeReceipt = beforeReceiptResponse.json();
      const oldKeyId = beforeReceipt.integrity.signingKeyId as string;

      const forbiddenRotate = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/keys/rotate",
        headers: operatorAuthHeader
      });
      expect(forbiddenRotate.statusCode).toBe(403);

      const rotateResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/keys/rotate",
        headers: adminAuthHeader
      });
      expect(rotateResponse.statusCode).toBe(200);
      const rotatePayload = rotateResponse.json();
      expect(rotatePayload.newKeyId).toBeTruthy();
      expect(rotatePayload.newKeyId).not.toBe(oldKeyId);

      const actionAfterRotation = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_key_rotation",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "After rotation"
          }
        }
      });
      expect(actionAfterRotation.statusCode).toBe(202);
      const afterPayload = actionAfterRotation.json();

      const afterReceiptResponse = await app.inject({
        method: "GET",
        url: `/v1/receipts/${afterPayload.receiptId}`,
        headers: adminAuthHeader
      });
      expect(afterReceiptResponse.statusCode).toBe(200);
      const afterReceipt = afterReceiptResponse.json();
      expect(afterReceipt.integrity.signingKeyId).toBe(rotatePayload.newKeyId);

      const verifyOldReceipt = await app.inject({
        method: "POST",
        url: "/v1/receipts/verify",
        headers: adminAuthHeader,
        payload: {
          receiptId: beforePayload.receiptId
        }
      });
      expect(verifyOldReceipt.statusCode).toBe(200);
      expect(verifyOldReceipt.json().isSignatureValid).toBe(true);

      const keysResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/keys",
        headers: adminAuthHeader
      });
      expect(keysResponse.statusCode).toBe(200);
      const keysPayload = keysResponse.json();
      expect(keysPayload.items.some((item: { keyId: string; status: string }) => item.keyId === oldKeyId && item.status === "retiring")).toBe(true);
      expect(
        keysPayload.items.some(
          (item: { keyId: string; status: string }) => item.keyId === rotatePayload.newKeyId && item.status === "active"
        )
      ).toBe(true);

      const trustResponse = await app.inject({
        method: "GET",
        url: "/v1/trust/tenants/tenant_alpha/keys"
      });
      expect(trustResponse.statusCode).toBe(200);
      const trustPayload = trustResponse.json();
      expect(
        trustPayload.items.some(
          (item: { keyId: string; publicKeyPem: string }) =>
            item.keyId === rotatePayload.newKeyId && item.publicKeyPem.includes("BEGIN PUBLIC KEY")
        )
      ).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("detects receipt verification failure when signing key material is missing", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_keyloss",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Signing key loss simulation"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);
      const receiptId = actionResponse.json().receiptId as string;
      await app.close();

      const keys = JSON.parse(readFileSync(keyFilePath, "utf8")) as { keys?: unknown[] };
      keys.keys = [];
      writeFileSync(keyFilePath, JSON.stringify(keys, null, 2), "utf8");

      const replayApp = buildServer(
        createPlatformContext({
          dataFilePath,
          keyFilePath,
          siemOptions: {
            autoStartRetry: false
          }
        })
      );
      const verifyResponse = await replayApp.inject({
        method: "POST",
        url: "/v1/receipts/verify",
        headers: adminAuthHeader,
        payload: {
          receiptId
        }
      });
      expect(verifyResponse.statusCode).toBe(200);
      const verifyPayload = verifyResponse.json();
      expect(verifyPayload.isSignatureValid).toBe(false);
      expect(verifyPayload.verificationErrors.some((entry: string) => entry.includes("signature"))).toBe(true);
      await replayApp.close();
    } finally {
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports policy get and rollback with admin-only policy writes", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const operatorCreate = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "v-op-1",
          rules: [
            {
              id: "R-OP",
              description: "Operator attempt",
              priority: 10,
              match: {},
              decision: "allow"
            }
          ]
        }
      });
      expect(operatorCreate.statusCode).toBe(403);

      const createPolicy1 = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "v1",
          rules: [
            {
              id: "R-V1-ALLOW",
              description: "Allow baseline",
              priority: 10,
              match: {},
              decision: "allow"
            }
          ]
        }
      });
      expect(createPolicy1.statusCode).toBe(201);
      const policy1 = createPolicy1.json();

      const createPolicy2 = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "v2",
          rules: [
            {
              id: "R-V2-DENY-DROP",
              description: "Deny destructive",
              priority: 100,
              match: {
                operations: ["drop_database"]
              },
              decision: "deny"
            }
          ]
        }
      });
      expect(createPolicy2.statusCode).toBe(201);
      const policy2 = createPolicy2.json();

      const publishPolicy1 = await app.inject({
        method: "POST",
        url: `/v1/policies/${policy1.id}/publish`,
        headers: adminAuthHeader
      });
      expect(publishPolicy1.statusCode).toBe(200);

      const publishPolicy2 = await app.inject({
        method: "POST",
        url: `/v1/policies/${policy2.id}/publish`,
        headers: adminAuthHeader
      });
      expect(publishPolicy2.statusCode).toBe(200);

      const getPolicy = await app.inject({
        method: "GET",
        url: `/v1/policies/${policy2.id}`,
        headers: operatorAuthHeader
      });
      expect(getPolicy.statusCode).toBe(200);
      expect(getPolicy.json().id).toBe(policy2.id);

      const rollbackResponse = await app.inject({
        method: "POST",
        url: `/v1/policies/${policy1.id}/rollback`,
        headers: adminAuthHeader
      });
      expect(rollbackResponse.statusCode).toBe(200);
      const rollbackPayload = rollbackResponse.json();
      expect(rollbackPayload.policy.id).toBe(policy1.id);
      expect(rollbackPayload.previousPublishedPolicyId).toBe(policy2.id);

      const listPolicies = await app.inject({
        method: "GET",
        url: "/v1/policies?tenantId=tenant_alpha",
        headers: adminAuthHeader
      });
      expect(listPolicies.statusCode).toBe(200);
      const listed = listPolicies.json().items as Array<{ id: string; status: string }>;
      expect(listed.some((entry) => entry.id === policy1.id && entry.status === "published")).toBe(true);
      expect(listed.some((entry) => entry.id === policy2.id && entry.status === "draft")).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports policy simulation without executing actions", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const createPolicy = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "sim-v1",
          rules: [
            {
              id: "R-SIM-DENY-TICKET",
              description: "Deny ticket creation in simulation policy",
              priority: 100,
              match: {
                operations: ["create_ticket"]
              },
              decision: "deny"
            }
          ]
        }
      });
      expect(createPolicy.statusCode).toBe(201);
      const createdPolicy = createPolicy.json();

      const simulate = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_policy_sim",
          policyId: createdPolicy.id,
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Simulation only"
          }
        }
      });
      expect(simulate.statusCode).toBe(200);
      const simulationPayload = simulate.json();
      expect(simulationPayload.policySetId).toBe(createdPolicy.id);
      expect(simulationPayload.decision).toBe("deny");
      expect(simulationPayload.ruleIds).toContain("R-SIM-DENY-TICKET");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports policy context matching (environment/dataTypes/timeWindowUtc)", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const createPolicy = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "ctx-v1",
          rules: [
            {
              id: "R-DENY-PROD-PII-BIZHOURS",
              description: "Deny PII changes in prod during business hours (UTC).",
              priority: 100,
              match: {
                environments: ["prod"],
                requiredDataTypes: ["pii"],
                timeWindowUtc: { startHour: 9, endHour: 17 }
              },
              decision: "deny"
            }
          ]
        }
      });
      expect(createPolicy.statusCode).toBe(201);
      const policy = createPolicy.json();

      const matching = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy.id,
          context: {
            environment: "prod",
            dataTypes: ["pii"],
            requestedAt: "2026-02-14T10:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          },
          input: {
            ref: "main"
          }
        }
      });
      expect(matching.statusCode).toBe(200);
      expect(matching.json().decision).toBe("deny");
      expect(matching.json().ruleIds).toContain("R-DENY-PROD-PII-BIZHOURS");

      const outsideWindow = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy.id,
          context: {
            environment: "prod",
            dataTypes: ["pii"],
            requestedAt: "2026-02-14T20:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          },
          input: {
            ref: "main"
          }
        }
      });
      expect(outsideWindow.statusCode).toBe(200);
      expect(outsideWindow.json().decision).toBe("allow");

      const wrongEnv = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy.id,
          context: {
            environment: "dev",
            dataTypes: ["pii"],
            requestedAt: "2026-02-14T10:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          }
        }
      });
      expect(wrongEnv.statusCode).toBe(200);
      expect(wrongEnv.json().decision).toBe("allow");

      const missingDataType = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy.id,
          context: {
            environment: "prod",
            dataTypes: ["public"],
            requestedAt: "2026-02-14T10:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          }
        }
      });
      expect(missingDataType.statusCode).toBe(200);
      expect(missingDataType.json().decision).toBe("allow");

      const createPolicy2 = await app.inject({
        method: "POST",
        url: "/v1/policies",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          version: "ctx-v2",
          rules: [
            {
              id: "R-QUARANTINE-PROD-OVERNIGHT",
              description: "Quarantine prod actions overnight (UTC).",
              priority: 100,
              match: {
                environments: ["prod"],
                timeWindowUtc: { startHour: 22, endHour: 2 }
              },
              decision: "quarantine"
            }
          ]
        }
      });
      expect(createPolicy2.statusCode).toBe(201);
      const policy2 = createPolicy2.json();

      const overnight = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy2.id,
          context: {
            environment: "prod",
            requestedAt: "2026-02-14T23:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          }
        }
      });
      expect(overnight.statusCode).toBe(200);
      expect(overnight.json().decision).toBe("quarantine");

      const notOvernight = await app.inject({
        method: "POST",
        url: "/v1/policies/simulate",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ctx",
          policyId: policy2.id,
          context: {
            environment: "prod",
            requestedAt: "2026-02-14T12:00:00Z"
          },
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          }
        }
      });
      expect(notOvernight.statusCode).toBe(200);
      expect(notOvernight.json().decision).toBe("allow");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("builds evidence graph nodes from receipt ingestion and exposes graph APIs", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_evidence_graph",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Evidence graph ingestion"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const forbiddenStatus = await app.inject({
        method: "GET",
        url: "/v1/admin/evidence/graph/status?tenantId=tenant_alpha",
        headers: operatorAuthHeader
      });
      expect(forbiddenStatus.statusCode).toBe(403);

      const statusResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/evidence/graph/status?tenantId=tenant_alpha",
        headers: adminAuthHeader
      });
      expect(statusResponse.statusCode).toBe(200);
      const statusPayload = statusResponse.json();
      expect(statusPayload.edgeCount).toBeGreaterThan(0);
      expect((statusPayload.nodeCounts.receipt ?? 0) > 0).toBe(true);
      expect((statusPayload.nodeCounts.action ?? 0) > 0).toBe(true);

      const nodesResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/evidence/graph/nodes?tenantId=tenant_alpha&nodeType=receipt&page=1&pageSize=20",
        headers: adminAuthHeader
      });
      expect(nodesResponse.statusCode).toBe(200);
      const nodesPayload = nodesResponse.json();
      expect(nodesPayload.total).toBeGreaterThan(0);
      expect(nodesPayload.items.length).toBeGreaterThan(0);
      expect(nodesPayload.items.every((node: { nodeType: string }) => node.nodeType === "receipt")).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("supports receipt queries by compliance control mappings (control tags)", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const jiraAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_compliance_receipts",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Control-tagged receipt seed"
          }
        }
      });
      expect(jiraAction.statusCode).toBe(202);

      const githubAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_compliance_receipts",
          resource: {
            toolId: "github",
            operation: "push_code",
            target: "repo:oars"
          },
          input: {
            ref: "main"
          }
        }
      });
      expect(githubAction.statusCode).toBe(202);

      const mappingResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/compliance/control-mappings",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2",
          controlId: "CC1.1",
          controlDescription: "Change management evidence (example)",
          requiredNodeTypes: ["receipt"],
          receiptFilters: {
            toolIds: ["jira"],
            operations: ["create_ticket"]
          }
        }
      });
      expect(mappingResponse.statusCode).toBe(200);

      const filtered = await app.inject({
        method: "GET",
        url: "/v1/receipts?tenantId=tenant_alpha&framework=soc2&controlId=CC1.1&limit=200",
        headers: adminAuthHeader
      });
      expect(filtered.statusCode).toBe(200);
      const filteredPayload = filtered.json();
      expect(filteredPayload.items.length).toBeGreaterThan(0);
      expect(
        filteredPayload.items.every(
          (receipt: { resource: { toolId: string; operation: string } }) =>
            receipt.resource.toolId === "jira" && receipt.resource.operation === "create_ticket"
        )
      ).toBe(true);

      const missingMapping = await app.inject({
        method: "GET",
        url: "/v1/receipts?tenantId=tenant_alpha&framework=soc2&controlId=MISSING&limit=50",
        headers: adminAuthHeader
      });
      expect(missingMapping.statusCode).toBe(404);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("manages control mappings and scans compliance coverage from evidence graph", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_compliance",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Compliance mapping seed"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const forbiddenWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/compliance/control-mappings",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2",
          controlId: "CC-1",
          controlDescription: "Control one",
          requiredNodeTypes: ["action", "receipt"]
        }
      });
      expect(forbiddenWrite.statusCode).toBe(403);

      const mappingCovered = await app.inject({
        method: "POST",
        url: "/v1/admin/compliance/control-mappings",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2",
          controlId: "CC-1",
          controlDescription: "Action and receipt evidence must exist",
          requiredNodeTypes: ["action", "receipt"]
        }
      });
      expect(mappingCovered.statusCode).toBe(200);

      const mappingMissing = await app.inject({
        method: "POST",
        url: "/v1/admin/compliance/control-mappings",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2",
          controlId: "CC-2",
          controlDescription: "Evidence bundle must exist",
          requiredNodeTypes: ["evidence_bundle"]
        }
      });
      expect(mappingMissing.statusCode).toBe(200);

      const listMappingsAuditor = await app.inject({
        method: "GET",
        url: "/v1/admin/compliance/control-mappings?tenantId=tenant_alpha&framework=soc2",
        headers: auditorAuthHeader
      });
      expect(listMappingsAuditor.statusCode).toBe(200);
      expect(listMappingsAuditor.json().items.length).toBe(2);

      const scanResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/compliance/coverage/scan",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2"
        }
      });
      expect(scanResponse.statusCode).toBe(200);
      const scanPayload = scanResponse.json();
      expect(scanPayload.totalControls).toBe(2);
      expect(scanPayload.coveredControls).toBe(1);
      expect(
        scanPayload.missingControls.some((entry: { controlId: string }) => entry.controlId === "CC-2")
      ).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("generates signed evidence bundles and verifies tamper detection", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_evidence_bundle",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Bundle signing seed"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const exportResponse = await app.inject({
        method: "POST",
        url: "/v1/evidence/exports",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          framework: "soc2",
          dateFrom: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          dateTo: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        }
      });
      expect(exportResponse.statusCode).toBe(200);
      const bundle = exportResponse.json();
      expect(bundle.bundleId).toBeTruthy();
      expect(bundle.integrity.bundleHash).toBeTruthy();
      expect(bundle.integrity.signature).toBeTruthy();
      expect(bundle.artifactHashes.length).toBe(bundle.summary.receiptCount);

      const verifyResponse = await app.inject({
        method: "POST",
        url: "/v1/evidence/exports/verify",
        headers: adminAuthHeader,
        payload: {
          bundle
        }
      });
      expect(verifyResponse.statusCode).toBe(200);
      const verification = verifyResponse.json();
      expect(verification.isHashValid).toBe(true);
      expect(verification.isSignatureValid).toBe(true);

      const tampered = JSON.parse(JSON.stringify(bundle)) as Record<string, unknown>;
      const tamperedSummary = tampered.summary as Record<string, unknown>;
      tamperedSummary.receiptCount = Number(tamperedSummary.receiptCount ?? 0) + 1;

      const verifyTampered = await app.inject({
        method: "POST",
        url: "/v1/evidence/exports/verify",
        headers: adminAuthHeader,
        payload: {
          bundle: tampered
        }
      });
      expect(verifyTampered.statusCode).toBe(200);
      const tamperedVerification = verifyTampered.json();
      expect(tamperedVerification.isHashValid).toBe(false);
      expect(tamperedVerification.isSignatureValid).toBe(false);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("accepts external RS256 token from trusted JWKS provider", async () => {
    const issuer = "https://idp.example.com";
    const audience = "oars-federated-api";
    const kid = "kid_ext_001";
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048
    });
    const publicJwk = pair.publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();

    const { app, dataFilePath, keyFilePath } = createTestServer({
      jwksOptions: {
        trustedProviders: [
          {
            issuer,
            audience,
            jwks: {
              keys: [
                {
                  ...publicJwk,
                  kid,
                  use: "sig",
                  alg: "RS256"
                }
              ]
            }
          }
        ]
      }
    });

    try {
      const token = signRs256Token({
        privateKeyPem,
        kid,
        issuer,
        audience,
        subject: "federated_user",
        tenantIds: ["tenant_alpha"],
        scopes: ["actions:write", "actions:read", "receipts:read"],
        role: "operator"
      });

      const response = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${token}`
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_external_idp",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "External federated token action"
          }
        }
      });

      expect(response.statusCode).toBe(202);
      const body = response.json();
      expect(body.state).toBe("executed");

      const providersResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/auth/providers",
        headers: adminAuthHeader
      });
      expect(providersResponse.statusCode).toBe(200);
      const providersPayload = providersResponse.json();
      expect(providersPayload.items.some((provider: { issuer: string }) => provider.issuer === issuer)).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("discovers jwks via OIDC metadata and manages refresh scheduler", async () => {
    const issuer = "https://login.example.net";
    const audience = "oars-oidc-api";
    const kid = "kid_oidc_001";
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
    const jwksUrl = `${issuer}/keys`;
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048
    });
    const publicJwk = pair.publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();

    const fetchFn = async (input: string) => {
      if (input === discoveryUrl) {
        return {
          ok: true,
          json: async () => ({
            issuer,
            jwks_uri: jwksUrl
          })
        };
      }
      if (input === jwksUrl) {
        return {
          ok: true,
          json: async () => ({
            keys: [
              {
                ...publicJwk,
                kid,
                use: "sig",
                alg: "RS256"
              }
            ]
          })
        };
      }
      return {
        ok: false,
        json: async () => ({})
      };
    };

    const { app, dataFilePath, keyFilePath } = createTestServer({
      jwksOptions: {
        trustedProviders: [
          {
            issuer,
            audience,
            discoveryUrl
          }
        ],
        fetchFn
      }
    });

    try {
      const token = signRs256Token({
        privateKeyPem,
        kid,
        issuer,
        audience,
        subject: "oidc_user",
        tenantIds: ["tenant_alpha"],
        scopes: ["actions:write", "actions:read"],
        role: "operator"
      });

      const preDiscoveryResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${token}`
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_oidc",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Before discovery should fail"
          }
        }
      });
      expect(preDiscoveryResponse.statusCode).toBe(401);

      const discoverResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/auth/providers/discover",
        headers: adminAuthHeader,
        payload: {
          issuer
        }
      });
      expect(discoverResponse.statusCode).toBe(200);
      const discoverPayload = discoverResponse.json();
      expect(discoverPayload.discoveredIssuers).toContain(issuer);

      const refreshResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/auth/providers/refresh",
        headers: adminAuthHeader,
        payload: {
          issuer
        }
      });
      expect(refreshResponse.statusCode).toBe(200);
      const refreshPayload = refreshResponse.json();
      expect(refreshPayload.refreshedIssuers).toContain(issuer);

      const postRefreshResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: `Bearer ${token}`
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_oidc",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "After discovery and refresh should pass"
          }
        }
      });
      expect(postRefreshResponse.statusCode).toBe(202);

      const statusBeforeStart = await app.inject({
        method: "GET",
        url: "/v1/admin/auth/refresh-scheduler",
        headers: adminAuthHeader
      });
      expect(statusBeforeStart.statusCode).toBe(200);
      expect(statusBeforeStart.json().running).toBe(false);

      const startResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/auth/refresh-scheduler/start",
        headers: adminAuthHeader,
        payload: {
          intervalSeconds: 30,
          discoverOnStart: false
        }
      });
      expect(startResponse.statusCode).toBe(200);
      expect(startResponse.json().running).toBe(true);

      const stopResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/auth/refresh-scheduler/stop",
        headers: adminAuthHeader
      });
      expect(stopResponse.statusCode).toBe(200);
      expect(stopResponse.json().running).toBe(false);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("syncs scim users/groups into tenant members using role mappings", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const forbiddenWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/users",
        headers: operatorAuthHeader,
        payload: {
          externalId: "u-operator",
          userName: "operator@example.com",
          displayName: "Operator Example",
          emails: ["operator@example.com"],
          active: true
        }
      });
      expect(forbiddenWrite.statusCode).toBe(403);

      const upsertUser1 = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/users",
        headers: adminAuthHeader,
        payload: {
          externalId: "u-active-1",
          userName: "alice@example.com",
          displayName: "Alice",
          emails: ["alice@example.com"],
          active: true
        }
      });
      expect(upsertUser1.statusCode).toBe(201);

      const upsertUser2 = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/users",
        headers: adminAuthHeader,
        payload: {
          externalId: "u-inactive-1",
          userName: "bob@example.com",
          displayName: "Bob",
          emails: ["bob@example.com"],
          active: false
        }
      });
      expect(upsertUser2.statusCode).toBe(201);

      const listUsersPage1 = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/scim/users?page=1&pageSize=1",
        headers: adminAuthHeader
      });
      expect(listUsersPage1.statusCode).toBe(200);
      const usersPage1 = listUsersPage1.json();
      expect(usersPage1.total).toBe(2);
      expect(usersPage1.page).toBe(1);
      expect(usersPage1.pageSize).toBe(1);
      expect(usersPage1.items).toHaveLength(1);

      const upsertGroup = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/groups",
        headers: adminAuthHeader,
        payload: {
          externalId: "g-admins",
          displayName: "IdP Admins",
          memberExternalUserIds: ["u-active-1", "u-inactive-1"]
        }
      });
      expect(upsertGroup.statusCode).toBe(201);

      const listGroups = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/scim/groups?page=1&pageSize=10",
        headers: adminAuthHeader
      });
      expect(listGroups.statusCode).toBe(200);
      expect(listGroups.json().total).toBe(1);

      const upsertMapping = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/role-mappings",
        headers: adminAuthHeader,
        payload: {
          groupDisplayName: "IdP Admins",
          role: "admin"
        }
      });
      expect(upsertMapping.statusCode).toBe(201);

      const listMappings = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/scim/role-mappings?page=1&pageSize=10",
        headers: adminAuthHeader
      });
      expect(listMappings.statusCode).toBe(200);
      expect(listMappings.json().total).toBe(1);

      const syncResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/sync",
        headers: adminAuthHeader
      });
      expect(syncResponse.statusCode).toBe(200);
      const syncPayload = syncResponse.json();
      expect(syncPayload.assignedCount).toBe(1);
      expect(syncPayload.skippedInactiveCount).toBe(1);

      const membersResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/members",
        headers: adminAuthHeader
      });
      expect(membersResponse.statusCode).toBe(200);
      const membersPayload = membersResponse.json();
      expect(
        membersPayload.items.some((member: { subject: string; role: string }) => member.subject === "alice@example.com" && member.role === "admin")
      ).toBe(true);
      expect(
        membersPayload.items.some((member: { subject: string }) => member.subject === "bob@example.com")
      ).toBe(false);

      const forbiddenDeprovision = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/deprovision",
        headers: operatorAuthHeader,
        payload: {
          externalId: "u-active-1"
        }
      });
      expect(forbiddenDeprovision.statusCode).toBe(403);

      const deprovisionResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/scim/deprovision",
        headers: adminAuthHeader,
        payload: {
          externalId: "u-active-1"
        }
      });
      expect(deprovisionResponse.statusCode).toBe(200);
      const deprovisionedUser = deprovisionResponse.json();
      expect(deprovisionedUser.active).toBe(false);

      const membersAfterDeprovision = await app.inject({
        method: "GET",
        url: "/v1/admin/tenants/tenant_alpha/members",
        headers: adminAuthHeader
      });
      expect(membersAfterDeprovision.statusCode).toBe(200);
      expect(
        membersAfterDeprovision
          .json()
          .items.some((member: { subject: string }) => member.subject === "alice@example.com")
      ).toBe(false);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("queues failed SIEM deliveries and flushes retry queue", async () => {
    let attempt = 0;
    const fetchFn = async (_input: string, _init?: RequestInit) => {
      attempt += 1;
      const shouldFail = attempt <= 3;
      return {
        ok: !shouldFail,
        status: shouldFail ? 500 : 200,
        text: async () => (shouldFail ? "failure" : "ok")
      };
    };

    const { app, dataFilePath, keyFilePath } = createTestServer({
      siemOptions: {
        targets: [
          {
            id: "test_webhook",
            type: "generic_webhook",
            url: "https://siem.example.test/ingest"
          }
        ],
        fetchFn,
        autoStartRetry: false
      }
    });

    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_siem",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Trigger SIEM delivery"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const statusBefore = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/status",
        headers: adminAuthHeader
      });
      expect(statusBefore.statusCode).toBe(200);
      const beforePayload = statusBefore.json();
      expect(beforePayload.queueLength).toBeGreaterThan(0);

      const flushResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/flush",
        headers: adminAuthHeader
      });
      expect(flushResponse.statusCode).toBe(200);
      const flushPayload = flushResponse.json();
      expect(flushPayload.processed).toBeGreaterThan(0);

      const statusAfter = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/status",
        headers: adminAuthHeader
      });
      expect(statusAfter.statusCode).toBe(200);
      const afterPayload = statusAfter.json();
      expect(afterPayload.queueLength).toBe(0);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("applies SIEM queue backpressure and persists retry queue across restart", async () => {
    const suffix = createId("siemq");
    const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
    const dataFilePath = join(baseDir, `${suffix}-state.json`);
    const keyFilePath = join(baseDir, `${suffix}-keys.json`);
    const ledgerFilePath = join(baseDir, `${suffix}-ledger.ndjson`);
    const vaultFilePath = join(baseDir, `${suffix}-vault.json`);
    const queueFilePath = join(baseDir, `${suffix}-siem-queue.json`);

    const failingFetch = async (_input: string, _init?: RequestInit) => ({
      ok: false,
      status: 500,
      text: async () => "failure"
    });

    const context1 = createPlatformContext({
      dataFilePath,
      keyFilePath,
      ledgerFilePath,
      vaultFilePath,
      siemOptions: {
        targets: [
          {
            id: "persisted_queue_target",
            type: "generic_webhook",
            url: "https://siem.example.test/persisted"
          }
        ],
        fetchFn: failingFetch,
        autoStartRetry: false,
        maxQueueSize: 1,
        queueFilePath
      }
    });
    const app1 = buildServer(context1);

    try {
      const actionOne = await app1.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_backpressure_1",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Queue pressure one"
          }
        }
      });
      expect(actionOne.statusCode).toBe(202);

      const actionTwo = await app1.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_backpressure_2",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Queue pressure two"
          }
        }
      });
      expect(actionTwo.statusCode).toBe(202);

      const status1 = await app1.inject({
        method: "GET",
        url: "/v1/admin/siem/status",
        headers: adminAuthHeader
      });
      expect(status1.statusCode).toBe(200);
      const statusPayload1 = status1.json();
      expect(statusPayload1.queueLength).toBe(1);
      expect(statusPayload1.backpressureDropCount).toBeGreaterThan(0);
    } finally {
      await app1.close();
    }

    const successFetch = async (_input: string, _init?: RequestInit) => ({
      ok: true,
      status: 200,
      text: async () => "ok"
    });
    const context2 = createPlatformContext({
      dataFilePath,
      keyFilePath,
      ledgerFilePath,
      vaultFilePath,
      siemOptions: {
        targets: [
          {
            id: "persisted_queue_target",
            type: "generic_webhook",
            url: "https://siem.example.test/persisted"
          }
        ],
        fetchFn: successFetch,
        autoStartRetry: false,
        maxQueueSize: 1,
        queueFilePath
      }
    });
    const app2 = buildServer(context2);

    try {
      const status2 = await app2.inject({
        method: "GET",
        url: "/v1/admin/siem/status",
        headers: adminAuthHeader
      });
      expect(status2.statusCode).toBe(200);
      expect(status2.json().queueLength).toBeGreaterThan(0);

      const flush = await app2.inject({
        method: "POST",
        url: "/v1/admin/siem/flush",
        headers: adminAuthHeader
      });
      expect(flush.statusCode).toBe(200);
      expect(flush.json().processed).toBeGreaterThan(0);

      const statusAfterFlush = await app2.inject({
        method: "GET",
        url: "/v1/admin/siem/status",
        headers: adminAuthHeader
      });
      expect(statusAfterFlush.statusCode).toBe(200);
      expect(statusAfterFlush.json().queueLength).toBe(0);
    } finally {
      await app2.close();
      cleanup([baseDir, dataFilePath, keyFilePath, ledgerFilePath, vaultFilePath, queueFilePath]);
    }
  });

  it("persists SIEM dead letters and supports replay and resolve", async () => {
    let shouldFail = true;
    const fetchFn = async (_input: string, _init?: RequestInit) => ({
      ok: !shouldFail,
      status: shouldFail ? 500 : 200,
      text: async () => (shouldFail ? "failure" : "ok")
    });

    const { app, dataFilePath, keyFilePath } = createTestServer({
      siemOptions: {
        targets: [
          {
            id: "dlq_webhook",
            type: "generic_webhook",
            url: "https://siem.example.test/dead-letter"
          }
        ],
        fetchFn,
        autoStartRetry: false,
        maxAttempts: 2
      }
    });

    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_siem_dlq",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Trigger dead-letter path"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const flushResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/flush",
        headers: adminAuthHeader
      });
      expect(flushResponse.statusCode).toBe(200);
      expect(flushResponse.json().processed).toBeGreaterThan(0);

      const deadLettersResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/dead-letters?tenantId=tenant_alpha&status=open&page=1&pageSize=20",
        headers: adminAuthHeader
      });
      expect(deadLettersResponse.statusCode).toBe(200);
      const deadLettersPayload = deadLettersResponse.json();
      expect(deadLettersPayload.total).toBeGreaterThan(0);
      expect(deadLettersPayload.items.length).toBeGreaterThan(0);
      const deadLetterId = deadLettersPayload.items[0].id as string;

      shouldFail = false;
      const replayResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/dead-letters/replay",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          deadLetterId
        }
      });
      expect(replayResponse.statusCode).toBe(200);
      const replayPayload = replayResponse.json();
      expect(replayPayload.replaySucceeded).toBe(true);
      expect(replayPayload.deadLetter.status).toBe("replayed");

      const resolveResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/dead-letters/resolve",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          deadLetterId
        }
      });
      expect(resolveResponse.statusCode).toBe(200);
      expect(resolveResponse.json().status).toBe("resolved");

      const resolvedListResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/dead-letters?tenantId=tenant_alpha&status=resolved&page=1&pageSize=20",
        headers: adminAuthHeader
      });
      expect(resolvedListResponse.statusCode).toBe(200);
      expect(
        resolvedListResponse
          .json()
          .items.some((entry: { id: string }) => entry.id === deadLetterId)
      ).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("enforces tenant scoping for SIEM dead-letter operations and returns requestId on errors", async () => {
    const fetchFn = async (_input: string, _init?: RequestInit) => ({
      ok: false,
      status: 500,
      text: async () => "failure"
    });

    const { app, dataFilePath, keyFilePath } = createTestServer({
      siemOptions: {
        targets: [
          {
            id: "scoped_webhook",
            type: "generic_webhook",
            url: "https://siem.example.test/scoped"
          }
        ],
        fetchFn,
        autoStartRetry: false,
        maxAttempts: 2
      }
    });

    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_siem_scope",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Trigger dead-letter scope checks"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const flushResponse = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/flush",
        headers: adminAuthHeader
      });
      expect(flushResponse.statusCode).toBe(200);

      const listResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/dead-letters?tenantId=tenant_alpha&status=open&page=1&pageSize=20",
        headers: adminAuthHeader
      });
      expect(listResponse.statusCode).toBe(200);
      const listed = listResponse.json();
      expect(listed.items.length).toBeGreaterThan(0);
      const deadLetterId = listed.items[0].id as string;

      const mismatchReplay = await app.inject({
        method: "POST",
        url: "/v1/admin/siem/dead-letters/replay",
        headers: {
          ...adminAuthHeader,
          "x-request-id": "req_mismatch_replay"
        },
        payload: {
          tenantId: "tenant_bravo",
          deadLetterId
        }
      });
      expect(mismatchReplay.statusCode).toBe(400);
      const replayError = mismatchReplay.json();
      expect(replayError.error.requestId).toBe("req_mismatch_replay");

      const missingTenantList = await app.inject({
        method: "GET",
        url: "/v1/admin/siem/dead-letters?status=open&page=1&pageSize=20",
        headers: {
          ...adminAuthHeader,
          "x-request-id": "req_missing_tenant"
        }
      });
      expect(missingTenantList.statusCode).toBe(400);
      const listError = missingTenantList.json();
      expect(listError.error.code).toBe("validation_error");
      expect(listError.error.requestId).toBe("req_missing_tenant");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("appends immutable ledger entries and detects tampering", async () => {
    const { app, dataFilePath, keyFilePath, ledgerFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_ledger",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Ledger append verification"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const forbiddenStatus = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/status",
        headers: operatorAuthHeader
      });
      expect(forbiddenStatus.statusCode).toBe(403);

      const statusResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/status",
        headers: adminAuthHeader
      });
      expect(statusResponse.statusCode).toBe(200);
      const statusPayload = statusResponse.json();
      expect(statusPayload.totalEntries).toBeGreaterThan(0);

      const entriesResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/entries?tenantId=tenant_alpha&limit=20",
        headers: adminAuthHeader
      });
      expect(entriesResponse.statusCode).toBe(200);
      const entriesPayload = entriesResponse.json();
      expect(entriesPayload.total).toBeGreaterThan(0);
      expect(entriesPayload.items.some((entry: { entityType: string }) => entry.entityType === "receipt")).toBe(true);
      expect(
        entriesPayload.items.some((entry: { entityType: string }) => entry.entityType === "security_event")
      ).toBe(true);

      const verifyResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/verify",
        headers: adminAuthHeader
      });
      expect(verifyResponse.statusCode).toBe(200);
      expect(verifyResponse.json().isValid).toBe(true);

      const lines = readFileSync(ledgerFilePath, "utf8")
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      expect(lines.length).toBeGreaterThan(0);
      const first = JSON.parse(lines[0] as string) as Record<string, unknown>;
      first.payloadHash = "tampered_hash";
      lines[0] = JSON.stringify(first);
      writeFileSync(ledgerFilePath, `${lines.join("\n")}\n`, "utf8");

      const verifyTampered = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/verify",
        headers: adminAuthHeader
      });
      expect(verifyTampered.statusCode).toBe(200);
      const tamperedPayload = verifyTampered.json();
      expect(tamperedPayload.isValid).toBe(false);
      expect(tamperedPayload.errors.length).toBeGreaterThan(0);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath, ledgerFilePath]);
    }
  });

  it("enforces legal hold and applies ledger retention policy", async () => {
    const { app, dataFilePath, keyFilePath, ledgerFilePath } = createTestServer();
    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_retention",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Retention control test"
          }
        }
      });
      expect(actionResponse.statusCode).toBe(202);

      const entriesBefore = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/entries?tenantId=tenant_alpha&limit=200",
        headers: adminAuthHeader
      });
      expect(entriesBefore.statusCode).toBe(200);
      const beforeCount = entriesBefore.json().total as number;
      expect(beforeCount).toBeGreaterThan(0);

      const forbiddenPolicyWrite = await app.inject({
        method: "POST",
        url: "/v1/admin/ledger/retention",
        headers: operatorAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          retentionDays: 1,
          legalHold: true,
          reason: "audit lock"
        }
      });
      expect(forbiddenPolicyWrite.statusCode).toBe(403);

      const setLegalHold = await app.inject({
        method: "POST",
        url: "/v1/admin/ledger/retention",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          retentionDays: 1,
          legalHold: true,
          reason: "Audit legal hold"
        }
      });
      expect(setLegalHold.statusCode).toBe(200);
      expect(setLegalHold.json().legalHold).toBe(true);

      const applyDuringHold = await app.inject({
        method: "POST",
        url: "/v1/admin/ledger/retention/apply",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          nowIso: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
        }
      });
      expect(applyDuringHold.statusCode).toBe(400);

      const disableLegalHold = await app.inject({
        method: "POST",
        url: "/v1/admin/ledger/retention",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          retentionDays: 1,
          legalHold: false,
          reason: "hold released"
        }
      });
      expect(disableLegalHold.statusCode).toBe(200);
      expect(disableLegalHold.json().legalHold).toBe(false);

      const applyRetention = await app.inject({
        method: "POST",
        url: "/v1/admin/ledger/retention/apply",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          nowIso: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
        }
      });
      expect(applyRetention.statusCode).toBe(200);
      const applyPayload = applyRetention.json();
      expect(applyPayload.prunedCount).toBeGreaterThan(0);

      const entriesAfter = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/entries?tenantId=tenant_alpha&limit=200",
        headers: adminAuthHeader
      });
      expect(entriesAfter.statusCode).toBe(200);
      const afterCount = entriesAfter.json().total as number;
      expect(afterCount).toBeLessThan(beforeCount);

      const verifyResponse = await app.inject({
        method: "GET",
        url: "/v1/admin/ledger/verify",
        headers: adminAuthHeader
      });
      expect(verifyResponse.statusCode).toBe(200);
      expect(verifyResponse.json().isValid).toBe(true);
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath, ledgerFilePath]);
    }
  });

  it("creates backups, restores snapshots, and records DR drill evidence", async () => {
    const {
      app,
      dataFilePath,
      keyFilePath,
      ledgerFilePath,
      vaultFilePath,
      backupRootPath,
      drillReportsPath,
      drillWorkspacePath
    } = createTestServer();
    try {
      const seedAction = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: adminAuthHeader,
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_backup",
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Seed backup artifacts"
          }
        }
      });
      expect(seedAction.statusCode).toBe(202);

      const seedSecret = await app.inject({
        method: "POST",
        url: "/v1/admin/tenants/tenant_alpha/vault/secrets",
        headers: adminAuthHeader,
        payload: {
          connectorId: "database",
          key: "connection",
          value: "postgres://db.internal:5432/oars"
        }
      });
      expect(seedSecret.statusCode).toBe(200);

      const forbiddenCreate = await app.inject({
        method: "POST",
        url: "/v1/admin/backups",
        headers: operatorAuthHeader,
        payload: {
          reason: "operator should not run backups"
        }
      });
      expect(forbiddenCreate.statusCode).toBe(403);

      const invalidRestore = await app.inject({
        method: "POST",
        url: "/v1/admin/backups/restore",
        headers: {
          ...adminAuthHeader,
          "x-request-id": "req_backup_restore_invalid"
        },
        payload: {
          backupId: "../escape",
          reason: "path traversal attempt"
        }
      });
      expect(invalidRestore.statusCode).toBe(400);
      expect(invalidRestore.json().error.requestId).toBe("req_backup_restore_invalid");

      const createBackup = await app.inject({
        method: "POST",
        url: "/v1/admin/backups",
        headers: adminAuthHeader,
        payload: {
          reason: "pre-release checkpoint"
        }
      });
      expect(createBackup.statusCode).toBe(201);
      const backupPayload = createBackup.json();
      expect(backupPayload.backupId).toBeTruthy();
      const backupId = backupPayload.backupId as string;

      const listBackups = await app.inject({
        method: "GET",
        url: "/v1/admin/backups?limit=5",
        headers: adminAuthHeader
      });
      expect(listBackups.statusCode).toBe(200);
      expect(listBackups.json().items.some((item: { backupId: string }) => item.backupId === backupId)).toBe(true);

      writeFileSync(dataFilePath, JSON.stringify({ actions: [] }, null, 2), "utf8");
      const corrupted = JSON.parse(readFileSync(dataFilePath, "utf8")) as { actions?: unknown[] };
      expect(Array.isArray(corrupted.actions)).toBe(true);
      expect(corrupted.actions?.length).toBe(0);

      const restoreBackup = await app.inject({
        method: "POST",
        url: "/v1/admin/backups/restore",
        headers: adminAuthHeader,
        payload: {
          backupId,
          reason: "restore validation",
          createPreRestoreSnapshot: false
        }
      });
      expect(restoreBackup.statusCode).toBe(200);
      const restorePayload = restoreBackup.json();
      expect(restorePayload.restoredFileIds).toContain("state");
      expect(restorePayload.restartRequired).toBe(true);
      const restoredState = JSON.parse(readFileSync(dataFilePath, "utf8")) as { actions?: unknown[] };
      expect(Array.isArray(restoredState.actions)).toBe(true);
      expect((restoredState.actions ?? []).length).toBeGreaterThan(0);

      const runDrill = await app.inject({
        method: "POST",
        url: "/v1/admin/backups/drills",
        headers: adminAuthHeader,
        payload: {
          reason: "quarterly drill"
        }
      });
      expect(runDrill.statusCode).toBe(200);
      const drillPayload = runDrill.json();
      expect(drillPayload.status).toBe("passed");
      expect(drillPayload.reportPath).toBeTruthy();

      const listDrills = await app.inject({
        method: "GET",
        url: "/v1/admin/backups/drills?limit=10",
        headers: adminAuthHeader
      });
      expect(listDrills.statusCode).toBe(200);
      expect(listDrills.json().items.length).toBeGreaterThan(0);

      const status = await app.inject({
        method: "GET",
        url: "/v1/admin/backups/status",
        headers: adminAuthHeader
      });
      expect(status.statusCode).toBe(200);
      const statusPayload = status.json();
      expect(statusPayload.backupCount).toBeGreaterThan(0);
      expect(statusPayload.drillCount).toBeGreaterThan(0);
    } finally {
      await app.close();
      cleanup([
        dataFilePath,
        keyFilePath,
        ledgerFilePath,
        vaultFilePath,
        backupRootPath,
        drillReportsPath,
        drillWorkspacePath
      ]);
    }
  });
});
