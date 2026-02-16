import { FilePlatformStore, type PlatformStore } from "../store/platform-store.js";
import { PostgresPlatformStore } from "../store/postgres-platform-store.js";
import { ActionService } from "./action-service.js";
import { AlertService } from "./alert-service.js";
import { AlertRoutingService } from "./alert-routing-service.js";
import { ApprovalService } from "./approval-service.js";
import { AuthService } from "./auth-service.js";
import { BackupRecoveryService } from "./backup-recovery-service.js";
import { DataProtectionService, type DataProtectionServiceOptions } from "./data-protection-service.js";
import { ExecutionService } from "./execution-service.js";
import { EvidenceGraphService } from "./evidence-graph-service.js";
import { EvidenceBundleService } from "./evidence-bundle-service.js";
import { ControlMappingService } from "./control-mapping-service.js";
import { ImmutableLedgerService } from "./immutable-ledger-service.js";
import { JwksService, type JwksServiceOptions } from "./jwks-service.js";
import { LedgerGovernanceService } from "./ledger-governance-service.js";
import { OperationsService } from "./operations-service.js";
import { PolicyService } from "./policy-service.js";
import { ReceiptService } from "./receipt-service.js";
import { RiskService } from "./risk-service.js";
import { ScimService } from "./scim-service.js";
import { SecurityEventService } from "./security-event-service.js";
import { ServiceIdentityService, type ServiceIdentityServiceOptions } from "./service-identity-service.js";
import { SiemDeliveryService, type SiemDeliveryOptions } from "./siem-delivery-service.js";
import { ServiceAccountService } from "./service-account-service.js";
import { SigningKeyService } from "./signing-key-service.js";
import { TenantAdminService } from "./tenant-admin-service.js";
import { VaultSecretService } from "./vault-secret-service.js";
import { ConnectorRegistry } from "../connectors/registry.js";
import type { AuthServiceOptions } from "./auth-service.js";
import { createExecutionBackplaneFromEnv, type ExecutionBackplane } from "../backplane/execution-backplane.js";
import { dirname } from "node:path";

export interface PlatformContext {
  store: PlatformStore;
  executionBackplane: ExecutionBackplane | null;
  actionService: ActionService;
  alertService: AlertService;
  alertRoutingService: AlertRoutingService;
  approvalService: ApprovalService;
  authService: AuthService;
  backupRecoveryService: BackupRecoveryService;
  connectorRegistry: ConnectorRegistry;
  executionService: ExecutionService;
  vaultSecretService: VaultSecretService;
  evidenceGraphService: EvidenceGraphService;
  evidenceBundleService: EvidenceBundleService;
  controlMappingService: ControlMappingService;
  dataProtectionService: DataProtectionService;
  serviceIdentityService: ServiceIdentityService;
  operationsService: OperationsService;
  jwksService: JwksService;
  immutableLedgerService: ImmutableLedgerService;
  ledgerGovernanceService: LedgerGovernanceService;
  policyService: PolicyService;
  receiptService: ReceiptService;
  riskService: RiskService;
  scimService: ScimService;
  siemDeliveryService: SiemDeliveryService;
  securityEventService: SecurityEventService;
  serviceAccountService: ServiceAccountService;
  signingKeyService: SigningKeyService;
  tenantAdminService: TenantAdminService;
}

export interface PlatformContextOptions {
  dataFilePath?: string | undefined;
  keyFilePath?: string | undefined;
  ledgerFilePath?: string | undefined;
  vaultFilePath?: string | undefined;
  backupRootPath?: string | undefined;
  drillReportsPath?: string | undefined;
  drillWorkspacePath?: string | undefined;
  storeMode?: "file" | "postgres" | undefined;
  postgresUrl?: string | undefined;
  dataProtectionOptions?: DataProtectionServiceOptions | undefined;
  serviceIdentityOptions?: ServiceIdentityServiceOptions | undefined;
  authOptions?: AuthServiceOptions | undefined;
  jwksOptions?: JwksServiceOptions | undefined;
  siemOptions?: SiemDeliveryOptions | undefined;
}

export function createPlatformContext(options?: PlatformContextOptions): PlatformContext {
  const dataFilePath = options?.dataFilePath ?? "data/oars-state.json";
  const keyFilePath = options?.keyFilePath ?? "data/signing-keys.json";
  const ledgerFilePath = options?.ledgerFilePath ?? process.env.OARS_IMMUTABLE_LEDGER_PATH ?? "data/immutable-ledger.ndjson";
  const vaultFilePath = options?.vaultFilePath ?? "data/vault-secrets.json";
  const siemRetryQueuePath =
    options?.siemOptions?.queueFilePath ?? process.env.OARS_SIEM_RETRY_QUEUE_PATH ?? "data/siem-retry-queue.json";

  const dataProtectionService = new DataProtectionService(options?.dataProtectionOptions);

  const storeMode = (options?.storeMode ?? (process.env.OARS_STORE ?? "file")).trim().toLowerCase();
  const postgresUrl = options?.postgresUrl ?? process.env.OARS_POSTGRES_URL ?? process.env.DATABASE_URL;
  const store: PlatformStore =
    storeMode === "postgres"
      ? new PostgresPlatformStore(
          postgresUrl ?? "postgres://postgres:postgres@localhost:5432/oars",
          dataProtectionService
        )
      : new FilePlatformStore(dataFilePath, dataProtectionService);
  const executionBackplane = createExecutionBackplaneFromEnv({
    postgresUrl,
    dataDir: dirname(dataFilePath)
  });
  const signingKeyService = new SigningKeyService(keyFilePath);
  const immutableLedgerService = new ImmutableLedgerService(ledgerFilePath);
  const vaultSecretService = new VaultSecretService(vaultFilePath);
  const backupRecoveryService = new BackupRecoveryService({
    managedFiles: [
      {
        id: "state",
        path: dataFilePath,
        required: true
      },
      {
        id: "signing_keys",
        path: keyFilePath,
        required: false
      },
      {
        id: "immutable_ledger",
        path: ledgerFilePath,
        required: false
      },
      {
        id: "vault_secrets",
        path: vaultFilePath,
        required: false
      },
      {
        id: "siem_retry_queue",
        path: siemRetryQueuePath,
        required: false
      }
    ],
    backupRootPath: options?.backupRootPath,
    drillReportsPath: options?.drillReportsPath,
    drillWorkspacePath: options?.drillWorkspacePath
  });
  const policyService = new PolicyService(store);
  const approvalService = new ApprovalService(store);
  const connectorRegistry = new ConnectorRegistry();
  const executionService = new ExecutionService(connectorRegistry, vaultSecretService);
  const evidenceGraphService = new EvidenceGraphService(store);
  const evidenceBundleService = new EvidenceBundleService(signingKeyService, evidenceGraphService);
  const controlMappingService = new ControlMappingService(store, evidenceGraphService);
  const serviceIdentityService = new ServiceIdentityService(options?.serviceIdentityOptions);
  const riskService = new RiskService();
  const siemDeliveryService = new SiemDeliveryService(options?.siemOptions);
  const securityEventService = new SecurityEventService(store, siemDeliveryService, undefined, immutableLedgerService);
  const ledgerGovernanceService = new LedgerGovernanceService(store, immutableLedgerService, securityEventService);
  const receiptService = new ReceiptService(
    store,
    signingKeyService,
    securityEventService,
    immutableLedgerService,
    evidenceGraphService
  );
  const jwksService = new JwksService(options?.jwksOptions);
  const authService = new AuthService(options?.authOptions, jwksService);
  const alertRoutingService = new AlertRoutingService(store);
  const alertService = new AlertService(store, securityEventService, alertRoutingService);
  const tenantAdminService = new TenantAdminService(store, securityEventService);
  const scimService = new ScimService(store, tenantAdminService, securityEventService);
  const serviceAccountService = new ServiceAccountService(store, securityEventService);
  const operationsService = new OperationsService(
    store,
    siemDeliveryService,
    serviceIdentityService,
    backupRecoveryService
  );
  const actionService = new ActionService(
    store,
    executionBackplane,
    policyService,
    approvalService,
    executionService,
    riskService,
    receiptService,
    alertService
  );

  return {
    store,
    executionBackplane,
    actionService,
    alertService,
    alertRoutingService,
    approvalService,
    authService,
    backupRecoveryService,
    connectorRegistry,
    executionService,
    vaultSecretService,
    evidenceGraphService,
    evidenceBundleService,
    controlMappingService,
    dataProtectionService,
    serviceIdentityService,
    operationsService,
    jwksService,
    immutableLedgerService,
    ledgerGovernanceService,
    policyService,
    receiptService,
    riskService,
    scimService,
    siemDeliveryService,
    securityEventService,
    serviceAccountService,
    signingKeyService,
    tenantAdminService
  };
}
