import { randomBytes } from "node:crypto";
import { createId } from "../../lib/id.js";
import { sha256Hex } from "../../lib/hash.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { ServiceAccountRecord } from "../types/domain.js";
import { SecurityEventService } from "./security-event-service.js";

interface CreateServiceAccountInput {
  tenantId: string;
  name: string;
  role: ServiceAccountRecord["role"];
  scopes: string[];
  createdBy: string;
}

interface AuthenticatedServiceAccount {
  account: ServiceAccountRecord;
}

export class ServiceAccountService {
  constructor(
    private readonly store: PlatformStore,
    private readonly securityEventService: SecurityEventService
  ) {}

  async create(input: CreateServiceAccountInput): Promise<{ account: ServiceAccountRecord; clientSecret: string }> {
    const clientSecret = randomBytes(32).toString("hex");
    const account: ServiceAccountRecord = {
      id: createId("svc"),
      tenantId: input.tenantId,
      name: input.name,
      role: input.role,
      scopes: [...new Set(input.scopes)].sort((a, b) => a.localeCompare(b)),
      secretHash: sha256Hex(clientSecret),
      createdAt: nowIso(),
      updatedAt: nowIso(),
      createdBy: input.createdBy,
      status: "active"
    };

    await this.store.saveServiceAccount(account);
    await this.securityEventService.publish({
      tenantId: input.tenantId,
      source: "admin",
      eventType: "service_account.created",
      payload: {
        serviceAccountId: account.id,
        role: account.role,
        scopes: account.scopes
      }
    });

    return {
      account,
      clientSecret
    };
  }

  async list(tenantId: string): Promise<ServiceAccountRecord[]> {
    return this.store.listServiceAccountsByTenant(tenantId);
  }

  async authenticate(accountId: string, clientSecret: string, tenantId: string): Promise<AuthenticatedServiceAccount> {
    const account = await this.store.getServiceAccount(accountId);
    if (!account || account.tenantId !== tenantId) {
      throw new Error("Invalid client credentials.");
    }
    if (account.status !== "active") {
      throw new Error("Service account is disabled.");
    }

    const hash = sha256Hex(clientSecret);
    if (hash !== account.secretHash) {
      throw new Error("Invalid client credentials.");
    }

    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "service_account.authenticated",
      payload: {
        serviceAccountId: account.id
      }
    });

    return { account };
  }
}
