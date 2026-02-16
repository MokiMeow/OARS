import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { TenantMemberRecord, TenantRecord, TenantRole } from "../types/domain.js";
import { SecurityEventService } from "./security-event-service.js";

export class TenantAdminService {
  constructor(
    private readonly store: PlatformStore,
    private readonly securityEventService: SecurityEventService
  ) {}

  async createTenant(
    tenantId: string,
    displayName: string,
    ownerSubject: string,
    createdBy: string
  ): Promise<{ tenant: TenantRecord; owner: TenantMemberRecord }> {
    const existing = await this.store.getTenant(tenantId);
    if (existing) {
      throw new Error(`Tenant already exists: ${tenantId}`);
    }

    const now = nowIso();
    const tenant: TenantRecord = {
      id: createId("ten"),
      tenantId,
      displayName,
      status: "active",
      createdAt: now,
      updatedAt: now,
      createdBy
    };
    await this.store.saveTenant(tenant);

    const owner = await this.upsertMember(tenantId, ownerSubject, "owner", createdBy);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "tenant.created",
      payload: {
        tenantId,
        displayName,
        ownerSubject,
        createdBy
      }
    });
    return {
      tenant,
      owner
    };
  }

  async listTenants(): Promise<TenantRecord[]> {
    return this.store.listTenants();
  }

  async upsertMember(
    tenantId: string,
    subject: string,
    role: TenantRole,
    createdBy: string
  ): Promise<TenantMemberRecord> {
    const existing = await this.store.getTenantMember(tenantId, subject);
    if (existing) {
      existing.role = role;
      existing.updatedAt = nowIso();
      await this.store.saveTenantMember(existing);
      await this.securityEventService.publish({
        tenantId,
        source: "admin",
        eventType: "tenant_member.updated",
        payload: {
          subject,
          role,
          updatedBy: createdBy
        }
      });
      return existing;
    }

    const member: TenantMemberRecord = {
      id: createId("mbr"),
      tenantId,
      subject,
      role,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      createdBy
    };
    await this.store.saveTenantMember(member);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "tenant_member.created",
      payload: {
        subject,
        role,
        createdBy
      }
    });
    return member;
  }

  async listMembers(tenantId: string): Promise<TenantMemberRecord[]> {
    return this.store.listTenantMembers(tenantId);
  }

  async removeMember(tenantId: string, subject: string, removedBy: string): Promise<boolean> {
    const deleted = await this.store.deleteTenantMember(tenantId, subject);
    if (deleted) {
      await this.securityEventService.publish({
        tenantId,
        source: "admin",
        eventType: "tenant_member.deleted",
        payload: {
          subject,
          removedBy
        }
      });
    }
    return deleted;
  }
}
