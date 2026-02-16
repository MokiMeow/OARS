import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type {
  ScimGroupRecord,
  ScimRoleMappingRecord,
  ScimUserRecord,
  TenantRole
} from "../types/domain.js";
import { SecurityEventService } from "./security-event-service.js";
import { TenantAdminService } from "./tenant-admin-service.js";

const rolePriority: Record<Exclude<TenantRole, "owner">, number> = {
  admin: 3,
  operator: 2,
  auditor: 1
};

interface UpsertScimUserInput {
  externalId: string;
  userName: string;
  displayName: string;
  emails: string[];
  active: boolean;
}

interface UpsertScimGroupInput {
  externalId: string;
  displayName: string;
  memberExternalUserIds: string[];
}

interface SyncResult {
  assignedCount: number;
  skippedInactiveCount: number;
  unmappedGroupCount: number;
}

interface PagedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export class ScimService {
  constructor(
    private readonly store: PlatformStore,
    private readonly tenantAdminService: TenantAdminService,
    private readonly securityEventService: SecurityEventService
  ) {}

  async upsertUser(tenantId: string, input: UpsertScimUserInput, actor: string): Promise<ScimUserRecord> {
    const existing = await this.store.getScimUserByExternalId(tenantId, input.externalId);
    if (existing) {
      existing.userName = input.userName;
      existing.displayName = input.displayName;
      existing.emails = [...new Set(input.emails)];
      existing.active = input.active;
      existing.updatedAt = nowIso();
      await this.store.saveScimUser(existing);
      await this.securityEventService.publish({
        tenantId,
        source: "admin",
        eventType: "scim.user.updated",
        payload: {
          externalId: input.externalId,
          userName: input.userName,
          updatedBy: actor
        }
      });
      return existing;
    }

    const user: ScimUserRecord = {
      id: createId("scim_usr"),
      tenantId,
      externalId: input.externalId,
      userName: input.userName,
      displayName: input.displayName,
      emails: [...new Set(input.emails)],
      active: input.active,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    await this.store.saveScimUser(user);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "scim.user.created",
      payload: {
        externalId: input.externalId,
        userName: input.userName,
        createdBy: actor
      }
    });
    return user;
  }

  async upsertGroup(tenantId: string, input: UpsertScimGroupInput, actor: string): Promise<ScimGroupRecord> {
    const existing = (await this.store.listScimGroupsByTenant(tenantId)).find(
      (entry) => entry.externalId === input.externalId
    );
    const sortedMembers = [...new Set(input.memberExternalUserIds)].sort((a, b) => a.localeCompare(b));
    if (existing) {
      existing.displayName = input.displayName;
      existing.memberExternalUserIds = sortedMembers;
      existing.updatedAt = nowIso();
      await this.store.saveScimGroup(existing);
      await this.securityEventService.publish({
        tenantId,
        source: "admin",
        eventType: "scim.group.updated",
        payload: {
          externalId: input.externalId,
          displayName: input.displayName,
          updatedBy: actor
        }
      });
      return existing;
    }

    const group: ScimGroupRecord = {
      id: createId("scim_grp"),
      tenantId,
      externalId: input.externalId,
      displayName: input.displayName,
      memberExternalUserIds: sortedMembers,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    await this.store.saveScimGroup(group);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "scim.group.created",
      payload: {
        externalId: input.externalId,
        displayName: input.displayName,
        createdBy: actor
      }
    });
    return group;
  }

  async deprovisionUser(tenantId: string, externalId: string, actor: string): Promise<ScimUserRecord> {
    const user = await this.store.getScimUserByExternalId(tenantId, externalId);
    if (!user) {
      throw new Error(`SCIM user not found: ${externalId}`);
    }

    user.active = false;
    user.updatedAt = nowIso();
    await this.store.saveScimUser(user);
    await this.tenantAdminService.removeMember(tenantId, user.userName, actor);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "scim.user.deprovisioned",
      payload: {
        externalId,
        userName: user.userName,
        actor
      }
    });
    return user;
  }

  async upsertRoleMapping(
    tenantId: string,
    groupDisplayName: string,
    role: Exclude<TenantRole, "owner">,
    actor: string
  ): Promise<ScimRoleMappingRecord> {
    const existing = (await this.store.listScimRoleMappingsByTenant(tenantId)).find(
      (entry) => entry.groupDisplayName === groupDisplayName
    );
    if (existing) {
      existing.role = role;
      existing.updatedAt = nowIso();
      await this.store.saveScimRoleMapping(existing);
      await this.securityEventService.publish({
        tenantId,
        source: "admin",
        eventType: "scim.role_mapping.updated",
        payload: {
          groupDisplayName,
          role,
          updatedBy: actor
        }
      });
      return existing;
    }

    const mapping: ScimRoleMappingRecord = {
      id: createId("scim_map"),
      tenantId,
      groupDisplayName,
      role,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    await this.store.saveScimRoleMapping(mapping);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "scim.role_mapping.created",
      payload: {
        groupDisplayName,
        role,
        createdBy: actor
      }
    });
    return mapping;
  }

  async listUsers(tenantId: string, page = 1, pageSize = 100): Promise<PagedResult<ScimUserRecord>> {
    return this.store.listScimUsersByTenantPaged(tenantId, page, pageSize);
  }

  async listGroups(tenantId: string, page = 1, pageSize = 100): Promise<PagedResult<ScimGroupRecord>> {
    return this.store.listScimGroupsByTenantPaged(tenantId, page, pageSize);
  }

  async listRoleMappings(
    tenantId: string,
    page = 1,
    pageSize = 100
  ): Promise<PagedResult<ScimRoleMappingRecord>> {
    return this.store.listScimRoleMappingsByTenantPaged(tenantId, page, pageSize);
  }

  async syncTenantMembers(tenantId: string, actor: string): Promise<SyncResult> {
    const groups = await this.store.listScimGroupsByTenant(tenantId);
    const mappings = await this.store.listScimRoleMappingsByTenant(tenantId);
    const users = await this.store.listScimUsersByTenant(tenantId);
    const usersByExternalId = new Map(users.map((user) => [user.externalId, user]));
    const roleByGroupName = new Map(mappings.map((mapping) => [mapping.groupDisplayName, mapping.role]));

    const resolvedBySubject = new Map<string, Exclude<TenantRole, "owner">>();
    let skippedInactiveCount = 0;
    let unmappedGroupCount = 0;

    for (const group of groups) {
      const mappedRole = roleByGroupName.get(group.displayName);
      if (!mappedRole) {
        unmappedGroupCount += 1;
        continue;
      }

      for (const externalUserId of group.memberExternalUserIds) {
        const user = usersByExternalId.get(externalUserId);
        if (!user) {
          continue;
        }
        if (!user.active) {
          skippedInactiveCount += 1;
          continue;
        }
        const subject = user.userName;
        const existing = resolvedBySubject.get(subject);
        if (!existing || rolePriority[mappedRole] > rolePriority[existing]) {
          resolvedBySubject.set(subject, mappedRole);
        }
      }
    }

    for (const [subject, role] of resolvedBySubject.entries()) {
      await this.tenantAdminService.upsertMember(tenantId, subject, role, actor);
    }

    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "scim.sync.completed",
      payload: {
        assignedCount: resolvedBySubject.size,
        skippedInactiveCount,
        unmappedGroupCount,
        actor
      }
    });

    return {
      assignedCount: resolvedBySubject.size,
      skippedInactiveCount,
      unmappedGroupCount
    };
  }
}
