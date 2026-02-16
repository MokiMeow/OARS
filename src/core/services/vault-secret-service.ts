import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";

interface VaultSecretRecord {
  id: string;
  tenantId: string;
  connectorId: string;
  key: string;
  encryptedValue: string;
  updatedAt: string;
  updatedBy: string;
}

interface VaultSecretState {
  secrets: VaultSecretRecord[];
}

const defaultState: VaultSecretState = {
  secrets: []
};

const DEFAULT_VAULT_KEY = "oars_dev_vault_key_change_me";

function deriveKey(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

export class VaultSecretService {
  private readonly state: VaultSecretState;
  private readonly encryptionKey: Buffer;

  constructor(
    private readonly filePath: string,
    encryptionSecret = process.env.OARS_VAULT_KEY ?? DEFAULT_VAULT_KEY
  ) {
    const allowInsecureDefaults =
      process.env.OARS_ALLOW_INSECURE_DEFAULTS === "true" || process.env.OARS_ALLOW_INSECURE_DEFAULTS === "1";
    if (process.env.NODE_ENV === "production" && !allowInsecureDefaults) {
      if (encryptionSecret === DEFAULT_VAULT_KEY) {
        throw new Error("OARS_VAULT_KEY must be set in production (development default is not allowed).");
      }
    }
    this.encryptionKey = deriveKey(encryptionSecret);
    this.state = this.load();
  }

  upsertSecret(tenantId: string, connectorId: string, key: string, value: string, actor: string): VaultSecretRecord {
    const encryptedValue = this.encrypt(value);
    const existing = this.state.secrets.find(
      (entry) => entry.tenantId === tenantId && entry.connectorId === connectorId && entry.key === key
    );
    if (existing) {
      existing.encryptedValue = encryptedValue;
      existing.updatedAt = nowIso();
      existing.updatedBy = actor;
      this.persist();
      return existing;
    }

    const secret: VaultSecretRecord = {
      id: createId("vlt"),
      tenantId,
      connectorId,
      key,
      encryptedValue,
      updatedAt: nowIso(),
      updatedBy: actor
    };
    this.state.secrets.push(secret);
    this.persist();
    return secret;
  }

  getSecret(tenantId: string, connectorId: string, key: string): string | null {
    const secret = this.state.secrets.find(
      (entry) => entry.tenantId === tenantId && entry.connectorId === connectorId && entry.key === key
    );
    if (!secret) {
      return null;
    }
    return this.decrypt(secret.encryptedValue);
  }

  hasSecret(tenantId: string, connectorId: string, key: string): boolean {
    return this.getSecret(tenantId, connectorId, key) !== null;
  }

  listMetadata(
    tenantId: string,
    connectorId?: string
  ): Array<{ id: string; tenantId: string; connectorId: string; key: string; updatedAt: string; updatedBy: string }> {
    return this.state.secrets
      .filter((entry) => entry.tenantId === tenantId)
      .filter((entry) => (connectorId ? entry.connectorId === connectorId : true))
      .sort((a, b) => a.connectorId.localeCompare(b.connectorId) || a.key.localeCompare(b.key))
      .map((entry) => ({
        id: entry.id,
        tenantId: entry.tenantId,
        connectorId: entry.connectorId,
        key: entry.key,
        updatedAt: entry.updatedAt,
        updatedBy: entry.updatedBy
      }));
  }

  private load(): VaultSecretState {
    if (!existsSync(this.filePath)) {
      return structuredClone(defaultState);
    }
    const raw = readFileSync(this.filePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<VaultSecretState>;
    return {
      secrets: parsed.secrets ?? []
    };
  }

  private persist(): void {
    const folder = dirname(this.filePath);
    if (!existsSync(folder)) {
      mkdirSync(folder, { recursive: true });
    }
    writeFileSync(this.filePath, JSON.stringify(this.state, null, 2), "utf8");
  }

  private encrypt(value: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("base64")}.${encrypted.toString("base64")}.${tag.toString("base64")}`;
  }

  private decrypt(encryptedValue: string): string | null {
    const [ivBase64, payloadBase64, tagBase64] = encryptedValue.split(".");
    if (!ivBase64 || !payloadBase64 || !tagBase64) {
      return null;
    }
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.encryptionKey,
        Buffer.from(ivBase64, "base64")
      );
      decipher.setAuthTag(Buffer.from(tagBase64, "base64"));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payloadBase64, "base64")),
        decipher.final()
      ]);
      return decrypted.toString("utf8");
    } catch {
      return null;
    }
  }
}
