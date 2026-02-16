import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";

interface TenantKeyMaterial {
  tenantId: string;
  keyId: string;
  privateKeyPem: string;
  publicKeyPem: string;
  status: "active" | "retiring" | "retired";
  createdAt: string;
  rotatedAt: string | null;
}

interface KeyState {
  keys: TenantKeyMaterial[];
}

const defaultState: KeyState = {
  keys: []
};

export class SigningKeyService {
  private state: KeyState;

  constructor(private readonly filePath: string) {
    this.state = this.load();
  }

  private load(): KeyState {
    if (!existsSync(this.filePath)) {
      return structuredClone(defaultState);
    }

    const raw = readFileSync(this.filePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<KeyState>;
    const loaded = parsed.keys ?? [];
    const byTenant = new Map<string, TenantKeyMaterial[]>();
    for (const raw of loaded) {
      const normalized: TenantKeyMaterial = {
        tenantId: raw.tenantId ?? "",
        keyId: raw.keyId ?? createId("key"),
        privateKeyPem: raw.privateKeyPem ?? "",
        publicKeyPem: raw.publicKeyPem ?? "",
        status: raw.status ?? "active",
        createdAt: raw.createdAt ?? nowIso(),
        rotatedAt: raw.rotatedAt ?? null
      };
      if (!byTenant.has(normalized.tenantId)) {
        byTenant.set(normalized.tenantId, []);
      }
      byTenant.get(normalized.tenantId)?.push(normalized);
    }

    const normalizedKeys: TenantKeyMaterial[] = [];
    for (const keys of byTenant.values()) {
      keys.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      const active = keys.filter((key) => key.status === "active");
      if (active.length > 1) {
        const newestActive = active.at(-1)?.keyId;
        for (const key of keys) {
          if (key.status === "active" && key.keyId !== newestActive) {
            key.status = "retiring";
            key.rotatedAt = key.rotatedAt ?? nowIso();
          }
        }
      }
      normalizedKeys.push(...keys);
    }

    return {
      keys: normalizedKeys
    };
  }

  private persist(): void {
    const folder = dirname(this.filePath);
    if (!existsSync(folder)) {
      mkdirSync(folder, { recursive: true });
    }
    writeFileSync(this.filePath, JSON.stringify(this.state, null, 2), "utf8");
  }

  getOrCreateTenantKey(tenantId: string): TenantKeyMaterial {
    const existing = this.state.keys.find((key) => key.tenantId === tenantId && key.status === "active");
    if (existing) {
      return existing;
    }

    const generated = generateKeyPairSync("ed25519");
    const key: TenantKeyMaterial = {
      tenantId,
      keyId: createId("key"),
      privateKeyPem: generated.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      publicKeyPem: generated.publicKey.export({ format: "pem", type: "spki" }).toString(),
      status: "active",
      createdAt: nowIso(),
      rotatedAt: null
    };

    this.state.keys.push(key);
    this.persist();
    return key;
  }

  getPublicKey(keyId: string): string | null {
    const key = this.state.keys.find((entry) => entry.keyId === keyId);
    return key?.publicKeyPem ?? null;
  }

  sign(tenantId: string, data: string): { signature: string; keyId: string } {
    const key = this.getOrCreateTenantKey(tenantId);
    const privateKey = createPrivateKey(key.privateKeyPem);
    // Ed25519 signs the message directly and ignores hash algorithm selection.
    const signature = sign(null, Buffer.from(data), privateKey);
    return {
      signature: signature.toString("base64"),
      keyId: key.keyId
    };
  }

  verify(data: string, signatureBase64: string, keyId: string): boolean {
    const publicKeyPem = this.getPublicKey(keyId);
    if (!publicKeyPem) {
      return false;
    }

    const publicKey = createPublicKey(publicKeyPem);
    const signature = Buffer.from(signatureBase64, "base64");
    return verify(null, Buffer.from(data), publicKey, signature);
  }

  rotateTenantKey(tenantId: string): {
    newKeyId: string;
    previousActiveKeyId: string | null;
    rotatedAt: string;
  } {
    const rotatedAt = nowIso();
    const existingActive = this.state.keys.find((key) => key.tenantId === tenantId && key.status === "active");
    if (existingActive) {
      existingActive.status = "retiring";
      existingActive.rotatedAt = rotatedAt;
    }

    const generated = generateKeyPairSync("ed25519");
    const next: TenantKeyMaterial = {
      tenantId,
      keyId: createId("key"),
      privateKeyPem: generated.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      publicKeyPem: generated.publicKey.export({ format: "pem", type: "spki" }).toString(),
      status: "active",
      createdAt: rotatedAt,
      rotatedAt: null
    };
    this.state.keys.push(next);
    this.persist();
    return {
      newKeyId: next.keyId,
      previousActiveKeyId: existingActive?.keyId ?? null,
      rotatedAt
    };
  }

  listTenantKeys(tenantId: string): Array<{
    keyId: string;
    tenantId: string;
    status: "active" | "retiring" | "retired";
    createdAt: string;
    rotatedAt: string | null;
  }> {
    return this.state.keys
      .filter((key) => key.tenantId === tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((key) => ({
        keyId: key.keyId,
        tenantId: key.tenantId,
        status: key.status,
        createdAt: key.createdAt,
        rotatedAt: key.rotatedAt
      }));
  }

  listTenantPublicKeys(tenantId: string): Array<{
    keyId: string;
    tenantId: string;
    status: "active" | "retiring" | "retired";
    createdAt: string;
    rotatedAt: string | null;
    publicKeyPem: string;
  }> {
    return this.state.keys
      .filter((key) => key.tenantId === tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((key) => ({
        keyId: key.keyId,
        tenantId: key.tenantId,
        status: key.status,
        createdAt: key.createdAt,
        rotatedAt: key.rotatedAt,
        publicKeyPem: key.publicKeyPem
      }));
  }
}
