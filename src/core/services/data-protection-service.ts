import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const ENCRYPTED_MARKER = "oars_enc_v1";

interface EncryptedPayload {
  __oarsEncrypted: typeof ENCRYPTED_MARKER;
  alg: "aes-256-gcm";
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface DataProtectionServiceOptions {
  encryptionKey?: string | undefined;
  enabled?: boolean | undefined;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  return value.trim().toLowerCase() === "true";
}

function deriveEncryptionKey(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

function isEncryptedPayload(value: unknown): value is EncryptedPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Partial<EncryptedPayload>;
  return (
    candidate.__oarsEncrypted === ENCRYPTED_MARKER &&
    candidate.alg === "aes-256-gcm" &&
    typeof candidate.iv === "string" &&
    typeof candidate.tag === "string" &&
    typeof candidate.ciphertext === "string"
  );
}

export class DataProtectionService {
  private readonly enabled: boolean;
  private readonly key: Buffer | null;

  constructor(options?: DataProtectionServiceOptions) {
    const configuredKey = options?.encryptionKey ?? process.env.OARS_DATA_ENCRYPTION_KEY;
    const explicitEnabled = options?.enabled ?? parseBoolean(process.env.OARS_DATA_ENCRYPTION_ENABLED, true);
    this.enabled = explicitEnabled && Boolean(configuredKey && configuredKey.trim().length > 0);
    this.key = this.enabled && configuredKey ? deriveEncryptionKey(configuredKey.trim()) : null;
  }

  status(): { enabled: boolean } {
    return {
      enabled: this.enabled
    };
  }

  protect<T>(value: T): T | EncryptedPayload {
    if (!this.enabled || this.key === null) {
      return value;
    }

    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const plaintext = JSON.stringify(value);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      __oarsEncrypted: ENCRYPTED_MARKER,
      alg: "aes-256-gcm",
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      ciphertext: ciphertext.toString("base64")
    };
  }

  restore<T>(value: unknown): T {
    if (!this.enabled || this.key === null) {
      if (isEncryptedPayload(value)) {
        throw new Error("Encrypted payload encountered but data protection key is not configured.");
      }
      return value as T;
    }
    if (!isEncryptedPayload(value)) {
      return value as T;
    }
    const iv = Buffer.from(value.iv, "base64");
    const tag = Buffer.from(value.tag, "base64");
    const ciphertext = Buffer.from(value.ciphertext, "base64");
    const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return JSON.parse(plaintext) as T;
  }
}

export type { EncryptedPayload };
