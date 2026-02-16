import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import type { TokenClaims } from "../types/auth.js";

export interface TrustedServiceIdentity {
  subject: string;
  fingerprintSha256: string;
  serviceAccountId?: string | undefined;
  tenantIds?: string[] | undefined;
}

export interface ServiceIdentityServiceOptions {
  enabled?: boolean | undefined;
  trustedIdentities?: TrustedServiceIdentity[] | undefined;
  rawTrustedIdentities?: string | undefined;
  trustedIdentitiesFilePath?: string | undefined;
  enforceForRoles?: TokenClaims["role"][] | undefined;
  attestationSecret?: string | undefined;
  maxClockSkewSeconds?: number | undefined;
}

interface ParsedHeaders {
  subject: string | null;
  fingerprintSha256: string | null;
  issuedAt: string | null;
  signature: string | null;
}

interface VerificationStats {
  successCount: number;
  failureCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastFailureReason: string | null;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  return value.trim().toLowerCase() === "true";
}

function parseIntWithMin(value: string | undefined, fallback: number, min: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < min) {
    return fallback;
  }
  return parsed;
}

function normalizeFingerprint(value: string): string {
  return value.toLowerCase().replace(/[^a-f0-9]/g, "");
}

function isValidHex(value: string): boolean {
  return /^[a-f0-9]+$/i.test(value);
}

function parseTrustedIdentities(raw: string | undefined): TrustedServiceIdentity[] {
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }
    const trusted: TrustedServiceIdentity[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== "object") {
        continue;
      }
      const candidate = entry as Partial<TrustedServiceIdentity>;
      if (typeof candidate.subject !== "string" || typeof candidate.fingerprintSha256 !== "string") {
        continue;
      }
      const fingerprintSha256 = normalizeFingerprint(candidate.fingerprintSha256);
      if (fingerprintSha256.length === 0 || !isValidHex(fingerprintSha256)) {
        continue;
      }

      const normalized: TrustedServiceIdentity = {
        subject: candidate.subject,
        fingerprintSha256
      };
      if (typeof candidate.serviceAccountId === "string") {
        normalized.serviceAccountId = candidate.serviceAccountId;
      }
      if (Array.isArray(candidate.tenantIds)) {
        normalized.tenantIds = candidate.tenantIds.filter((value): value is string => typeof value === "string");
      }
      trusted.push(normalized);
    }
    return trusted;
  } catch {
    return [];
  }
}

function loadTrustedIdentitiesFile(path: string | undefined): TrustedServiceIdentity[] {
  if (!path || path.trim().length === 0) {
    return [];
  }
  try {
    const raw = readFileSync(path, "utf8");
    return parseTrustedIdentities(raw);
  } catch {
    return [];
  }
}

function headerValue(headers: Record<string, unknown>, key: string): string | null {
  const value = headers[key];
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }
  if (Array.isArray(value) && typeof value[0] === "string" && value[0].trim().length > 0) {
    return value[0].trim();
  }
  return null;
}

export class ServiceIdentityService {
  private readonly enabled: boolean;
  private readonly trustedIdentities: TrustedServiceIdentity[];
  private readonly enforceForRoles: TokenClaims["role"][];
  private readonly attestationSecret: string | null;
  private readonly maxClockSkewSeconds: number;
  private readonly stats: VerificationStats = {
    successCount: 0,
    failureCount: 0,
    lastSuccessAt: null,
    lastFailureAt: null,
    lastFailureReason: null
  };

  constructor(options?: ServiceIdentityServiceOptions) {
    this.enabled = options?.enabled ?? parseBoolean(process.env.OARS_MTLS_ENABLED, false);
    if (options?.trustedIdentities) {
      this.trustedIdentities = options.trustedIdentities.map((entry) => ({
        ...entry,
        fingerprintSha256: normalizeFingerprint(entry.fingerprintSha256)
      }));
    } else {
      const filePath = options?.trustedIdentitiesFilePath ?? process.env.OARS_MTLS_TRUSTED_IDENTITIES_FILE;
      const fromFile = loadTrustedIdentitiesFile(filePath);
      this.trustedIdentities =
        fromFile.length > 0
          ? fromFile
          : parseTrustedIdentities(options?.rawTrustedIdentities ?? process.env.OARS_MTLS_TRUSTED_IDENTITIES);
    }
    this.enforceForRoles = options?.enforceForRoles ?? ["service"];
    const configuredSecret = options?.attestationSecret ?? process.env.OARS_MTLS_ATTESTATION_SECRET;
    this.attestationSecret =
      configuredSecret && configuredSecret.trim().length > 0 ? configuredSecret.trim() : null;
    this.maxClockSkewSeconds =
      options?.maxClockSkewSeconds ??
      parseIntWithMin(process.env.OARS_MTLS_MAX_CLOCK_SKEW_SECONDS, 300, 30);
  }

  enforceRequestIdentity(claims: TokenClaims, headers: Record<string, unknown>): void {
    if (!this.isEnforcedForClaims(claims)) {
      return;
    }

    const parsedHeaders = this.parseHeaders(headers);
    if (!parsedHeaders.subject || !parsedHeaders.fingerprintSha256) {
      this.recordFailure("Missing mTLS identity headers.");
      throw new Error("mTLS service identity is required for this token.");
    }

    const normalizedFingerprint = normalizeFingerprint(parsedHeaders.fingerprintSha256);
    if (!normalizedFingerprint || !isValidHex(normalizedFingerprint)) {
      this.recordFailure("Invalid mTLS fingerprint header format.");
      throw new Error("mTLS fingerprint format is invalid.");
    }

    if (this.attestationSecret) {
      this.validateAttestation(parsedHeaders);
    }

    const trusted = this.trustedIdentities.find(
      (identity) =>
        identity.subject === parsedHeaders.subject &&
        identity.fingerprintSha256 === normalizedFingerprint
    );
    if (!trusted) {
      this.recordFailure("Presented mTLS identity is not trusted.");
      throw new Error("mTLS service identity is not trusted.");
    }

    if (trusted.serviceAccountId && claims.serviceAccountId !== trusted.serviceAccountId) {
      this.recordFailure("mTLS identity does not match service account.");
      throw new Error("mTLS service identity does not match authenticated service account.");
    }

    if (trusted.tenantIds && trusted.tenantIds.length > 0) {
      const allAllowed = claims.tenantIds.every((tenantId) => trusted.tenantIds?.includes(tenantId));
      if (!allAllowed) {
        this.recordFailure("mTLS identity tenant scope mismatch.");
        throw new Error("mTLS service identity is not authorized for requested tenant scope.");
      }
    }

    this.recordSuccess();
  }

  status(): {
    enabled: boolean;
    enforceForRoles: TokenClaims["role"][];
    trustedIdentityCount: number;
    attestationRequired: boolean;
    maxClockSkewSeconds: number;
    verification: VerificationStats;
  } {
    return {
      enabled: this.enabled,
      enforceForRoles: [...this.enforceForRoles],
      trustedIdentityCount: this.trustedIdentities.length,
      attestationRequired: this.attestationSecret !== null,
      maxClockSkewSeconds: this.maxClockSkewSeconds,
      verification: structuredClone(this.stats)
    };
  }

  private parseHeaders(headers: Record<string, unknown>): ParsedHeaders {
    return {
      subject: headerValue(headers, "x-oars-mtls-subject"),
      fingerprintSha256: headerValue(headers, "x-oars-mtls-fingerprint"),
      issuedAt: headerValue(headers, "x-oars-mtls-issued-at"),
      signature: headerValue(headers, "x-oars-mtls-signature")
    };
  }

  private validateAttestation(headers: ParsedHeaders): void {
    if (!this.attestationSecret) {
      return;
    }

    if (!headers.subject || !headers.fingerprintSha256 || !headers.issuedAt || !headers.signature) {
      this.recordFailure("Missing mTLS attestation headers.");
      throw new Error("mTLS attestation headers are required.");
    }

    const issuedAtMs = Date.parse(headers.issuedAt);
    if (Number.isNaN(issuedAtMs)) {
      this.recordFailure("Invalid mTLS attestation timestamp.");
      throw new Error("mTLS attestation timestamp is invalid.");
    }
    const skewMs = Math.abs(Date.now() - issuedAtMs);
    if (skewMs > this.maxClockSkewSeconds * 1000) {
      this.recordFailure("mTLS attestation timestamp skew exceeded.");
      throw new Error("mTLS attestation timestamp is outside allowed clock skew.");
    }

    const payload = `${headers.subject}\n${normalizeFingerprint(headers.fingerprintSha256)}\n${headers.issuedAt}`;
    const expected = createHmac("sha256", this.attestationSecret).update(payload, "utf8").digest("hex");
    const presented = headers.signature.trim().toLowerCase();
    if (presented.length !== expected.length || !timingSafeEqual(Buffer.from(presented), Buffer.from(expected))) {
      this.recordFailure("mTLS attestation signature mismatch.");
      throw new Error("mTLS attestation signature is invalid.");
    }
  }

  private isEnforcedForClaims(claims: TokenClaims): boolean {
    if (!this.enabled) {
      return false;
    }
    return this.enforceForRoles.includes(claims.role);
  }

  private recordSuccess(): void {
    this.stats.successCount += 1;
    this.stats.lastSuccessAt = new Date().toISOString();
    this.stats.lastFailureReason = null;
  }

  private recordFailure(reason: string): void {
    this.stats.failureCount += 1;
    this.stats.lastFailureAt = new Date().toISOString();
    this.stats.lastFailureReason = reason;
  }
}
