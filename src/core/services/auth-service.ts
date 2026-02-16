import { createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { createId } from "../../lib/id.js";
import type { TokenClaims } from "../types/auth.js";
import { JwksService } from "./jwks-service.js";

interface TokenRecord extends TokenClaims {
  token: string;
}

interface JwtPayload {
  jti?: string | undefined;
  iss?: string | undefined;
  aud?: string | string[] | undefined;
  sub?: string | undefined;
  iat?: number | undefined;
  exp?: number | undefined;
  tid?: string | string[] | undefined;
  scp?: string | string[] | undefined;
  role?: TokenClaims["role"] | undefined;
  dch?: string[] | undefined;
  sai?: string | undefined;
}

interface JwtHeader {
  alg?: string | undefined;
  typ?: string | undefined;
  kid?: string | undefined;
}

interface IssueTokenInput {
  subject: string;
  tenantIds: string[];
  scopes: string[];
  role: TokenClaims["role"];
  expiresInSeconds?: number | undefined;
  delegationChain?: string[] | undefined;
  serviceAccountId?: string | undefined;
}

export interface AuthServiceOptions {
  rawConfig?: string | undefined;
  jwtSecret?: string | undefined;
  jwtIssuer?: string | undefined;
  jwtAudience?: string | undefined;
}

const DEFAULT_JWT_SECRET = "dev_oars_jwt_secret_change_me";

const defaultTokens: TokenRecord[] = [
  {
    token: "dev_admin_token",
    tokenId: "tok_dev_admin",
    subject: "admin_user",
    tenantIds: ["tenant_alpha", "tenant_bravo", "tenant_enterprise"],
    scopes: [
      "actions:write",
      "actions:read",
      "approvals:write",
      "receipts:read",
      "receipts:verify",
      "policies:write",
      "policies:read",
      "evidence:export",
      "evidence:read",
      "compliance:read",
      "compliance:write",
      "alerts:read",
      "connectors:read",
      "events:read",
      "ledger:read",
      "ledger:write",
      "tenant_admin:read",
      "tenant_admin:write",
      "service_accounts:read",
      "service_accounts:write",
      "scim:read",
      "scim:write",
      "scim:sync",
      "token:exchange",
      "auth_providers:read",
      "auth_providers:refresh",
      "siem:read",
      "siem:write",
      "impersonate"
    ],
    role: "admin"
  },
  {
    token: "dev_operator_token",
    tokenId: "tok_dev_operator",
    subject: "operator_user",
    tenantIds: ["tenant_alpha", "tenant_bravo"],
    scopes: [
      "actions:write",
      "actions:read",
      "approvals:write",
      "receipts:read",
      "receipts:verify",
      "policies:read",
      "evidence:export",
      "alerts:read",
      "connectors:read"
    ],
    role: "operator"
  },
  {
    token: "dev_auditor_token",
    tokenId: "tok_dev_auditor",
    subject: "auditor_user",
    tenantIds: ["tenant_alpha", "tenant_bravo"],
    scopes: [
      "actions:read",
      "receipts:read",
      "receipts:verify",
      "policies:read",
      "evidence:export",
      "evidence:read",
      "compliance:read",
      "alerts:read",
      "connectors:read",
      "events:read",
      "ledger:read",
      "tenant_admin:read",
      "service_accounts:read",
      "scim:read",
      "auth_providers:read",
      "siem:read"
    ],
    role: "auditor"
  }
];

function devTokensDisabled(): boolean {
  const allowDevTokensInProduction =
    process.env.OARS_ALLOW_DEV_TOKENS_IN_PRODUCTION === "true" ||
    process.env.OARS_ALLOW_DEV_TOKENS_IN_PRODUCTION === "1";
  if (process.env.NODE_ENV === "production" && !allowDevTokensInProduction) {
    return true;
  }
  return (
    process.env.OARS_DISABLE_DEV_TOKENS === "true" ||
    process.env.OARS_DISABLE_DEV_TOKENS === "1"
  );
}

function parseConfiguredTokens(raw: string | undefined): TokenRecord[] {
  if (devTokensDisabled()) {
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as TokenRecord[];
      if (!Array.isArray(parsed) || parsed.length === 0) {
        return [];
      }
      return parsed;
    } catch {
      return [];
    }
  }

  if (!raw) {
    if (process.env.NODE_ENV === "production") {
      console.warn(
        "[SECURITY WARNING] Dev tokens are active in production. Set OARS_DISABLE_DEV_TOKENS=true or provide OARS_API_TOKENS."
      );
    }
    return defaultTokens;
  }

  try {
    const parsed = JSON.parse(raw) as TokenRecord[];
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return defaultTokens;
    }
    return parsed;
  } catch {
    return defaultTokens;
  }
}

function encodeBase64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function decodeBase64Url(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function normalizeArray(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function parseScopes(value: unknown): string[] | null {
  if (Array.isArray(value)) {
    const allStrings = value.every((entry) => typeof entry === "string");
    if (!allStrings) {
      return null;
    }
    return normalizeArray(value as string[]);
  }
  if (typeof value === "string") {
    return normalizeArray(
      value
        .split(" ")
        .map((entry) => entry.trim())
        .filter(Boolean)
    );
  }
  return null;
}

function parseTenantIds(value: unknown): string[] | null {
  if (Array.isArray(value)) {
    const allStrings = value.every((entry) => typeof entry === "string");
    if (!allStrings) {
      return null;
    }
    return normalizeArray(value as string[]);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    return [value.trim()];
  }
  return null;
}

function parseAudience(value: unknown): string[] | null {
  if (typeof value === "string" && value.trim().length > 0) {
    return [value];
  }
  if (Array.isArray(value)) {
    const allStrings = value.every((entry) => typeof entry === "string");
    if (!allStrings) {
      return null;
    }
    return [...value];
  }
  return null;
}

function isTokenRole(value: unknown): value is TokenClaims["role"] {
  return (
    value === "admin" ||
    value === "operator" ||
    value === "auditor" ||
    value === "agent" ||
    value === "service"
  );
}

export class AuthService {
  private readonly tokens: TokenRecord[];
  private readonly jwtSecret: string;
  private readonly jwtIssuer: string;
  private readonly jwtAudience: string;
  private readonly jwksService: JwksService;

  constructor(options?: AuthServiceOptions, jwksService?: JwksService) {
    this.tokens = parseConfiguredTokens(options?.rawConfig ?? process.env.OARS_API_TOKENS);
    this.jwtSecret = options?.jwtSecret ?? process.env.OARS_JWT_SECRET ?? DEFAULT_JWT_SECRET;
    this.jwtIssuer = options?.jwtIssuer ?? process.env.OARS_JWT_ISSUER ?? "oars.local";
    this.jwtAudience = options?.jwtAudience ?? process.env.OARS_JWT_AUDIENCE ?? "oars-api";
    this.jwksService = jwksService ?? new JwksService();

    const allowInsecureDefaults =
      process.env.OARS_ALLOW_INSECURE_DEFAULTS === "true" || process.env.OARS_ALLOW_INSECURE_DEFAULTS === "1";
    if (process.env.NODE_ENV === "production" && !allowInsecureDefaults) {
      if (this.jwtSecret === DEFAULT_JWT_SECRET) {
        throw new Error("OARS_JWT_SECRET must be set in production (development default is not allowed).");
      }
    }
  }

  authenticate(authorizationHeader: string | undefined): TokenClaims {
    if (!authorizationHeader) {
      throw new Error("Missing Authorization header.");
    }

    const [scheme, value] = authorizationHeader.split(" ");
    if (!scheme || !value || scheme.toLowerCase() !== "bearer") {
      throw new Error("Authorization must use Bearer token.");
    }

    const staticMatch = this.tokens.find((token) => token.token === value);
    if (staticMatch) {
      return {
        tokenId: staticMatch.tokenId,
        subject: staticMatch.subject,
        tenantIds: [...staticMatch.tenantIds],
        scopes: [...staticMatch.scopes],
        role: staticMatch.role,
        delegationChain: staticMatch.delegationChain,
        serviceAccountId: staticMatch.serviceAccountId,
        tokenType: "static"
      };
    }

    const jwtClaims = this.verifyJwt(value);
    if (!jwtClaims) {
      throw new Error("Invalid API token.");
    }
    return jwtClaims;
  }

  issueToken(input: IssueTokenInput): { accessToken: string; expiresAt: string } {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresInSeconds = Math.max(60, Math.min(input.expiresInSeconds ?? 3600, 86400));
    const exp = nowSeconds + expiresInSeconds;
    const payload: JwtPayload = {
      jti: createId("jwt"),
      iss: this.jwtIssuer,
      aud: this.jwtAudience,
      sub: input.subject,
      iat: nowSeconds,
      exp,
      tid: normalizeArray(input.tenantIds),
      scp: normalizeArray(input.scopes),
      role: input.role
    };
    if (input.delegationChain && input.delegationChain.length > 0) {
      payload.dch = [...input.delegationChain];
    }
    if (input.serviceAccountId) {
      payload.sai = input.serviceAccountId;
    }

    const headerSegment = encodeBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payloadSegment = encodeBase64Url(JSON.stringify(payload));
    const signature = this.sign(`${headerSegment}.${payloadSegment}`);
    const accessToken = `${headerSegment}.${payloadSegment}.${signature}`;

    return {
      accessToken,
      expiresAt: new Date(exp * 1000).toISOString()
    };
  }

  requireScope(claims: TokenClaims, scope: string): void {
    if (!claims.scopes.includes(scope)) {
      throw new Error(`Missing required scope: ${scope}`);
    }
  }

  requireTenantAccess(claims: TokenClaims, tenantId: string): void {
    if (!claims.tenantIds.includes(tenantId)) {
      throw new Error(`Token has no access to tenant: ${tenantId}`);
    }
  }

  canImpersonate(claims: TokenClaims): boolean {
    return claims.scopes.includes("impersonate");
  }

  requireRole(claims: TokenClaims, role: TokenClaims["role"]): void {
    if (claims.role !== role) {
      throw new Error(`Role ${claims.role} cannot access ${role}-only operation.`);
    }
  }

  assertRequestedScopesWithin(availableScopes: string[], requestedScopes: string[]): void {
    const set = new Set(availableScopes);
    for (const scope of requestedScopes) {
      if (!set.has(scope)) {
        throw new Error(`Requested scope not allowed: ${scope}`);
      }
    }
  }

  listTrustedProviders(): ReturnType<JwksService["listProviders"]> {
    return this.jwksService.listProviders();
  }

  async refreshTrustedProviders(issuer?: string): Promise<{ refreshedIssuers: string[]; failedIssuers: string[] }> {
    if (issuer) {
      const refreshed = await this.jwksService.refreshIssuer(issuer);
      return {
        refreshedIssuers: refreshed ? [issuer] : [],
        failedIssuers: refreshed ? [] : [issuer]
      };
    }
    return this.jwksService.refreshAll();
  }

  private sign(input: string): string {
    return createHmac("sha256", this.jwtSecret).update(input).digest("base64url");
  }

  private verifyJwt(token: string): TokenClaims | null {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const [headerSegment, payloadSegment, signatureSegment] = parts;
    if (!headerSegment || !payloadSegment || !signatureSegment) {
      return null;
    }

    let header: JwtHeader;
    let payload: JwtPayload;
    try {
      header = JSON.parse(decodeBase64Url(headerSegment)) as JwtHeader;
      payload = JSON.parse(decodeBase64Url(payloadSegment)) as JwtPayload;
    } catch {
      return null;
    }

    if (header.typ !== "JWT") {
      return null;
    }

    const claims = this.verifySignatureAndClaims(header, payload, `${headerSegment}.${payloadSegment}`, signatureSegment);
    if (!claims) {
      return null;
    }
    return claims;
  }

  private verifySignatureAndClaims(
    header: JwtHeader,
    payload: JwtPayload,
    signedPayload: string,
    signatureSegment: string
  ): TokenClaims | null {
    if (!payload.sub || !payload.iss || !isTokenRole(payload.role)) {
      return null;
    }
    if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
      return null;
    }

    const tenantIds = parseTenantIds(payload.tid);
    const scopes = parseScopes(payload.scp);
    const audiences = parseAudience(payload.aud);
    if (!tenantIds || !scopes || !audiences) {
      return null;
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSeconds || payload.iat > nowSeconds + 60) {
      return null;
    }

    if (header.alg === "HS256") {
      const expectedSignature = this.sign(signedPayload);
      const expectedBuffer = Buffer.from(expectedSignature, "utf8");
      const providedBuffer = Buffer.from(signatureSegment, "utf8");
      if (expectedBuffer.length !== providedBuffer.length) {
        return null;
      }
      if (!timingSafeEqual(expectedBuffer, providedBuffer)) {
        return null;
      }
      if (payload.iss !== this.jwtIssuer || !audiences.includes(this.jwtAudience)) {
        return null;
      }
    } else if (header.alg === "RS256") {
      if (!header.kid) {
        return null;
      }
      if (!this.jwksService.hasIssuer(payload.iss)) {
        return null;
      }
      const expectedAudience = this.jwksService.expectedAudience(payload.iss);
      if (!expectedAudience || !audiences.includes(expectedAudience)) {
        return null;
      }
      const jwk = this.jwksService.getSigningKey(payload.iss, header.kid);
      if (!jwk) {
        return null;
      }
      let publicKey;
      try {
        publicKey = createPublicKey({ key: jwk as Record<string, unknown>, format: "jwk" });
      } catch {
        return null;
      }
      const isValid = verify(
        "RSA-SHA256",
        Buffer.from(signedPayload),
        publicKey,
        Buffer.from(signatureSegment, "base64url")
      );
      if (!isValid) {
        return null;
      }
    } else {
      return null;
    }

    const delegationChain =
      payload.dch && Array.isArray(payload.dch) && payload.dch.every((item) => typeof item === "string")
        ? payload.dch
        : undefined;

    return {
      tokenId: payload.jti ?? createId("jwt_ext"),
      subject: payload.sub,
      tenantIds,
      scopes,
      role: payload.role,
      delegationChain,
      serviceAccountId: payload.sai,
      issuer: payload.iss,
      tokenType: "jwt"
    };
  }
}
