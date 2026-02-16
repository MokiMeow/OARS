import { ZodError } from "zod";
import { createId } from "../lib/id.js";
import type { PlatformContext } from "../core/services/platform-context.js";
import type { TokenClaims } from "../core/types/auth.js";

export function requestIdFromHeaders(headers: Record<string, unknown>): string {
  const header = headers["x-request-id"];
  if (typeof header === "string" && header.trim().length > 0) {
    return header;
  }
  if (Array.isArray(header) && typeof header[0] === "string" && header[0].trim().length > 0) {
    return header[0];
  }
  return createId("req");
}

export function authHeaderFromHeaders(headers: Record<string, unknown>): string | undefined {
  const header = headers.authorization;
  if (typeof header === "string") {
    return header;
  }
  if (Array.isArray(header) && typeof header[0] === "string") {
    return header[0];
  }
  return undefined;
}

export function idempotencyKeyFromHeaders(headers: Record<string, unknown>): string | null {
  const header = headers["idempotency-key"];
  if (typeof header === "string" && header.trim().length > 0) {
    return header.trim();
  }
  if (Array.isArray(header) && typeof header[0] === "string" && header[0].trim().length > 0) {
    return header[0].trim();
  }
  return null;
}

export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly errorCode: string,
    message: string
  ) {
    super(message);
  }
}

export function authenticate(context: PlatformContext, headers: Record<string, unknown>, scope: string): TokenClaims {
  const authHeader = authHeaderFromHeaders(headers);
  let claims: TokenClaims;
  try {
    claims = context.authService.authenticate(authHeader);
  } catch (error) {
    throw new HttpError(401, "unauthorized", error instanceof Error ? error.message : "Unauthorized.");
  }

  try {
    context.authService.requireScope(claims, scope);
  } catch (error) {
    throw new HttpError(403, "forbidden", error instanceof Error ? error.message : "Forbidden.");
  }

  try {
    context.serviceIdentityService.enforceRequestIdentity(claims, headers);
  } catch (error) {
    throw new HttpError(403, "mtls_identity_required", error instanceof Error ? error.message : "Forbidden.");
  }

  return claims;
}

export function requireTenantAccess(context: PlatformContext, claims: TokenClaims, tenantId: string): void {
  try {
    context.authService.requireTenantAccess(claims, tenantId);
  } catch (error) {
    throw new HttpError(403, "tenant_forbidden", error instanceof Error ? error.message : "Tenant access denied.");
  }
}

export function requireRole(context: PlatformContext, claims: TokenClaims, role: TokenClaims["role"]): void {
  try {
    context.authService.requireRole(claims, role);
  } catch (error) {
    throw new HttpError(403, "forbidden", error instanceof Error ? error.message : "Forbidden.");
  }
}

export function handleError(
  error: unknown,
  reply: { status: (code: number) => { send: (body: unknown) => unknown } },
  requestId?: string
) {
  const errorBody = (body: Record<string, unknown>) =>
    requestId
      ? {
          ...body,
          requestId
        }
      : body;

  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: errorBody({
        code: "validation_error",
        message: "Invalid request payload.",
        details: error.issues
      })
    });
  }

  if (error instanceof HttpError) {
    return reply.status(error.statusCode).send({
      error: errorBody({
        code: error.errorCode,
        message: error.message
      })
    });
  }

  if (error instanceof Error) {
    const maybeStatus = (error as unknown as { statusCode?: unknown }).statusCode;
    const statusCode =
      typeof maybeStatus === "number" && Number.isFinite(maybeStatus) && maybeStatus >= 400 && maybeStatus <= 599
        ? maybeStatus
        : 400;
    return reply.status(statusCode).send({
      error: errorBody({
        code: "request_error",
        message: error.message
      })
    });
  }

  return reply.status(500).send({
    error: errorBody({
      code: "internal_error",
      message: "Unexpected error."
    })
  });
}

