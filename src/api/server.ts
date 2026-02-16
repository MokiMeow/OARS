import Fastify from "fastify";
import { readFileSync } from "node:fs";
import { createPlatformContext, type PlatformContext } from "../core/services/platform-context.js";
import { authHeaderFromHeaders, handleError, requestIdFromHeaders } from "./http.js";
import { registerActionRoutes } from "./routes/actions.js";
import { registerAdminRoutes } from "./routes/admin.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerEvidenceRoutes } from "./routes/evidence.js";
import { registerPolicyRoutes } from "./routes/policies.js";
import { registerPublicRoutes } from "./routes/public.js";
import { registerReceiptRoutes } from "./routes/receipts.js";
import { registerTenantRoutes } from "./routes/tenants.js";
import { registerMcpRoutes } from "./routes/mcp.js";

export function buildServer(context = createPlatformContext()) {
  const bodyLimitBytes = Number.parseInt(process.env.OARS_BODY_LIMIT_BYTES ?? "1048576", 10);
  const rateLimitWindowMs = 60_000;
  const rateLimitMax = Number.parseInt(process.env.OARS_RATE_LIMIT_RPM ?? "300", 10);
  const mtlsMode = (process.env.OARS_MTLS_MODE ?? "header").trim().toLowerCase();
  const tlsKeyPath = process.env.OARS_TLS_KEY_PATH;
  const tlsCertPath = process.env.OARS_TLS_CERT_PATH;
  const mtlsCaPath = process.env.OARS_MTLS_CA_PATH;

  const https =
    tlsKeyPath && tlsCertPath
      ? {
          key: readFileSync(tlsKeyPath),
          cert: readFileSync(tlsCertPath),
          ...(mtlsMode === "tls"
            ? {
                requestCert: true,
                // Allow the handshake so we can return a clear 403 and still serve /health to infra probes.
                rejectUnauthorized: false,
                ...(mtlsCaPath ? { ca: readFileSync(mtlsCaPath) } : {})
              }
            : {})
        }
      : undefined;

  if (mtlsMode === "tls" && !https) {
    throw new Error("OARS_MTLS_MODE=tls requires OARS_TLS_KEY_PATH and OARS_TLS_CERT_PATH.");
  }
  if (mtlsMode === "tls" && !mtlsCaPath) {
    throw new Error("OARS_MTLS_MODE=tls requires OARS_MTLS_CA_PATH (CA bundle for client cert verification).");
  }

  interface RateBucket {
    timestamps: number[];
  }

  const rateBuckets = new Map<string, RateBucket>();

  function checkRateLimit(key: string): { allowed: boolean; remaining: number } {
    if (rateLimitMax <= 0) {
      return { allowed: true, remaining: 0 };
    }
    const now = Date.now();
    const cutoff = now - rateLimitWindowMs;
    let bucket = rateBuckets.get(key);
    if (!bucket) {
      bucket = { timestamps: [] };
      rateBuckets.set(key, bucket);
    }
    bucket.timestamps = bucket.timestamps.filter((ts) => ts > cutoff);
    if (bucket.timestamps.length >= rateLimitMax) {
      return { allowed: false, remaining: 0 };
    }
    bucket.timestamps.push(now);
    return { allowed: true, remaining: rateLimitMax - bucket.timestamps.length };
  }

  const app = Fastify({
    logger: false,
    bodyLimit: bodyLimitBytes,
    ...(https ? { https } : {})
  });

  // When configured, derive workload identity from a verified TLS client certificate.
  // This keeps the rest of the auth pipeline unchanged (ServiceIdentityService reads the same headers),
  // while preventing spoofing by overwriting any presented header values in TLS mode.
  app.addHook("onRequest", async (request, reply) => {
    if (mtlsMode !== "tls") {
      return;
    }
    const headers = request.headers as unknown as Record<string, unknown>;
    delete headers["x-oars-mtls-subject"];
    delete headers["x-oars-mtls-fingerprint"];
    delete headers["x-oars-mtls-issued-at"];
    delete headers["x-oars-mtls-signature"];

    const socket = request.raw.socket as unknown as {
      authorized?: boolean | undefined;
      getPeerCertificate?: (() => unknown) | undefined;
    };

    if (!socket || typeof socket.getPeerCertificate !== "function" || !socket.authorized) {
      return;
    }

    const peerCert = socket.getPeerCertificate() as {
      subject?: { CN?: string | undefined } | undefined;
      fingerprint256?: string | undefined;
      fingerprint?: string | undefined;
    };
    const subject = peerCert?.subject?.CN;
    const fingerprint = peerCert?.fingerprint256 ?? peerCert?.fingerprint;

    if (typeof subject === "string" && subject.trim().length > 0) {
      headers["x-oars-mtls-subject"] = subject.trim();
    }
    if (typeof fingerprint === "string" && fingerprint.trim().length > 0) {
      headers["x-oars-mtls-fingerprint"] = fingerprint.trim();
    }
  });

  // Security response headers
  app.addHook("onRequest", async (request, reply) => {
    const headers = request.headers as unknown as Record<string, unknown>;
    const requestId = requestIdFromHeaders(headers);
    headers["x-request-id"] = requestId;
    reply.header("x-request-id", requestId);
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("cache-control", "no-store");
    // Deprecated in modern browsers; set to 0 to avoid legacy misbehavior.
    reply.header("x-xss-protection", "0");
  });

  // Rate limiting hook (skip /health)
  app.addHook("onRequest", async (request, reply) => {
    if (request.url === "/health") {
      return;
    }
    const authHeader = authHeaderFromHeaders(request.headers as unknown as Record<string, unknown>);
    const rateLimitKey = authHeader ?? request.ip ?? "unknown";
    const result = checkRateLimit(rateLimitKey);
    reply.header("x-ratelimit-limit", String(rateLimitMax));
    reply.header("x-ratelimit-remaining", String(result.remaining));
    if (!result.allowed) {
      return reply.status(429).send({
        error: {
          code: "rate_limit_exceeded",
          message: "Too many requests. Try again later."
        }
      });
    }
  });

  // CORS
  const corsOrigins = process.env.OARS_CORS_ORIGINS;
  if (corsOrigins) {
    const allowed = corsOrigins
      .split(",")
      .map((o) => o.trim())
      .filter(Boolean);
    const allowAll = allowed.includes("*");

    app.addHook("onRequest", async (request, reply) => {
      const origin = (request.headers as Record<string, unknown>).origin;
      if (typeof origin === "string") {
        if (allowAll || allowed.includes(origin)) {
          reply.header("access-control-allow-origin", allowAll ? "*" : origin);
          reply.header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
          reply.header(
            "access-control-allow-headers",
            "Authorization, Content-Type, Idempotency-Key, X-Request-Id, X-OARS-mTLS-Subject, X-OARS-mTLS-Fingerprint, X-OARS-mTLS-Issued-At, X-OARS-mTLS-Signature, mcp-session-id, mcp-protocol-version, Last-Event-ID, X-OARS-Tenant-Id"
          );
          reply.header("access-control-max-age", "86400");
          if (!allowAll) {
            reply.header("vary", "Origin");
          }
        }
      }
      if (request.method === "OPTIONS") {
        if (typeof origin === "string" && origin.trim().length > 0 && !(allowAll || allowed.includes(origin))) {
          return reply.status(403).send({
            error: {
              code: "cors_forbidden",
              message: "Origin is not allowed."
            }
          });
        }
        return reply.status(204).send();
      }
    });
  }

  // Periodically purge stale buckets to prevent memory growth (per server instance)
  const ratePurgeTimer = setInterval(() => {
    if (rateLimitMax <= 0) {
      rateBuckets.clear();
      return;
    }
    const cutoff = Date.now() - rateLimitWindowMs * 2;
    for (const [key, bucket] of rateBuckets) {
      if (bucket.timestamps.length === 0 || bucket.timestamps[bucket.timestamps.length - 1]! < cutoff) {
        rateBuckets.delete(key);
      }
    }
  }, rateLimitWindowMs * 2).unref();

  app.addHook("onClose", async () => {
    clearInterval(ratePurgeTimer);
    context.jwksService.stopAutoRefresh();
    context.securityEventService.stopSiemRetryScheduler();
    await context.executionBackplane?.close?.();
    await context.store.close?.();
  });

  registerPublicRoutes(app, context);
  registerAuthRoutes(app, context);
  registerTenantRoutes(app, context);
  registerActionRoutes(app, context);
  registerReceiptRoutes(app, context);
  registerPolicyRoutes(app, context);
  registerEvidenceRoutes(app, context);
  registerAdminRoutes(app, context);
  registerMcpRoutes(app, context);

  app.setErrorHandler((error, request, reply) =>
    handleError(error, reply, requestIdFromHeaders(request.headers as Record<string, unknown>))
  );

  return app;
}

export type { PlatformContext };
