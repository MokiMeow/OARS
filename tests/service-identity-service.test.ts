import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ServiceIdentityService } from "../src/core/services/service-identity-service.js";
import type { TokenClaims } from "../src/core/types/auth.js";

function makeClaims(overrides?: Partial<TokenClaims>): TokenClaims {
  return {
    tokenId: "tok_test",
    subject: "service_account:svc_test",
    tenantIds: ["tenant_alpha"],
    scopes: ["actions:read"],
    role: "service",
    serviceAccountId: "svc_test",
    ...overrides
  };
}

describe("ServiceIdentityService (trusted identity file)", () => {
  it("loads trusted identities from file when provided", () => {
    const baseDir = mkdtempSync(join(tmpdir(), "oars-mtls-"));
    const filePath = join(baseDir, "trusted-identities.json");
    try {
      writeFileSync(
        filePath,
        JSON.stringify(
          [
            {
              subject: "oars-worker",
              fingerprintSha256: "AA:BB:CC"
            }
          ],
          null,
          2
        ),
        "utf8"
      );

      const service = new ServiceIdentityService({
        enabled: true,
        enforceForRoles: ["service"],
        trustedIdentitiesFilePath: filePath
      });

      expect(() =>
        service.enforceRequestIdentity(makeClaims(), {
          "x-oars-mtls-subject": "oars-worker",
          "x-oars-mtls-fingerprint": "aabbcc"
        })
      ).not.toThrow();
    } finally {
      rmSync(baseDir, { force: true, recursive: true });
    }
  });

  it("falls back to env trusted identities when file is empty/invalid", () => {
    const prev = process.env.OARS_MTLS_TRUSTED_IDENTITIES;
    const baseDir = mkdtempSync(join(tmpdir(), "oars-mtls-"));
    const filePath = join(baseDir, "trusted-identities.json");
    try {
      writeFileSync(filePath, "[]", "utf8");
      process.env.OARS_MTLS_TRUSTED_IDENTITIES = JSON.stringify([
        { subject: "from-env", fingerprintSha256: "deadbeef" }
      ]);

      const service = new ServiceIdentityService({
        enabled: true,
        enforceForRoles: ["service"],
        trustedIdentitiesFilePath: filePath
      });

      expect(() =>
        service.enforceRequestIdentity(makeClaims({ subject: "service_account:svc_test" }), {
          "x-oars-mtls-subject": "from-env",
          "x-oars-mtls-fingerprint": "DE:AD:BE:EF"
        })
      ).not.toThrow();
    } finally {
      process.env.OARS_MTLS_TRUSTED_IDENTITIES = prev;
      rmSync(baseDir, { force: true, recursive: true });
    }
  });
});

