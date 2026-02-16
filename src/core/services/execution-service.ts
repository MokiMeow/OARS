import { nowIso } from "../../lib/time.js";
import { isIP } from "node:net";
import type { ActionRecord } from "../types/domain.js";
import { ConnectorRegistry } from "../connectors/registry.js";
import { VaultSecretService } from "./vault-secret-service.js";

export interface ExecutionResult {
  success: boolean;
  output: Record<string, unknown>;
  error: string | null;
  executedAt: string;
}

export class ExecutionService {
  constructor(
    private readonly connectorRegistry: ConnectorRegistry,
    private readonly vaultSecretService?: VaultSecretService
  ) {}

  async execute(action: ActionRecord): Promise<ExecutionResult> {
    const operation = action.resource.operation.toLowerCase();

    if (operation.includes("fail")) {
      return {
        success: false,
        output: {},
        error: "Simulated connector failure based on operation pattern.",
        executedAt: nowIso()
      };
    }

    if (this.isForbiddenTarget(action.resource.target)) {
      return {
        success: false,
        output: {},
        error: "Execution blocked by connector sandbox target policy.",
        executedAt: nowIso()
      };
    }

    const connector = this.connectorRegistry.get(action.resource.toolId);
    if (!connector) {
      return {
        success: false,
        output: {},
        error: `No registered connector for tool: ${action.resource.toolId}`,
        executedAt: nowIso()
      };
    }

    if (action.resource.toolId === "database") {
      const hasConnectionSecret = this.vaultSecretService?.hasSecret(action.tenantId, "database", "connection");
      if (!hasConnectionSecret) {
        return {
          success: false,
          output: {},
          error: "Missing required database connection secret in vault.",
          executedAt: nowIso()
        };
      }
    }

    const connectorResult = await connector.execute(action);
    const sanitizedOutput = this.sanitize({
      ...connectorResult.output,
      toolId: action.resource.toolId,
      operation: action.resource.operation,
      target: action.resource.target,
      referenceId: `exec_${action.id}`
    });

    return {
      success: connectorResult.success,
      output: sanitizedOutput,
      error: connectorResult.error,
      executedAt: nowIso()
    };
  }

  private isForbiddenTarget(target: string): boolean {
    const normalized = target.trim().toLowerCase();

    // Cloud metadata endpoints (block even if embedded in an unparsed identifier).
    if (
      normalized.includes("169.254.") ||
      normalized.includes("metadata.internal") ||
      normalized.includes("metadata.google")
    ) {
      return true;
    }

    let host = normalized;
    try {
      if (normalized.startsWith("http://") || normalized.startsWith("https://")) {
        host = new URL(normalized).hostname.toLowerCase();
      } else {
        // Extract hostname portion (handle URLs and bare hostnames)
        const hostMatch = normalized.match(/^(?:https?:\/\/)?([^/:]+)/);
        host = hostMatch?.[1] ?? normalized;
      }
    } catch {
      // Leave as-is for non-URL identifiers (e.g., `project:SEC`).
    }

    // Strip IPv6 brackets.
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.slice(1, -1);
    }

    // Localhost variants.
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0" || host === "::") {
      return true;
    }

    const ipVersion = isIP(host);
    if (ipVersion === 4) {
      const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      const first = ipv4Match ? Number.parseInt(ipv4Match[1]!, 10) : NaN;
      const second = ipv4Match ? Number.parseInt(ipv4Match[2]!, 10) : NaN;
      if (Number.isNaN(first) || Number.isNaN(second)) {
        return true;
      }
      if (first === 10) return true; // 10.0.0.0/8
      if (first === 172 && second >= 16 && second <= 31) return true; // 172.16.0.0/12
      if (first === 192 && second === 168) return true; // 192.168.0.0/16
      if (first === 127) return true; // 127.0.0.0/8
      if (first === 169 && second === 254) return true; // 169.254.0.0/16
      if (first === 0) return true; // 0.0.0.0/8
      if (first === 100 && second >= 64 && second <= 127) return true; // 100.64.0.0/10 (CGNAT)
      if (first === 198 && (second === 18 || second === 19)) return true; // 198.18.0.0/15 (benchmarking)
    }

    if (ipVersion === 6) {
      const lower = host.toLowerCase();
      if (lower.startsWith("fd") || lower.startsWith("fc")) return true; // fc00::/7 ULA
      if (lower.startsWith("fe80")) return true; // fe80::/10 link-local (prefix check is coarse but safe)
      if (lower.startsWith("::ffff:")) {
        const mapped = lower.slice("::ffff:".length);
        if (isIP(mapped) === 4) {
          return this.isForbiddenTarget(mapped);
        }
        const parts = mapped.split(":").filter(Boolean);
        if (parts.length === 2 && parts.every((part) => /^[0-9a-f]{1,4}$/.test(part))) {
          const hi = Number.parseInt(parts[0]!, 16);
          const lo = Number.parseInt(parts[1]!, 16);
          const a = (hi >> 8) & 0xff;
          const b = hi & 0xff;
          const c = (lo >> 8) & 0xff;
          const d = lo & 0xff;
          return this.isForbiddenTarget(`${a}.${b}.${c}.${d}`);
        }
        // Fail closed on unknown ::ffff: encodings.
        return true;
      }
    }

    return false;
  }

  private sanitize(payload: Record<string, unknown>): Record<string, unknown> {
    const blockedKeys = new Set(["password", "secret", "token"]);
    const out: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(payload)) {
      if (blockedKeys.has(key.toLowerCase())) {
        out[key] = "[REDACTED]";
        continue;
      }
      out[key] = value;
    }

    return out;
  }
}
