import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createId } from "../src/lib/id.js";
import { SiemDeliveryService } from "../src/core/services/siem-delivery-service.js";
import type { SecurityEventRecord } from "../src/core/types/domain.js";

function mockFetch(responses: Array<{ ok: boolean; status: number }>) {
  let callIndex = 0;
  const calls: Array<{ url: string; init: RequestInit | null }> = [];
  const fn = async (url: string, init?: RequestInit) => {
    calls.push({ url, init: init ?? null });
    const response = responses[callIndex] ?? { ok: true, status: 200 };
    callIndex++;
    return {
      ok: response.ok,
      status: response.status,
      text: async () => (response.ok ? "ok" : "error")
    };
  };
  return { fn, calls };
}

function makeEvent(id: string): SecurityEventRecord {
  return {
    id,
    tenantId: "tenant_alpha",
    source: "admin",
    eventType: "test.event",
    occurredAt: new Date().toISOString(),
    payload: { test: true }
  };
}

describe("SiemDeliveryService", () => {
  it("delivers to generic webhook target", async () => {
    const { fn, calls } = mockFetch([{ ok: true, status: 200 }]);
    const service = new SiemDeliveryService({
      rawTargetsConfig: JSON.stringify([
        { type: "generic_webhook", id: "test_webhook", url: "https://siem.example.com/events" }
      ]),
      fetchFn: fn as any,
      autoStartRetry: false
    });

    await service.deliver(makeEvent("evt_1"));
    expect(calls.length).toBe(1);
    expect(calls[0]?.url).toBe("https://siem.example.com/events");
  });

  it("delivers to splunk HEC target", async () => {
    const { fn, calls } = mockFetch([{ ok: true, status: 200 }]);
    const service = new SiemDeliveryService({
      rawTargetsConfig: JSON.stringify([
        { type: "splunk_hec", id: "splunk_1", url: "https://splunk.example.com:8088/services/collector", token: "test-token" }
      ]),
      fetchFn: fn as any,
      autoStartRetry: false
    });

    await service.deliver(makeEvent("evt_2"));
    expect(calls.length).toBe(1);
    const headers = calls[0]?.init?.headers as Record<string, string> | undefined;
    expect(headers?.["authorization"]).toContain("Splunk");
  });

  it("queues failed deliveries for retry", async () => {
    const { fn } = mockFetch([{ ok: false, status: 500 }]);
    const service = new SiemDeliveryService({
      rawTargetsConfig: JSON.stringify([
        { type: "generic_webhook", id: "fail_webhook", url: "https://siem.example.com/events" }
      ]),
      fetchFn: fn as any,
      autoStartRetry: false
    });

    await service.deliver(makeEvent("evt_3"));
    const s = service.status();
    expect(s.queueLength).toBeGreaterThanOrEqual(1);
  });

  it("respects backpressure queue limit", async () => {
    const { fn } = mockFetch(Array(20).fill({ ok: false, status: 500 }));
    const service = new SiemDeliveryService({
      rawTargetsConfig: JSON.stringify([
        { type: "generic_webhook", id: "bp_webhook", url: "https://siem.example.com/events" }
      ]),
      fetchFn: fn as any,
      autoStartRetry: false,
      maxQueueSize: 3
    });

    for (let i = 0; i < 10; i++) {
      await service.deliver(makeEvent(`evt_bp_${i}`));
    }

    const s = service.status();
    expect(s.queueLength).toBeLessThanOrEqual(3);
  });

  it("returns empty targets with no targets configured", () => {
    const suffix = createId("t");
    const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
    const service = new SiemDeliveryService({
      autoStartRetry: false,
      queueFilePath: join(baseDir, `siem-test-empty-${suffix}.json`)
    });
    const s = service.status();
    expect(s.targets.length).toBe(0);
    expect(s.queueLength).toBe(0);
    rmSync(baseDir, { force: true, recursive: true });
  });
});
