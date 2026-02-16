import type { AlertRecord } from "../types/domain.js";
import type { PlatformStore } from "../store/platform-store.js";

type FetchLike = (input: string, init?: RequestInit) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

type BaseChannelConfig = {
  id: string;
  enabled?: boolean | undefined;
};

type GenericWebhookChannel = BaseChannelConfig & {
  type: "generic_webhook";
  url: string;
  headers?: Record<string, string> | undefined;
};

type SlackWebhookChannel = BaseChannelConfig & {
  type: "slack_webhook";
  url: string;
};

type PagerDutyEventsV2Channel = BaseChannelConfig & {
  type: "pagerduty_events_v2";
  routingKey: string;
  source?: string | undefined;
};

export type AlertChannelConfig = GenericWebhookChannel | SlackWebhookChannel | PagerDutyEventsV2Channel;

export interface AlertRoutingServiceOptions {
  channels?: AlertChannelConfig[] | undefined;
  rawChannelsConfig?: string | undefined;
  fetchFn?: FetchLike | undefined;
  legacyWebhookUrl?: string | undefined;
}

export interface AlertDeliveryResult {
  channelId: string;
  channelType: AlertChannelConfig["type"] | "unknown";
  ok: boolean;
  status: number | null;
  error: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRecordOfStrings(value: unknown): value is Record<string, string> {
  if (!isRecord(value)) {
    return false;
  }
  return Object.values(value).every((entry) => typeof entry === "string");
}

function parseChannelConfig(entry: unknown): AlertChannelConfig | null {
  if (!isRecord(entry)) {
    return null;
  }
  const id = entry.id;
  const type = entry.type;
  const enabled = entry.enabled;
  if (typeof id !== "string" || id.trim().length === 0) {
    return null;
  }
  if (typeof type !== "string" || type.trim().length === 0) {
    return null;
  }
  const enabledFlag = typeof enabled === "boolean" ? enabled : undefined;

  if (type === "generic_webhook") {
    const url = entry.url;
    const headers = entry.headers;
    if (typeof url !== "string" || url.trim().length === 0) {
      return null;
    }
    if (headers !== undefined && !isRecordOfStrings(headers)) {
      return null;
    }
    return {
      id,
      type,
      url,
      ...(enabledFlag === undefined ? {} : { enabled: enabledFlag }),
      ...(headers === undefined ? {} : { headers })
    };
  }

  if (type === "slack_webhook") {
    const url = entry.url;
    if (typeof url !== "string" || url.trim().length === 0) {
      return null;
    }
    return {
      id,
      type,
      url,
      ...(enabledFlag === undefined ? {} : { enabled: enabledFlag })
    };
  }

  if (type === "pagerduty_events_v2") {
    const routingKey = entry.routingKey;
    const source = entry.source;
    if (typeof routingKey !== "string" || routingKey.trim().length === 0) {
      return null;
    }
    if (source !== undefined && typeof source !== "string") {
      return null;
    }
    return {
      id,
      type,
      routingKey,
      ...(enabledFlag === undefined ? {} : { enabled: enabledFlag }),
      ...(source === undefined ? {} : { source })
    };
  }

  return null;
}

function normalizeChannels(options?: AlertRoutingServiceOptions): AlertChannelConfig[] {
  if (options?.channels && options.channels.length > 0) {
    return options.channels;
  }

  const raw = options?.rawChannelsConfig ?? process.env.OARS_ALERT_CHANNELS;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) {
        const validated: AlertChannelConfig[] = [];
        for (const entry of parsed) {
          const channel = parseChannelConfig(entry);
          if (channel) {
            validated.push(channel);
          }
        }
        return validated;
      }
    } catch {
      // Fall through to legacy mapping.
    }
  }

  const legacyWebhookUrl = options?.legacyWebhookUrl ?? process.env.OARS_ALERT_WEBHOOK_URL;
  if (legacyWebhookUrl) {
    return [
      {
        id: "legacy_alert_webhook",
        type: "generic_webhook",
        url: legacyWebhookUrl
      }
    ];
  }

  return [];
}

function defaultChannelsForSeverity(severity: AlertRecord["severity"]): string[] {
  if (severity === "critical") {
    return ["pagerduty", "slack_secops"];
  }
  if (severity === "high") {
    return ["slack_secops"];
  }
  if (severity === "medium") {
    return ["slack_secops"];
  }
  return ["slack_secops"];
}

export class AlertRoutingService {
  private readonly channels: AlertChannelConfig[];
  private readonly fetchFn: FetchLike;

  constructor(
    private readonly store: PlatformStore,
    options?: AlertRoutingServiceOptions
  ) {
    this.channels = normalizeChannels(options).filter((channel) => channel.enabled !== false);
    this.fetchFn = options?.fetchFn ?? (fetch as unknown as FetchLike);
  }

  configuredChannelIds(): string[] {
    return this.channels.map((channel) => channel.id);
  }

  async deliver(alert: AlertRecord): Promise<AlertDeliveryResult[]> {
    if (this.channels.length === 0) {
      return [];
    }

    const rule = (await this.store.listAlertRoutingRulesByTenant(alert.tenantId)).find(
      (entry) => entry.severity === alert.severity
    );
    const channelIds = rule?.channels?.length ? rule.channels : defaultChannelsForSeverity(alert.severity);

    const results: AlertDeliveryResult[] = [];
    for (const channelId of channelIds) {
      const channel = this.channels.find((entry) => entry.id === channelId);
      if (!channel) {
        results.push({
          channelId,
          channelType: "unknown",
          ok: false,
          status: null,
          error: "Channel not configured."
        });
        continue;
      }

      results.push(await this.sendToChannel(channel, alert));
    }

    return results;
  }

  private async sendToChannel(channel: AlertChannelConfig, alert: AlertRecord): Promise<AlertDeliveryResult> {
    try {
      switch (channel.type) {
        case "generic_webhook": {
          const response = await this.fetchFn(channel.url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(channel.headers ?? {})
            },
            body: JSON.stringify(alert)
          });
          return {
            channelId: channel.id,
            channelType: channel.type,
            ok: response.ok,
            status: response.status,
            error: response.ok ? null : await response.text()
          };
        }
        case "slack_webhook": {
          const response = await this.fetchFn(channel.url, {
            method: "POST",
            headers: {
              "content-type": "application/json"
            },
            body: JSON.stringify({
              text:
                `[${alert.severity.toUpperCase()}] ${alert.code} - ${alert.message}\n` +
                `tenant=${alert.tenantId}${alert.actionId ? ` action=${alert.actionId}` : ""}`
            })
          });
          return {
            channelId: channel.id,
            channelType: channel.type,
            ok: response.ok,
            status: response.status,
            error: response.ok ? null : await response.text()
          };
        }
        case "pagerduty_events_v2": {
          const response = await this.fetchFn("https://events.pagerduty.com/v2/enqueue", {
            method: "POST",
            headers: {
              "content-type": "application/json"
            },
            body: JSON.stringify({
              routing_key: channel.routingKey,
              event_action: "trigger",
              payload: {
                summary: `[${alert.severity.toUpperCase()}] ${alert.code} - ${alert.message}`,
                source: channel.source ?? "oars-platform",
                severity:
                  alert.severity === "critical"
                    ? "critical"
                    : alert.severity === "high"
                      ? "error"
                      : alert.severity === "medium"
                        ? "warning"
                        : "info",
                custom_details: {
                  alertId: alert.id,
                  tenantId: alert.tenantId,
                  actionId: alert.actionId,
                  code: alert.code,
                  metadata: alert.metadata
                }
              }
            })
          });
          return {
            channelId: channel.id,
            channelType: channel.type,
            ok: response.ok,
            status: response.status,
            error: response.ok ? null : await response.text()
          };
        }
      }

      const unreachable: never = channel;
      throw new Error(`Unsupported channel type: ${(unreachable as unknown as { type?: string }).type ?? "unknown"}`);
    } catch (error) {
      return {
        channelId: channel.id,
        channelType: channel.type,
        ok: false,
        status: null,
        error: error instanceof Error ? error.message : "Unknown error."
      };
    }
  }
}
