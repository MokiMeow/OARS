interface JwkLike {
  kid?: string | undefined;
  kty?: string | undefined;
  use?: string | undefined;
  alg?: string | undefined;
  [key: string]: unknown;
}

interface JwksDocument {
  keys: JwkLike[];
}

interface OidcMetadata {
  issuer?: string | undefined;
  jwks_uri?: string | undefined;
}

interface FetchResponseLike {
  ok: boolean;
  json: () => Promise<unknown>;
}

type FetchLike = (input: string) => Promise<FetchResponseLike>;

export interface TrustedJwksProviderConfig {
  issuer: string;
  audience: string;
  jwksUri?: string | undefined;
  discoveryUrl?: string | undefined;
  jwks?: JwksDocument | undefined;
}

interface TrustedProviderState extends TrustedJwksProviderConfig {
  keysById: Map<string, JwkLike>;
  lastRefreshedAt: string | null;
  lastDiscoveryAt: string | null;
  lastError: string | null;
}

interface SchedulerResult {
  discoveredIssuers: string[];
  failedDiscoveries: string[];
  refreshedIssuers: string[];
  failedIssuers: string[];
}

interface SchedulerState {
  running: boolean;
  intervalSeconds: number;
  lastRunAt: string | null;
  tickCount: number;
  inProgress: boolean;
  lastResult: SchedulerResult | null;
  timer: NodeJS.Timeout | null;
}

interface AutoRefreshOptions {
  enabled?: boolean | undefined;
  intervalSeconds?: number | undefined;
  discoverOnStart?: boolean | undefined;
}

export interface JwksServiceOptions {
  rawTrustedJwksConfig?: string | undefined;
  trustedProviders?: TrustedJwksProviderConfig[] | undefined;
  fetchFn?: FetchLike | undefined;
  autoRefresh?: AutoRefreshOptions | undefined;
}

function isValidProvider(value: unknown): value is TrustedJwksProviderConfig {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<TrustedJwksProviderConfig>;
  return typeof candidate.issuer === "string" && typeof candidate.audience === "string";
}

function normalizeProviders(options?: JwksServiceOptions): TrustedJwksProviderConfig[] {
  if (options?.trustedProviders && options.trustedProviders.length > 0) {
    return options.trustedProviders;
  }

  const raw = options?.rawTrustedJwksConfig ?? process.env.OARS_TRUSTED_JWKS;
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter(isValidProvider);
  } catch {
    return [];
  }
}

function keysByIdFrom(provider: TrustedJwksProviderConfig): Map<string, JwkLike> {
  const map = new Map<string, JwkLike>();
  const keys = provider.jwks?.keys ?? [];
  for (const key of keys) {
    if (!key.kid) {
      continue;
    }
    map.set(key.kid, key);
  }
  return map;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  return value.trim().toLowerCase() === "true";
}

function parseInterval(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 30) {
    return fallback;
  }
  return parsed;
}

function defaultDiscoveryUrl(issuer: string): string {
  const normalized = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
  return `${normalized}/.well-known/openid-configuration`;
}

export class JwksService {
  private readonly providers = new Map<string, TrustedProviderState>();
  private readonly fetchFn: FetchLike;
  private scheduler: SchedulerState = {
    running: false,
    intervalSeconds: 300,
    lastRunAt: null,
    tickCount: 0,
    inProgress: false,
    lastResult: null,
    timer: null
  };

  constructor(options?: JwksServiceOptions) {
    const initialProviders = normalizeProviders(options);
    for (const provider of initialProviders) {
      this.providers.set(provider.issuer, {
        issuer: provider.issuer,
        audience: provider.audience,
        jwksUri: provider.jwksUri,
        discoveryUrl: provider.discoveryUrl ?? defaultDiscoveryUrl(provider.issuer),
        jwks: provider.jwks,
        keysById: keysByIdFrom(provider),
        lastRefreshedAt: provider.jwks ? new Date().toISOString() : null,
        lastDiscoveryAt: provider.discoveryUrl || provider.jwksUri ? new Date().toISOString() : null,
        lastError: null
      });
    }

    this.fetchFn = options?.fetchFn ?? (fetch as unknown as FetchLike);

    const autoRefreshEnabled =
      options?.autoRefresh?.enabled ?? parseBoolean(process.env.OARS_JWKS_AUTO_REFRESH_ENABLED, false);
    const intervalSeconds =
      options?.autoRefresh?.intervalSeconds ?? parseInterval(process.env.OARS_JWKS_AUTO_REFRESH_INTERVAL_SECONDS, 300);
    const discoverOnStart = options?.autoRefresh?.discoverOnStart ?? true;

    if (autoRefreshEnabled) {
      void this.startAutoRefresh(intervalSeconds, discoverOnStart);
    }
  }

  listProviders(): Array<{
    issuer: string;
    audience: string;
    jwksUri: string | null;
    discoveryUrl: string | null;
    keyCount: number;
    lastRefreshedAt: string | null;
    lastDiscoveryAt: string | null;
    lastError: string | null;
  }> {
    return [...this.providers.values()].map((provider) => ({
      issuer: provider.issuer,
      audience: provider.audience,
      jwksUri: provider.jwksUri ?? null,
      discoveryUrl: provider.discoveryUrl ?? null,
      keyCount: provider.keysById.size,
      lastRefreshedAt: provider.lastRefreshedAt,
      lastDiscoveryAt: provider.lastDiscoveryAt,
      lastError: provider.lastError
    }));
  }

  hasIssuer(issuer: string): boolean {
    return this.providers.has(issuer);
  }

  expectedAudience(issuer: string): string | null {
    return this.providers.get(issuer)?.audience ?? null;
  }

  getSigningKey(issuer: string, kid: string): JwkLike | null {
    const provider = this.providers.get(issuer);
    if (!provider) {
      return null;
    }
    return provider.keysById.get(kid) ?? null;
  }

  async discoverIssuer(issuer: string): Promise<boolean> {
    const provider = this.providers.get(issuer);
    if (!provider) {
      return false;
    }
    const discoveryUrl = provider.discoveryUrl ?? defaultDiscoveryUrl(provider.issuer);

    try {
      const response = await this.fetchFn(discoveryUrl);
      if (!response.ok) {
        provider.lastError = `Discovery request failed for ${issuer}`;
        return false;
      }
      const body = (await response.json()) as OidcMetadata;
      if (!body.jwks_uri || typeof body.jwks_uri !== "string") {
        provider.lastError = `Invalid discovery metadata for ${issuer}`;
        return false;
      }
      provider.discoveryUrl = discoveryUrl;
      provider.jwksUri = body.jwks_uri;
      provider.lastDiscoveryAt = new Date().toISOString();
      provider.lastError = null;
      return true;
    } catch {
      provider.lastError = `Discovery exception for ${issuer}`;
      return false;
    }
  }

  async discoverAll(): Promise<{ discoveredIssuers: string[]; failedDiscoveries: string[] }> {
    const discoveredIssuers: string[] = [];
    const failedDiscoveries: string[] = [];
    for (const provider of this.providers.values()) {
      const ok = await this.discoverIssuer(provider.issuer);
      if (ok) {
        discoveredIssuers.push(provider.issuer);
      } else {
        failedDiscoveries.push(provider.issuer);
      }
    }
    return {
      discoveredIssuers,
      failedDiscoveries
    };
  }

  async refreshIssuer(issuer: string): Promise<boolean> {
    const provider = this.providers.get(issuer);
    if (!provider) {
      return false;
    }

    if (!provider.jwksUri) {
      const discovered = await this.discoverIssuer(issuer);
      if (!discovered) {
        return false;
      }
    }

    if (!provider.jwksUri) {
      provider.lastError = `No JWKS URI available for ${issuer}`;
      return false;
    }

    try {
      const response = await this.fetchFn(provider.jwksUri);
      if (!response.ok) {
        provider.lastError = `JWKS refresh request failed for ${issuer}`;
        return false;
      }
      const body = (await response.json()) as Partial<JwksDocument>;
      if (!Array.isArray(body.keys)) {
        provider.lastError = `JWKS payload invalid for ${issuer}`;
        return false;
      }
      provider.jwks = { keys: body.keys };
      provider.keysById = keysByIdFrom(provider);
      provider.lastRefreshedAt = new Date().toISOString();
      provider.lastError = null;
      return true;
    } catch {
      provider.lastError = `JWKS refresh exception for ${issuer}`;
      return false;
    }
  }

  async refreshAll(): Promise<{ refreshedIssuers: string[]; failedIssuers: string[] }> {
    const refreshedIssuers: string[] = [];
    const failedIssuers: string[] = [];
    for (const provider of this.providers.values()) {
      const ok = await this.refreshIssuer(provider.issuer);
      if (ok) {
        refreshedIssuers.push(provider.issuer);
      } else {
        failedIssuers.push(provider.issuer);
      }
    }

    return {
      refreshedIssuers,
      failedIssuers
    };
  }

  schedulerStatus(): {
    running: boolean;
    intervalSeconds: number;
    lastRunAt: string | null;
    tickCount: number;
    inProgress: boolean;
    lastResult: SchedulerResult | null;
  } {
    return {
      running: this.scheduler.running,
      intervalSeconds: this.scheduler.intervalSeconds,
      lastRunAt: this.scheduler.lastRunAt,
      tickCount: this.scheduler.tickCount,
      inProgress: this.scheduler.inProgress,
      lastResult: this.scheduler.lastResult
    };
  }

  async startAutoRefresh(
    intervalSeconds = 300,
    discoverOnStart = true
  ): Promise<{
    running: boolean;
    intervalSeconds: number;
    lastRunAt: string | null;
    tickCount: number;
    inProgress: boolean;
    lastResult: SchedulerResult | null;
  }> {
    this.stopAutoRefresh();
    this.scheduler.running = true;
    this.scheduler.intervalSeconds = Math.max(30, intervalSeconds);
    await this.runRefreshCycle(discoverOnStart);
    this.scheduler.timer = setInterval(() => {
      void this.runRefreshCycle(false);
    }, this.scheduler.intervalSeconds * 1000);
    return this.schedulerStatus();
  }

  stopAutoRefresh(): {
    running: boolean;
    intervalSeconds: number;
    lastRunAt: string | null;
    tickCount: number;
    inProgress: boolean;
    lastResult: SchedulerResult | null;
  } {
    if (this.scheduler.timer) {
      clearInterval(this.scheduler.timer);
      this.scheduler.timer = null;
    }
    this.scheduler.running = false;
    this.scheduler.inProgress = false;
    return this.schedulerStatus();
  }

  private async runRefreshCycle(discoverFirst: boolean): Promise<void> {
    if (this.scheduler.inProgress) {
      return;
    }
    this.scheduler.inProgress = true;
    const discovered = discoverFirst
      ? await this.discoverAll()
      : { discoveredIssuers: [] as string[], failedDiscoveries: [] as string[] };
    const refreshed = await this.refreshAll();
    this.scheduler.tickCount += 1;
    this.scheduler.lastRunAt = new Date().toISOString();
    this.scheduler.lastResult = {
      discoveredIssuers: discovered.discoveredIssuers,
      failedDiscoveries: discovered.failedDiscoveries,
      refreshedIssuers: refreshed.refreshedIssuers,
      failedIssuers: refreshed.failedIssuers
    };
    this.scheduler.inProgress = false;
  }
}
