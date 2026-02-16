import { IamConnector } from "./iam-connector.js";
import { JiraConnector } from "./jira-connector.js";
import { SlackConnector } from "./slack-connector.js";
import { ConfluenceConnector } from "./confluence-connector.js";
import { DatabaseConnector } from "./database-connector.js";
import { McpConnector } from "./mcp-connector.js";
import type { Connector } from "./types.js";

function createDefaultConnectors(): Connector[] {
  const connectors: Connector[] = [
    new JiraConnector(),
    new SlackConnector(),
    new IamConnector(),
    new ConfluenceConnector(),
    new DatabaseConnector()
  ];
  const mcp = McpConnector.fromEnv();
  if (mcp) {
    connectors.push(mcp);
  }
  return connectors;
}

function parseAllowedTools(raw: string | undefined): Set<string> | null {
  if (!raw) {
    return null;
  }
  const entries = raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (entries.length === 0) {
    return null;
  }
  return new Set(entries);
}

export class ConnectorRegistry {
  private readonly connectorsByToolId: Map<string, Connector>;
  private readonly allowedTools: Set<string> | null;

  constructor(connectors = createDefaultConnectors(), rawAllowedTools = process.env.OARS_ALLOWED_TOOLS) {
    this.connectorsByToolId = new Map(connectors.map((connector) => [connector.toolId, connector]));
    this.allowedTools = parseAllowedTools(rawAllowedTools);
  }

  get(toolId: string): Connector | null {
    if (this.allowedTools && !this.allowedTools.has(toolId)) {
      return null;
    }
    return this.connectorsByToolId.get(toolId) ?? null;
  }

  listToolIds(): string[] {
    const ids = [...this.connectorsByToolId.keys()];
    if (!this.allowedTools) {
      return ids;
    }
    return ids.filter((id) => this.allowedTools?.has(id));
  }
}
