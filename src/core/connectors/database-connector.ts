import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";

const SQL_COMMENT_SINGLE_LINE = /--[^\r\n]*/g;
const SQL_COMMENT_BLOCK = /\/\*[\s\S]*?\*\//g;

function isDestructiveSql(sql: string): boolean {
  // Normalize by removing comments and string literals so we don't false-positive on harmless payload text.
  // This is not a full SQL parser; it's a defensive "read-only" guardrail for the demo connector.
  const withoutComments = sql.replace(SQL_COMMENT_SINGLE_LINE, "").replace(SQL_COMMENT_BLOCK, "");
  const withoutStrings = withoutComments
    .replace(/'(?:''|[^'])*'/g, "''")
    .replace(/\"(?:\"\"|[^\"])*\"/g, "\"\"");

  const normalized = withoutStrings
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, " ")
    .trim();

  // Catch both spaced and collapsed variants (e.g., comment removal can collapse `delete/**/from` -> `deletefrom`).
  const patterns = [
    /\bdrop\b/,
    /\btruncate\b/,
    /\bgrant\b/,
    /\brevoke\b/,
    /\bdelete\b\s+\bfrom\b/,
    /\bdeletefrom\b/,
    /\balter\b\s+\btable\b/,
    /\baltertable\b/
  ];

  return patterns.some((pattern) => pattern.test(normalized));
}

export class DatabaseConnector implements Connector {
  readonly toolId = "database";

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    if (action.resource.operation !== "run_query") {
      return {
        success: false,
        output: {},
        error: `Unsupported database operation: ${action.resource.operation}`
      };
    }

    const sql = typeof action.input.sql === "string" ? action.input.sql : "";
    if (isDestructiveSql(sql)) {
      return {
        success: false,
        output: {},
        error: "Destructive SQL statements are blocked by connector policy."
      };
    }

    return {
      success: true,
      output: {
        queryRef: `db_${action.id.slice(-8)}`,
        target: action.resource.target,
        rowCount: 1,
        status: "completed"
      },
      error: null
    };
  }
}
