# MCP Proxy Mode (PC-006)

OARS can expose a Model Context Protocol (MCP) Streamable HTTP endpoint at `/mcp` to act as an "AI tool gateway".

In this mode:

- OARS advertises upstream MCP tools (namespaced) via `tools/list`.
- When a tool is called (`tools/call`), OARS converts the call into an OARS action request.
- Policy evaluation + approval workflows apply before connector execution.
- When allowed, OARS executes the upstream MCP tool via the built-in `mcp` connector.

## Endpoint

- MCP Streamable HTTP: `POST/GET /mcp`
- Requires `Authorization: Bearer ...` (scope `actions:write`).
- If a token has multiple tenants, clients must send `x-oars-tenant-id`.

## Upstream Configuration

Configure upstream MCP servers via:

- `OARS_MCP_UPSTREAMS` JSON array of `{ id, url, headers? }`
- `OARS_MCP_ALLOW_PRIVATE_NETWORK=true` to allow private network upstream URLs (default is blocked)
- `OARS_MCP_TOOL_CACHE_TTL_SECONDS` tool-list cache TTL (default `300`)

Example:

```json
[
  {
    "id": "github",
    "url": "https://mcp-github.example.com/mcp",
    "headers": {
      "Authorization": "Bearer upstream-token"
    }
  }
]
```

## Tool Naming

Upstream tools are exposed as MCP tools named:

- `mcp_<upstreamId>__<toolName>` (non-alphanumeric characters are normalized to `_`)

These tool calls map to OARS actions:

- `resource.toolId = "mcp"`
- `resource.target = <upstreamId>`
- `resource.operation = <toolName>`
- `input = <tool arguments>`

