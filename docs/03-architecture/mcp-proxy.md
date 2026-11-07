# MCP Proxy Mode (PC-006)

OARS can expose a Model Context Protocol (MCP) Streamable HTTP endpoint at `/mcp` to act as an "AI tool gateway".

In this mode:

- OARS advertises upstream MCP tools (namespaced) via `tools/list`.
- When a tool is called (`tools/call`), OARS converts the call into an OARS action request.
- Policy evaluation + approval workflows apply before connector execution.
- When allowed, OARS executes the upstream MCP tool via the built-in `mcp` connector.

## Endpoint

- MCP Streamable HTTP: `POST/GET/DELETE /mcp`
- Requires `Authorization: Bearer ...` on every request, including session reuse and deletion.
- Tool scopes: `oars_get_action` requires `actions:read`, `oars_list_receipts` requires `receipts:read`, and upstream proxy calls require `actions:write`. Initialization and tool discovery only require authentication.
- Sessions bind to the authenticated subject and selected tenant. Tokens may rotate, but current scopes and tenant membership are checked for each call.
- Action/receipt reads are confined to the selected session tenant, even when a token can access other tenants. Missing and inaccessible actions return the same tool error.
- Unknown or expired session IDs return HTTP 404; initialize again without the stale session ID.
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


## Authorization references

The session binding and per-request checks follow the [MCP session hijacking guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking). Object reads follow [OWASP API1:2023 object-level authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/). The versioned MCP guidance applies to the stateful Streamable HTTP transport used here.
