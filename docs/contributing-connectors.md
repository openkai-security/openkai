# Contributing Connectors to OpenKai

Connectors are the integration layer between OpenKai and external security tools. This guide explains how to build and contribute a connector.

## Connector Architecture

A connector is an OpenClaw extension that:
1. Authenticates with an external security tool
2. Registers tools that agents can use to query/push data
3. Handles errors gracefully when not configured

## Directory Structure

```
connectors/<connector-name>/
├── index.ts        # Plugin entry point
├── package.json    # Manifest with openclaw config
└── README.md       # Usage documentation (optional)
```

## Step-by-Step Guide

### 1. Create the directory

```bash
mkdir connectors/my-tool
```

### 2. Create package.json

```json
{
  "name": "@openkai/connector-my-tool",
  "version": "0.1.0",
  "description": "OpenKai connector for My Tool — brief description",
  "main": "index.ts",
  "openclaw": {
    "extensions": ["./index.ts"]
  },
  "dependencies": {}
}
```

### 3. Create index.ts

```typescript
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "API endpoint URL" }),
  token: Type.String({ description: "API authentication token" }),
  // Add other config fields as needed
});

const plugin = {
  id: "connector-my-tool",
  name: "OpenKai My Tool Connector",
  description: "Connect to My Tool for [what it does]",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; token?: string };

    // Helper function for API calls
    async function apiCall(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const resp = await fetch(`${config.url}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${config.token}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) {
        throw new Error(`My Tool API error: ${resp.status} ${resp.statusText}`);
      }
      return resp.json();
    }

    // Register tools
    api.registerTool({
      name: "my_tool_get_data",
      label: "Get My Tool Data",
      description: "Fetch data from My Tool",
      parameters: Type.Object({
        query: Type.String({ description: "Search query" }),
        limit: Type.Optional(Type.Number({ default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        // Always check if configured
        if (!config.url || !config.token) {
          return {
            content: [{
              type: "text" as const,
              text: "My Tool connector not configured. Set MY_TOOL_URL and MY_TOOL_TOKEN in .env.",
            }],
          };
        }

        try {
          const results = await apiCall(`/api/v1/search?q=${encodeURIComponent(String(params.query))}&limit=${params.limit || 100}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{
              type: "text" as const,
              text: `My Tool error: ${err instanceof Error ? err.message : String(err)}`,
            }],
          };
        }
      },
    });
  },
};

export default plugin;
```

### 4. Add configuration to openkai.yaml

```yaml
plugins:
  entries:
    - id: connector-my-tool
      enabled: false  # Users enable when they configure credentials
      config:
        url: "${MY_TOOL_URL}"
        token: "${MY_TOOL_TOKEN}"
```

### 5. Add environment variables to .env.example

```bash
# My Tool
MY_TOOL_URL=
MY_TOOL_TOKEN=
```

## Connector Conventions

### Naming
- Plugin ID: `connector-<tool-name>` (kebab-case)
- Tool names: `<tool>_<action>` (snake_case, e.g., `splunk_search`)
- Package name: `@openkai/connector-<tool-name>`

### Authentication Patterns

| Pattern | Example | When to use |
|---------|---------|-------------|
| Bearer token | `Authorization: Bearer <token>` | Most REST APIs |
| API key header | `X-Api-Key: <key>` | Tenable, Nessus |
| Basic auth | `Authorization: Basic <base64>` | Jira, Qualys |
| OAuth2 client_credentials | Token exchange flow | CrowdStrike, Azure, Wiz |

For OAuth2, cache tokens and refresh before expiry:

```typescript
let accessToken: string | null = null;
let tokenExpiry = 0;

async function authenticate(): Promise<string> {
  if (accessToken && Date.now() < tokenExpiry) return accessToken;
  // ... token exchange ...
  accessToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000 - 60000; // 1min buffer
  return accessToken;
}
```

### Error Handling

1. Always check if the connector is configured before making API calls
2. Return helpful setup instructions when not configured
3. Wrap API calls in try/catch
4. Include the HTTP status code in error messages
5. Never expose raw credentials in error messages

### Tool Design

- Each tool should do **one thing well**
- Include clear parameter descriptions
- Use `Type.Optional()` for non-required parameters with sensible defaults
- Return structured data (JSON) that agents can parse
- For large result sets, support pagination via `limit`/`offset` parameters

## Testing

### Unit Tests

```typescript
import { describe, it, expect, vi } from "vitest";

describe("connector-my-tool", () => {
  it("returns setup message when not configured", async () => {
    // Test with empty config
  });

  it("makes correct API call", async () => {
    // Mock fetch and verify request format
  });
});
```

### Integration Tests

Run with `--live` flag against a real instance:

```bash
MY_TOOL_URL=https://... MY_TOOL_TOKEN=... vitest run --live
```

## Submitting Your Connector

1. Fork the OpenKai repository
2. Create your connector in `connectors/<name>/`
3. Add config entries to `config/openkai.yaml` (disabled by default)
4. Add env vars to `.env.example`
5. Test thoroughly
6. Submit a pull request with:
   - Description of what the connector integrates with
   - List of tools provided
   - Any setup prerequisites
