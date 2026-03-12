/**
 * OpenKai Wiz Connector
 *
 * Integrates with Wiz for cloud security issue and inventory management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  clientId: Type.String({ description: "Wiz service account client ID" }),
  clientSecret: Type.String({ description: "Wiz service account client secret" }),
  apiUrl: Type.Optional(Type.String({ description: "Wiz API endpoint URL", default: "https://api.us20.app.wiz.io/graphql" })),
});

const plugin = {
  id: "connector-wiz",
  name: "OpenKai Wiz Connector",
  description: "Connect to Wiz for cloud security issue and inventory management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { clientId?: string; clientSecret?: string; apiUrl?: string };
    let accessToken: string | null = null;
    let tokenExpiry = 0;

    async function authenticate(): Promise<string> {
      if (accessToken && Date.now() < tokenExpiry) return accessToken;

      const resp = await fetch("https://auth.app.wiz.io/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: config.clientId || "",
          client_secret: config.clientSecret || "",
          audience: "wiz-api",
        }),
      });
      if (!resp.ok) throw new Error(`Wiz auth failed: ${resp.status}`);
      const data = (await resp.json()) as { access_token: string; expires_in: number };
      accessToken = data.access_token;
      tokenExpiry = Date.now() + data.expires_in * 1000 - 60000;
      return accessToken;
    }

    async function wizGraphQL(query: string, variables?: Record<string, unknown>): Promise<unknown> {
      const token = await authenticate();
      const apiUrl = config.apiUrl || "https://api.us20.app.wiz.io/graphql";
      const resp = await fetch(apiUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query, variables }),
      });
      if (!resp.ok) throw new Error(`Wiz API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "wiz_get_issues",
      label: "Get Wiz Issues",
      description: "Fetch cloud security issues from Wiz",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ description: "Filter by severity: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL" })),
        status: Type.Optional(Type.String({ description: "Filter by status: OPEN, IN_PROGRESS, RESOLVED, REJECTED", default: "OPEN" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return {
            content: [{ type: "text" as const, text: "Wiz connector not configured. Set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET in .env." }],
          };
        }
        try {
          const filterParts: string[] = [];
          if (params.severity) filterParts.push(`severity: [${String(params.severity)}]`);
          if (params.status) filterParts.push(`status: [${String(params.status)}]`);
          const filterStr = filterParts.length > 0 ? `filterBy: { ${filterParts.join(", ")} }` : "";
          const query = `query {
            issues(first: ${params.limit || 100}, ${filterStr}) {
              nodes {
                id
                severity
                status
                title
                description
                createdAt
                resource { id name type }
              }
            }
          }`;
          const results = await wizGraphQL(query);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Wiz error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "wiz_get_inventory",
      label: "Get Wiz Inventory",
      description: "Query cloud resource inventory from Wiz",
      parameters: Type.Object({
        type: Type.Optional(Type.String({ description: "Resource type filter (e.g., 'virtualMachine', 'container', 'bucket')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return {
            content: [{ type: "text" as const, text: "Wiz connector not configured." }],
          };
        }
        try {
          const typeFilter = params.type ? `filterBy: { type: ["${String(params.type)}"] }` : "";
          const query = `query {
            graphSearch(first: ${params.limit || 100}, query: { type: ["CLOUD_RESOURCE"], ${typeFilter} }) {
              nodes {
                entities {
                  id
                  name
                  type
                  properties
                }
              }
            }
          }`;
          const results = await wizGraphQL(query);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Wiz error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
