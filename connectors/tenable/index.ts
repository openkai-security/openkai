/**
 * OpenKai Tenable.io Connector
 *
 * Integrates with Tenable.io for vulnerability and asset management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  accessKey: Type.String({ description: "Tenable.io API access key" }),
  secretKey: Type.String({ description: "Tenable.io API secret key" }),
  url: Type.Optional(Type.String({ description: "Tenable.io API URL", default: "https://cloud.tenable.com" })),
});

const plugin = {
  id: "connector-tenable",
  name: "OpenKai Tenable.io Connector",
  description: "Connect to Tenable.io for vulnerability and asset management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { accessKey?: string; secretKey?: string; url?: string };

    async function tenableApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const baseUrl = config.url || "https://cloud.tenable.com";
      const resp = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          "X-ApiKeys": `accessKey=${config.accessKey};secretKey=${config.secretKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`Tenable API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "tenable_get_vulns",
      label: "Get Tenable Vulnerabilities",
      description: "Export and retrieve vulnerability findings from Tenable.io",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ description: "Filter by severity: info, low, medium, high, critical", default: "high,critical" })),
        limit: Type.Optional(Type.Number({ description: "Max results to return", default: 200 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.accessKey || !config.secretKey) {
          return {
            content: [{ type: "text" as const, text: "Tenable connector not configured. Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env." }],
          };
        }
        try {
          const filters: Record<string, unknown>[] = [];
          if (params.severity) {
            filters.push({
              type: "vuln",
              quality: "eq",
              field: "severity",
              value: String(params.severity),
            });
          }
          const results = await tenableApi("/vulns/export", "POST", {
            filters,
            num_assets: params.limit || 200,
          });
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Tenable error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "tenable_get_assets",
      label: "Get Tenable Assets",
      description: "Retrieve discovered assets from Tenable.io",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "Asset filter (e.g., hostname, IP)" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 200 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.accessKey || !config.secretKey) {
          return {
            content: [{ type: "text" as const, text: "Tenable connector not configured." }],
          };
        }
        try {
          const results = await tenableApi("/assets/export", "POST", {
            chunk_size: params.limit || 200,
          });
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Tenable error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
