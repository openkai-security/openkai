/**
 * OpenKai Orca Security Connector
 *
 * Integrates with Orca Security for cloud security alerts and asset inventory.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  apiKey: Type.String({ description: "Orca Security API key" }),
  apiUrl: Type.Optional(Type.String({ description: "Orca API base URL", default: "https://api.orcasecurity.io" })),
});

const plugin = {
  id: "connector-orca",
  name: "OpenKai Orca Security Connector",
  description: "Connect to Orca Security for cloud security alerts and asset inventory",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { apiKey?: string; apiUrl?: string };

    async function orcaApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const baseUrl = config.apiUrl || "https://api.orcasecurity.io";
      const resp = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Token ${config.apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`Orca API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "orca_get_alerts",
      label: "Get Orca Alerts",
      description: "Fetch security alerts from Orca Security",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ description: "Filter by severity: informational, low, medium, high, critical" })),
        status: Type.Optional(Type.String({ description: "Filter by status: open, in_progress, closed", default: "open" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Orca connector not configured. Set ORCA_API_KEY in .env." }],
          };
        }
        try {
          const queryParams: string[] = [`limit=${params.limit || 100}`];
          if (params.severity) queryParams.push(`severity=${encodeURIComponent(String(params.severity))}`);
          if (params.status) queryParams.push(`status=${encodeURIComponent(String(params.status))}`);
          const results = await orcaApi(`/api/alerts?${queryParams.join("&")}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Orca error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "orca_get_assets",
      label: "Get Orca Assets",
      description: "Retrieve cloud asset inventory from Orca Security",
      parameters: Type.Object({
        type: Type.Optional(Type.String({ description: "Asset type filter (e.g., 'vm', 'container', 'storage')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Orca connector not configured." }],
          };
        }
        try {
          const queryParams: string[] = [`limit=${params.limit || 100}`];
          if (params.type) queryParams.push(`type=${encodeURIComponent(String(params.type))}`);
          const results = await orcaApi(`/api/assets?${queryParams.join("&")}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Orca error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
