/**
 * OpenKai Microsoft Sentinel Connector
 *
 * Integrates with Microsoft Sentinel for KQL log search and incident management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  workspaceId: Type.String({ description: "Log Analytics workspace ID" }),
  tenantId: Type.String({ description: "Azure AD tenant ID" }),
  clientId: Type.String({ description: "Azure AD app client ID" }),
  clientSecret: Type.String({ description: "Azure AD app client secret" }),
});

const plugin = {
  id: "connector-sentinel",
  name: "OpenKai Microsoft Sentinel Connector",
  description: "Connect to Microsoft Sentinel for KQL search and incident management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { workspaceId?: string; tenantId?: string; clientId?: string; clientSecret?: string };
    let accessToken: string | null = null;
    let tokenExpiry = 0;

    async function authenticate(): Promise<string> {
      if (accessToken && Date.now() < tokenExpiry) return accessToken;

      const resp = await fetch(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: config.clientId || "",
          client_secret: config.clientSecret || "",
          scope: "https://api.loganalytics.io/.default",
          grant_type: "client_credentials",
        }),
      });
      if (!resp.ok) throw new Error(`Sentinel auth failed: ${resp.status}`);
      const data = (await resp.json()) as { access_token: string; expires_in: number };
      accessToken = data.access_token;
      tokenExpiry = Date.now() + data.expires_in * 1000 - 60000;
      return accessToken;
    }

    api.registerTool({
      name: "sentinel_search",
      label: "Sentinel KQL Search",
      description: "Execute a KQL query against Microsoft Sentinel / Log Analytics workspace",
      parameters: Type.Object({
        query: Type.String({ description: "KQL query to execute" }),
        timespan: Type.Optional(Type.String({ description: "ISO 8601 duration (e.g., 'PT24H', 'P7D')", default: "PT24H" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.workspaceId || !config.clientId || !config.clientSecret) {
          return {
            content: [{ type: "text" as const, text: "Sentinel connector not configured. Set SENTINEL_WORKSPACE_ID, SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID, and SENTINEL_CLIENT_SECRET in .env." }],
          };
        }
        try {
          const token = await authenticate();
          const resp = await fetch(`https://api.loganalytics.io/v1/workspaces/${config.workspaceId}/query`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              query: String(params.query),
              timespan: String(params.timespan || "PT24H"),
            }),
          });
          if (!resp.ok) throw new Error(`Sentinel query error: ${resp.status} ${resp.statusText}`);
          const results = await resp.json();
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Sentinel search error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "sentinel_incidents",
      label: "Get Sentinel Incidents",
      description: "Fetch security incidents from Microsoft Sentinel",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "OData filter (e.g., \"properties/severity eq 'High'\")" })),
        top: Type.Optional(Type.Number({ description: "Max incidents to return", default: 50 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.workspaceId || !config.clientId || !config.clientSecret) {
          return {
            content: [{ type: "text" as const, text: "Sentinel connector not configured." }],
          };
        }
        try {
          const token = await authenticate();
          const subscriptionResp = await fetch("https://management.azure.com/subscriptions?api-version=2020-01-01", {
            headers: { Authorization: `Bearer ${token}` },
          });
          let filterParam = params.filter ? `&$filter=${encodeURIComponent(String(params.filter))}` : "";
          const top = params.top || 50;
          const resp = await fetch(
            `https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.workspaceId}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-11-01&$top=${top}${filterParam}`,
            {
              headers: { Authorization: `Bearer ${token}` },
            }
          );
          if (!resp.ok) throw new Error(`Sentinel incidents error: ${resp.status} ${resp.statusText}`);
          const results = await resp.json();
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Sentinel incidents error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
