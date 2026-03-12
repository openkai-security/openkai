/**
 * OpenKai ServiceNow Connector
 *
 * Integrates with ServiceNow for incident creation and table search.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  instance: Type.String({ description: "ServiceNow instance name (e.g., 'yourorg' for yourorg.service-now.com)" }),
  username: Type.String({ description: "ServiceNow username" }),
  password: Type.String({ description: "ServiceNow password" }),
});

const plugin = {
  id: "connector-servicenow",
  name: "OpenKai ServiceNow Connector",
  description: "Connect to ServiceNow for incident creation and search",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { instance?: string; username?: string; password?: string };

    async function snowApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const baseUrl = `https://${config.instance}.service-now.com`;
      const resp = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`ServiceNow API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "servicenow_create_incident",
      label: "Create ServiceNow Incident",
      description: "Create a new incident in ServiceNow (e.g., for a security finding)",
      parameters: Type.Object({
        short_description: Type.String({ description: "Incident short description" }),
        description: Type.Optional(Type.String({ description: "Detailed description" })),
        urgency: Type.Optional(Type.String({ description: "Urgency: 1 (High), 2 (Medium), 3 (Low)", default: "2" })),
        impact: Type.Optional(Type.String({ description: "Impact: 1 (High), 2 (Medium), 3 (Low)", default: "2" })),
        category: Type.Optional(Type.String({ description: "Incident category (e.g., 'Security')" })),
        assignment_group: Type.Optional(Type.String({ description: "Assignment group name or sys_id" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.instance || !config.username || !config.password) {
          return {
            content: [{ type: "text" as const, text: "ServiceNow connector not configured. Set SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD in .env." }],
          };
        }
        try {
          const incidentData: Record<string, unknown> = {
            short_description: String(params.short_description),
            urgency: String(params.urgency || "2"),
            impact: String(params.impact || "2"),
          };
          if (params.description) incidentData.description = String(params.description);
          if (params.category) incidentData.category = String(params.category);
          if (params.assignment_group) incidentData.assignment_group = String(params.assignment_group);
          const result = await snowApi("/api/now/table/incident", "POST", incidentData);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `ServiceNow create error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "servicenow_search",
      label: "Search ServiceNow",
      description: "Search ServiceNow tables using encoded query syntax",
      parameters: Type.Object({
        table: Type.Optional(Type.String({ description: "Table to search (e.g., 'incident', 'cmdb_ci')", default: "incident" })),
        query: Type.String({ description: "Encoded query string (e.g., 'priority=1^state=1')" }),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 50 })),
        fields: Type.Optional(Type.String({ description: "Comma-separated fields to return" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.instance || !config.username || !config.password) {
          return {
            content: [{ type: "text" as const, text: "ServiceNow connector not configured." }],
          };
        }
        try {
          const table = params.table || "incident";
          const limit = params.limit || 50;
          let path = `/api/now/table/${table}?sysparm_query=${encodeURIComponent(String(params.query))}&sysparm_limit=${limit}`;
          if (params.fields) path += `&sysparm_fields=${encodeURIComponent(String(params.fields))}`;
          const results = await snowApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `ServiceNow search error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
