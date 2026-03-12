/**
 * OpenKai Snyk Connector
 *
 * Integrates with Snyk for software composition analysis (SCA) and project management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  token: Type.String({ description: "Snyk API token" }),
  orgId: Type.String({ description: "Snyk organization ID" }),
});

const plugin = {
  id: "connector-snyk",
  name: "OpenKai Snyk Connector",
  description: "Connect to Snyk for SCA vulnerability and project management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { token?: string; orgId?: string };

    async function snykApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const resp = await fetch(`https://api.snyk.io/rest${path}`, {
        method,
        headers: {
          Authorization: `token ${config.token}`,
          "Content-Type": "application/vnd.api+json",
          Accept: "application/vnd.api+json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`Snyk API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "snyk_get_issues",
      label: "Get Snyk Issues",
      description: "Fetch vulnerability issues from Snyk for the configured organization",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ description: "Filter by severity: low, medium, high, critical" })),
        type: Type.Optional(Type.String({ description: "Issue type: vuln, license, configuration" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.token || !config.orgId) {
          return {
            content: [{ type: "text" as const, text: "Snyk connector not configured. Set SNYK_TOKEN and SNYK_ORG_ID in .env." }],
          };
        }
        try {
          let queryParams = `?version=2024-01-23&limit=${params.limit || 100}`;
          if (params.severity) queryParams += `&severity=${encodeURIComponent(String(params.severity))}`;
          if (params.type) queryParams += `&type=${encodeURIComponent(String(params.type))}`;
          const results = await snykApi(`/orgs/${config.orgId}/issues${queryParams}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Snyk error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "snyk_get_projects",
      label: "Get Snyk Projects",
      description: "List projects monitored by Snyk in the configured organization",
      parameters: Type.Object({
        name: Type.Optional(Type.String({ description: "Filter projects by name" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.token || !config.orgId) {
          return {
            content: [{ type: "text" as const, text: "Snyk connector not configured." }],
          };
        }
        try {
          let queryParams = `?version=2024-01-23&limit=${params.limit || 100}`;
          if (params.name) queryParams += `&name=${encodeURIComponent(String(params.name))}`;
          const results = await snykApi(`/orgs/${config.orgId}/projects${queryParams}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Snyk error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
