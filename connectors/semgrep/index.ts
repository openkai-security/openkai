/**
 * OpenKai Semgrep Connector
 *
 * Integrates with Semgrep App for SAST findings and project management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  appToken: Type.String({ description: "Semgrep App API token" }),
});

const plugin = {
  id: "connector-semgrep",
  name: "OpenKai Semgrep Connector",
  description: "Connect to Semgrep App for SAST findings and project management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { appToken?: string };

    async function semgrepApi(path: string): Promise<unknown> {
      const resp = await fetch(`https://semgrep.dev/api/v1${path}`, {
        headers: {
          Authorization: `Bearer ${config.appToken}`,
          Accept: "application/json",
        },
      });
      if (!resp.ok) throw new Error(`Semgrep API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "semgrep_get_findings",
      label: "Get Semgrep Findings",
      description: "Fetch SAST findings from Semgrep App",
      parameters: Type.Object({
        repo: Type.Optional(Type.String({ description: "Filter by repository name" })),
        severity: Type.Optional(Type.String({ description: "Filter by severity: info, warning, error" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.appToken) {
          return {
            content: [{ type: "text" as const, text: "Semgrep connector not configured. Set SEMGREP_APP_TOKEN in .env." }],
          };
        }
        try {
          const queryParams: string[] = [`page_size=${params.limit || 100}`];
          if (params.repo) queryParams.push(`repos=${encodeURIComponent(String(params.repo))}`);
          if (params.severity) queryParams.push(`severity=${encodeURIComponent(String(params.severity))}`);
          const results = await semgrepApi(`/findings?${queryParams.join("&")}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Semgrep error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "semgrep_get_projects",
      label: "Get Semgrep Projects",
      description: "List projects (repositories) monitored by Semgrep App",
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.appToken) {
          return {
            content: [{ type: "text" as const, text: "Semgrep connector not configured." }],
          };
        }
        try {
          const results = await semgrepApi(`/deployments/current/repos?page_size=${params.limit || 100}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Semgrep error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
