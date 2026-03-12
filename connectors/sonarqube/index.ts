/**
 * OpenKai SonarQube Connector
 *
 * Integrates with SonarQube for code quality issue and project management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "SonarQube server URL (e.g., https://sonarqube.example.com)" }),
  token: Type.String({ description: "SonarQube user token" }),
});

const plugin = {
  id: "connector-sonarqube",
  name: "OpenKai SonarQube Connector",
  description: "Connect to SonarQube for code quality issue and project management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; token?: string };

    async function sonarApi(path: string): Promise<unknown> {
      const resp = await fetch(`${config.url}${path}`, {
        headers: {
          Authorization: `Basic ${Buffer.from(`${config.token}:`).toString("base64")}`,
          Accept: "application/json",
        },
      });
      if (!resp.ok) throw new Error(`SonarQube API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "sonarqube_get_issues",
      label: "Get SonarQube Issues",
      description: "Fetch code quality and security issues from SonarQube",
      parameters: Type.Object({
        projectKey: Type.Optional(Type.String({ description: "Project key to filter issues" })),
        severities: Type.Optional(Type.String({ description: "Comma-separated severities: INFO, MINOR, MAJOR, CRITICAL, BLOCKER", default: "CRITICAL,BLOCKER" })),
        types: Type.Optional(Type.String({ description: "Comma-separated types: CODE_SMELL, BUG, VULNERABILITY, SECURITY_HOTSPOT" })),
        limit: Type.Optional(Type.Number({ description: "Max results (page size)", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.token) {
          return {
            content: [{ type: "text" as const, text: "SonarQube connector not configured. Set SONARQUBE_URL and SONARQUBE_TOKEN in .env." }],
          };
        }
        try {
          const queryParts: string[] = [`ps=${params.limit || 100}`];
          if (params.projectKey) queryParts.push(`componentKeys=${encodeURIComponent(String(params.projectKey))}`);
          if (params.severities) queryParts.push(`severities=${encodeURIComponent(String(params.severities))}`);
          if (params.types) queryParts.push(`types=${encodeURIComponent(String(params.types))}`);
          const results = await sonarApi(`/api/issues/search?${queryParts.join("&")}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `SonarQube error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "sonarqube_get_projects",
      label: "Get SonarQube Projects",
      description: "List projects monitored by SonarQube",
      parameters: Type.Object({
        query: Type.Optional(Type.String({ description: "Search query to filter projects by name" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.token) {
          return {
            content: [{ type: "text" as const, text: "SonarQube connector not configured." }],
          };
        }
        try {
          const queryParts: string[] = [`ps=${params.limit || 100}`];
          if (params.query) queryParts.push(`q=${encodeURIComponent(String(params.query))}`);
          const results = await sonarApi(`/api/projects/search?${queryParts.join("&")}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `SonarQube error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
