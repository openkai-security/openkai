/**
 * OpenKai Qualys Connector
 *
 * Integrates with Qualys for vulnerability scanning and assessment data.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "Qualys API URL" }),
  username: Type.String({ description: "Qualys API username" }),
  password: Type.String({ description: "Qualys API password" }),
});

const plugin = {
  id: "connector-qualys",
  name: "OpenKai Qualys Connector",
  description: "Connect to Qualys for vulnerability scanning and assessment data",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; username?: string; password?: string };

    async function qualysApi(path: string): Promise<unknown> {
      const resp = await fetch(`${config.url}${path}`, {
        headers: {
          "X-Requested-With": "OpenKai",
          Authorization: `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`,
        },
      });
      if (!resp.ok) throw new Error(`Qualys API error: ${resp.status}`);
      return resp.json();
    }

    api.registerTool({
      name: "qualys_get_vulns",
      label: "Get Qualys Vulnerabilities",
      description: "Fetch vulnerability scan results from Qualys",
      parameters: Type.Object({
        severity: Type.Optional(Type.String({ description: "Filter by severity: 1-5 or comma-separated", default: "4,5" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 200 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.username) {
          return { content: [{ type: "text" as const, text: "Qualys connector not configured. Set QUALYS_URL, QUALYS_USERNAME, QUALYS_PASSWORD." }] };
        }
        try {
          const results = await qualysApi(`/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&severities=${params.severity || "4,5"}`);
          return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `Qualys error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });

    api.registerTool({
      name: "qualys_get_hosts",
      label: "Get Qualys Host Assets",
      description: "Fetch discovered host assets from Qualys",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "Host filter criteria" })),
      }),
      async execute(_id, _params: Record<string, unknown>) {
        if (!config.url || !config.username) {
          return { content: [{ type: "text" as const, text: "Qualys connector not configured." }] };
        }
        try {
          const results = await qualysApi("/api/2.0/fo/asset/host/?action=list&details=All&truncation_limit=100");
          return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `Qualys error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });
  },
};

export default plugin;
