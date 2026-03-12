/**
 * OpenKai Nessus Connector
 *
 * Integrates with a local Nessus scanner for scan and vulnerability retrieval.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "Nessus scanner URL (e.g., https://localhost:8834)" }),
  apiKey: Type.String({ description: "Nessus API key (X-ApiKeys format: accessKey=...;secretKey=...)" }),
});

const plugin = {
  id: "connector-nessus",
  name: "OpenKai Nessus Connector",
  description: "Connect to a local Nessus scanner for scan and vulnerability retrieval",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; apiKey?: string };

    async function nessusApi(path: string): Promise<unknown> {
      const resp = await fetch(`${config.url}${path}`, {
        headers: {
          "X-ApiKeys": config.apiKey || "",
          Accept: "application/json",
        },
      });
      if (!resp.ok) throw new Error(`Nessus API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "nessus_get_scans",
      label: "Get Nessus Scans",
      description: "List scans from the local Nessus scanner",
      parameters: Type.Object({
        folder_id: Type.Optional(Type.Number({ description: "Filter by folder ID" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Nessus connector not configured. Set NESSUS_URL and NESSUS_API_KEY in .env." }],
          };
        }
        try {
          let path = "/scans";
          if (params.folder_id) path += `?folder_id=${params.folder_id}`;
          const results = await nessusApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Nessus error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "nessus_get_vulnerabilities",
      label: "Get Nessus Vulnerabilities",
      description: "Get vulnerability details from a specific Nessus scan",
      parameters: Type.Object({
        scan_id: Type.Number({ description: "Scan ID to retrieve vulnerabilities from" }),
        severity: Type.Optional(Type.String({ description: "Min severity filter: info, low, medium, high, critical" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Nessus connector not configured." }],
          };
        }
        try {
          const results = await nessusApi(`/scans/${params.scan_id}`);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Nessus error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
