/**
 * OpenKai CrowdStrike Connector
 *
 * Integrates with CrowdStrike Falcon for endpoint detection and response.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  clientId: Type.String({ description: "CrowdStrike API client ID" }),
  clientSecret: Type.String({ description: "CrowdStrike API client secret" }),
  baseUrl: Type.Optional(Type.String({ description: "CrowdStrike API base URL", default: "https://api.crowdstrike.com" })),
});

const plugin = {
  id: "connector-crowdstrike",
  name: "OpenKai CrowdStrike Connector",
  description: "Connect to CrowdStrike Falcon for endpoint detection and response",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { clientId?: string; clientSecret?: string; baseUrl?: string };
    let accessToken: string | null = null;
    let tokenExpiry = 0;

    async function authenticate(): Promise<string> {
      if (accessToken && Date.now() < tokenExpiry) return accessToken;

      const resp = await fetch(`${config.baseUrl || "https://api.crowdstrike.com"}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: config.clientId || "",
          client_secret: config.clientSecret || "",
        }),
      });
      if (!resp.ok) throw new Error(`CrowdStrike auth failed: ${resp.status}`);
      const data = (await resp.json()) as { access_token: string; expires_in: number };
      accessToken = data.access_token;
      tokenExpiry = Date.now() + data.expires_in * 1000 - 60000;
      return accessToken;
    }

    async function csApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const token = await authenticate();
      const resp = await fetch(`${config.baseUrl || "https://api.crowdstrike.com"}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`CrowdStrike API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "crowdstrike_query_detections",
      label: "Query CrowdStrike Detections",
      description: "Query recent detections from CrowdStrike Falcon",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "FQL filter query (e.g., 'severity:>=4+last_behavior:>2024-01-01')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 50 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const filter = params.filter ? `&filter=${encodeURIComponent(String(params.filter))}` : "";
          const results = await csApi(`/detects/queries/detects/v1?limit=${params.limit || 50}${filter}`);
          return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });

    api.registerTool({
      name: "crowdstrike_query_hosts",
      label: "Query CrowdStrike Hosts",
      description: "Query host/endpoint information from CrowdStrike Falcon",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "FQL filter (e.g., 'platform_name:Windows')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const filter = params.filter ? `&filter=${encodeURIComponent(String(params.filter))}` : "";
          const results = await csApi(`/devices/queries/devices-scroll/v1?limit=${params.limit || 100}${filter}`);
          return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });

    api.registerTool({
      name: "crowdstrike_query_vulnerabilities",
      label: "Query CrowdStrike Vulnerabilities",
      description: "Query Spotlight vulnerability data from CrowdStrike",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "FQL filter (e.g., 'cve.severity:CRITICAL')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const filter = params.filter ? `&filter=${encodeURIComponent(String(params.filter))}` : "";
          const results = await csApi(`/spotlight/queries/vulnerabilities/v1?limit=${params.limit || 100}${filter}`);
          return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });
  },
};

export default plugin;
