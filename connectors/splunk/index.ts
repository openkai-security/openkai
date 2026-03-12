/**
 * OpenKai Splunk Connector
 *
 * Integrates with Splunk for log search, alert management, and detection rule deployment.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "Splunk management URL (e.g., https://splunk.example.com:8089)" }),
  token: Type.String({ description: "Splunk HEC or API token" }),
  index: Type.Optional(Type.String({ description: "Default search index", default: "main" })),
});

const plugin = {
  id: "connector-splunk",
  name: "OpenKai Splunk Connector",
  description: "Connect to Splunk for log search, alert management, and detection rule deployment",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; token?: string; index?: string };

    async function splunkSearch(query: string, earliest: string = "-24h", latest: string = "now"): Promise<unknown> {
      const url = `${config.url}/services/search/jobs`;
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.token}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          search: `search index=${config.index || "main"} ${query}`,
          earliest_time: earliest,
          latest_time: latest,
          output_mode: "json",
          exec_mode: "oneshot",
          count: "100",
        }),
      });
      if (!resp.ok) {
        throw new Error(`Splunk API error: ${resp.status} ${resp.statusText}`);
      }
      return resp.json();
    }

    // Search logs
    api.registerTool({
      name: "splunk_search",
      label: "Splunk Search",
      description: "Execute a search query against Splunk and return results",
      parameters: Type.Object({
        query: Type.String({ description: "SPL search query (without 'search' prefix)" }),
        earliest: Type.Optional(Type.String({ description: "Earliest time (e.g., '-24h', '-7d')", default: "-24h" })),
        latest: Type.Optional(Type.String({ description: "Latest time (e.g., 'now')", default: "now" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.token) {
          return {
            content: [{ type: "text" as const, text: "Splunk connector not configured. Set SPLUNK_URL and SPLUNK_TOKEN in .env." }],
          };
        }
        try {
          const results = await splunkSearch(
            String(params.query),
            String(params.earliest || "-24h"),
            String(params.latest || "now")
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Splunk search error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    // Get log volume stats
    api.registerTool({
      name: "splunk_log_stats",
      label: "Splunk Log Statistics",
      description: "Get log volume and source statistics from Splunk for pipeline analysis",
      parameters: Type.Object({
        time_range: Type.Optional(Type.String({ description: "Time range for stats (e.g., '-7d')", default: "-7d" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.token) {
          return {
            content: [{ type: "text" as const, text: "Splunk connector not configured." }],
          };
        }
        try {
          const results = await splunkSearch(
            "| tstats count where index=* by index, sourcetype | sort -count",
            String(params.time_range || "-7d"),
            "now"
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Splunk stats error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    // Deploy detection rule
    api.registerTool({
      name: "splunk_deploy_rule",
      label: "Deploy Splunk Detection Rule",
      description: "Deploy a SPL detection rule as a saved search / correlation search in Splunk",
      parameters: Type.Object({
        name: Type.String({ description: "Rule/saved search name" }),
        spl_query: Type.String({ description: "SPL query for the detection rule" }),
        cron_schedule: Type.Optional(Type.String({ description: "Cron schedule (e.g., '*/5 * * * *')", default: "*/15 * * * *" })),
        severity: Type.Optional(Type.String({ description: "Alert severity", enum: ["critical", "high", "medium", "low", "info"], default: "medium" })),
        description: Type.Optional(Type.String({ description: "Rule description" })),
        dry_run: Type.Optional(Type.Boolean({ description: "If true, validate but don't deploy", default: true })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.token) {
          return {
            content: [{ type: "text" as const, text: "Splunk connector not configured." }],
          };
        }

        if (params.dry_run !== false) {
          return {
            content: [{
              type: "text" as const,
              text: [
                `## Detection Rule (Dry Run)`,
                ``,
                `**Name:** ${params.name}`,
                `**Schedule:** ${params.cron_schedule || "*/15 * * * *"}`,
                `**Severity:** ${params.severity || "medium"}`,
                `**Description:** ${params.description || "N/A"}`,
                ``,
                `### SPL Query`,
                "```spl",
                String(params.spl_query),
                "```",
                ``,
                `_Dry run mode — set dry_run=false to deploy._`,
              ].join("\n"),
            }],
          };
        }

        try {
          const url = `${config.url}/servicesNS/admin/search/saved/searches`;
          const resp = await fetch(url, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${config.token}`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              name: String(params.name),
              search: String(params.spl_query),
              "alert.severity": String(params.severity === "critical" ? 5 : params.severity === "high" ? 4 : params.severity === "medium" ? 3 : params.severity === "low" ? 2 : 1),
              "cron_schedule": String(params.cron_schedule || "*/15 * * * *"),
              "description": String(params.description || ""),
              "is_scheduled": "1",
              "alert_type": "number of events",
              "alert_comparator": "greater than",
              "alert_threshold": "0",
              output_mode: "json",
            }),
          });
          if (!resp.ok) {
            throw new Error(`Deploy failed: ${resp.status} ${resp.statusText}`);
          }
          return {
            content: [{ type: "text" as const, text: `Detection rule "${params.name}" deployed successfully to Splunk.` }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Deploy error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
