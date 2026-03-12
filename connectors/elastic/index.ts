/**
 * OpenKai Elasticsearch Connector
 *
 * Integrates with Elasticsearch/Kibana for log search and security analytics.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "Elasticsearch URL (e.g., https://elastic.example.com:9200)" }),
  apiKey: Type.String({ description: "Elasticsearch API key" }),
  index: Type.Optional(Type.String({ description: "Default search index pattern", default: "security-*" })),
});

const plugin = {
  id: "connector-elastic",
  name: "OpenKai Elasticsearch Connector",
  description: "Connect to Elasticsearch/Kibana for log search and security analytics",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; apiKey?: string; index?: string };

    async function esSearch(body: Record<string, unknown>, index?: string): Promise<unknown> {
      const idx = index || config.index || "security-*";
      const resp = await fetch(`${config.url}/${idx}/_search`, {
        method: "POST",
        headers: {
          Authorization: `ApiKey ${config.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        throw new Error(`Elasticsearch error: ${resp.status} ${resp.statusText}`);
      }
      return resp.json();
    }

    api.registerTool({
      name: "elastic_search",
      label: "Elasticsearch Search",
      description: "Execute a search query against Elasticsearch and return results",
      parameters: Type.Object({
        query: Type.String({ description: "Elasticsearch query (Lucene syntax or JSON DSL)" }),
        index: Type.Optional(Type.String({ description: "Index pattern to search" })),
        time_range: Type.Optional(Type.String({ description: "Time range (e.g., 'now-24h')", default: "now-24h" })),
        size: Type.Optional(Type.Number({ description: "Max results to return", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Elasticsearch connector not configured. Set ELASTIC_URL and ELASTIC_API_KEY in .env." }],
          };
        }
        try {
          const body: Record<string, unknown> = {
            size: params.size || 100,
            query: {
              bool: {
                must: [
                  { query_string: { query: String(params.query) } },
                ],
                filter: [
                  { range: { "@timestamp": { gte: String(params.time_range || "now-24h"), lte: "now" } } },
                ],
              },
            },
            sort: [{ "@timestamp": { order: "desc" } }],
          };
          const results = await esSearch(body, params.index as string | undefined);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Elasticsearch error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "elastic_log_stats",
      label: "Elasticsearch Log Statistics",
      description: "Get log volume statistics by index and data stream",
      parameters: Type.Object({
        time_range: Type.Optional(Type.String({ description: "Time range", default: "now-7d" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "Elasticsearch connector not configured." }],
          };
        }
        try {
          const resp = await fetch(`${config.url}/_cat/indices?format=json&bytes=gb&s=store.size:desc`, {
            headers: { Authorization: `ApiKey ${config.apiKey}` },
          });
          if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
          const indices = await resp.json();
          return {
            content: [{ type: "text" as const, text: JSON.stringify(indices, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
