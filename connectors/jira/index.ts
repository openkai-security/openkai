/**
 * OpenKai Jira Connector
 *
 * Integrates with Jira for issue creation, search, and management.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  url: Type.String({ description: "Jira instance URL (e.g., https://yourorg.atlassian.net)" }),
  email: Type.String({ description: "Jira account email" }),
  apiToken: Type.String({ description: "Jira API token" }),
  projectKey: Type.Optional(Type.String({ description: "Default Jira project key" })),
});

const plugin = {
  id: "connector-jira",
  name: "OpenKai Jira Connector",
  description: "Connect to Jira for issue creation, search, and management",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { url?: string; email?: string; apiToken?: string; projectKey?: string };

    async function jiraApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const resp = await fetch(`${config.url}/rest/api/3${path}`, {
        method,
        headers: {
          Authorization: `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString("base64")}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`Jira API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "jira_create_issue",
      label: "Create Jira Issue",
      description: "Create a new issue in Jira (e.g., a security finding ticket)",
      parameters: Type.Object({
        summary: Type.String({ description: "Issue summary/title" }),
        description: Type.Optional(Type.String({ description: "Issue description (plain text)" })),
        issueType: Type.Optional(Type.String({ description: "Issue type: Bug, Task, Story, etc.", default: "Bug" })),
        priority: Type.Optional(Type.String({ description: "Priority: Highest, High, Medium, Low, Lowest", default: "Medium" })),
        projectKey: Type.Optional(Type.String({ description: "Project key (overrides default)" })),
        labels: Type.Optional(Type.Array(Type.String(), { description: "Labels to apply" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.email || !config.apiToken) {
          return {
            content: [{ type: "text" as const, text: "Jira connector not configured. Set JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN in .env." }],
          };
        }
        try {
          const project = params.projectKey || config.projectKey;
          if (!project) {
            return {
              content: [{ type: "text" as const, text: "No project key specified. Provide projectKey parameter or set JIRA_PROJECT_KEY." }],
            };
          }
          const issueData: Record<string, unknown> = {
            fields: {
              project: { key: String(project) },
              summary: String(params.summary),
              issuetype: { name: String(params.issueType || "Bug") },
              priority: { name: String(params.priority || "Medium") },
              ...(params.description ? {
                description: {
                  type: "doc",
                  version: 1,
                  content: [{ type: "paragraph", content: [{ type: "text", text: String(params.description) }] }],
                },
              } : {}),
              ...(params.labels ? { labels: params.labels } : {}),
            },
          };
          const result = await jiraApi("/issue", "POST", issueData);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Jira create error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "jira_search_issues",
      label: "Search Jira Issues",
      description: "Search Jira issues using JQL (Jira Query Language)",
      parameters: Type.Object({
        jql: Type.String({ description: "JQL query (e.g., 'project = SEC AND status = Open')" }),
        maxResults: Type.Optional(Type.Number({ description: "Max results to return", default: 50 })),
        fields: Type.Optional(Type.String({ description: "Comma-separated fields to return", default: "summary,status,priority,assignee,created" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.email || !config.apiToken) {
          return {
            content: [{ type: "text" as const, text: "Jira connector not configured." }],
          };
        }
        try {
          const results = await jiraApi("/search", "POST", {
            jql: String(params.jql),
            maxResults: params.maxResults || 50,
            fields: String(params.fields || "summary,status,priority,assignee,created").split(","),
          });
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Jira search error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "jira_get_issue",
      label: "Get Jira Issue",
      description: "Fetch a specific Jira issue by key (e.g., SEC-123)",
      parameters: Type.Object({
        issueKey: Type.String({ description: "Jira issue key (e.g., SEC-123)" }),
        fields: Type.Optional(Type.String({ description: "Comma-separated fields to return" })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.url || !config.email || !config.apiToken) {
          return {
            content: [{ type: "text" as const, text: "Jira connector not configured." }],
          };
        }
        try {
          let path = `/issue/${encodeURIComponent(String(params.issueKey))}`;
          if (params.fields) path += `?fields=${encodeURIComponent(String(params.fields))}`;
          const result = await jiraApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Jira error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
