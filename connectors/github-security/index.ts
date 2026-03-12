/**
 * OpenKai GitHub Advanced Security Connector
 *
 * Integrates with GitHub Advanced Security for code scanning, Dependabot, and secret scanning alerts.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  token: Type.String({ description: "GitHub personal access token or app token with security_events scope" }),
  org: Type.String({ description: "GitHub organization name" }),
});

const plugin = {
  id: "connector-github-security",
  name: "OpenKai GitHub Advanced Security Connector",
  description: "Connect to GitHub Advanced Security for code scanning, Dependabot, and secret scanning alerts",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { token?: string; org?: string };

    async function ghApi(path: string): Promise<unknown> {
      const resp = await fetch(`https://api.github.com${path}`, {
        headers: {
          Authorization: `Bearer ${config.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
      if (!resp.ok) throw new Error(`GitHub API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "github_code_scanning_alerts",
      label: "GitHub Code Scanning Alerts",
      description: "Fetch code scanning (CodeQL/SAST) alerts for a GitHub organization or repository",
      parameters: Type.Object({
        repo: Type.Optional(Type.String({ description: "Repository name (if omitted, fetches org-level alerts)" })),
        state: Type.Optional(Type.String({ description: "Alert state: open, closed, dismissed, fixed", default: "open" })),
        severity: Type.Optional(Type.String({ description: "Filter by severity: critical, high, medium, low, warning, note, error" })),
        limit: Type.Optional(Type.Number({ description: "Max results per page", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.token || !config.org) {
          return {
            content: [{ type: "text" as const, text: "GitHub Security connector not configured. Set GITHUB_TOKEN and GITHUB_ORG in .env." }],
          };
        }
        try {
          const state = params.state || "open";
          const perPage = params.limit || 100;
          let path: string;
          if (params.repo) {
            path = `/repos/${config.org}/${params.repo}/code-scanning/alerts?state=${state}&per_page=${perPage}`;
          } else {
            path = `/orgs/${config.org}/code-scanning/alerts?state=${state}&per_page=${perPage}`;
          }
          if (params.severity) path += `&severity=${encodeURIComponent(String(params.severity))}`;
          const results = await ghApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `GitHub code scanning error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "github_dependabot_alerts",
      label: "GitHub Dependabot Alerts",
      description: "Fetch Dependabot vulnerability alerts for a GitHub organization or repository",
      parameters: Type.Object({
        repo: Type.Optional(Type.String({ description: "Repository name (if omitted, fetches org-level alerts)" })),
        state: Type.Optional(Type.String({ description: "Alert state: auto_dismissed, dismissed, fixed, open", default: "open" })),
        severity: Type.Optional(Type.String({ description: "Filter by severity: low, medium, high, critical" })),
        limit: Type.Optional(Type.Number({ description: "Max results per page", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.token || !config.org) {
          return {
            content: [{ type: "text" as const, text: "GitHub Security connector not configured." }],
          };
        }
        try {
          const state = params.state || "open";
          const perPage = params.limit || 100;
          let path: string;
          if (params.repo) {
            path = `/repos/${config.org}/${params.repo}/dependabot/alerts?state=${state}&per_page=${perPage}`;
          } else {
            path = `/orgs/${config.org}/dependabot/alerts?state=${state}&per_page=${perPage}`;
          }
          if (params.severity) path += `&severity=${encodeURIComponent(String(params.severity))}`;
          const results = await ghApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `GitHub Dependabot error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "github_secret_scanning_alerts",
      label: "GitHub Secret Scanning Alerts",
      description: "Fetch secret scanning alerts for a GitHub organization or repository",
      parameters: Type.Object({
        repo: Type.Optional(Type.String({ description: "Repository name (if omitted, fetches org-level alerts)" })),
        state: Type.Optional(Type.String({ description: "Alert state: open, resolved", default: "open" })),
        limit: Type.Optional(Type.Number({ description: "Max results per page", default: 100 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.token || !config.org) {
          return {
            content: [{ type: "text" as const, text: "GitHub Security connector not configured." }],
          };
        }
        try {
          const state = params.state || "open";
          const perPage = params.limit || 100;
          let path: string;
          if (params.repo) {
            path = `/repos/${config.org}/${params.repo}/secret-scanning/alerts?state=${state}&per_page=${perPage}`;
          } else {
            path = `/orgs/${config.org}/secret-scanning/alerts?state=${state}&per_page=${perPage}`;
          }
          const results = await ghApi(path);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }],
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `GitHub secret scanning error: ${err instanceof Error ? err.message : String(err)}` }],
          };
        }
      },
    });
  },
};

export default plugin;
