/**
 * OpenKai Core Extension
 *
 * Provides shared utilities, i18n support, and base security context
 * for all OpenKai extensions and agents.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

interface I18nMessages {
  [key: string]: string | I18nMessages;
}

let messages: I18nMessages = {};
let currentLocale = "en";

function loadLocale(locale: string): I18nMessages {
  const i18nDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../i18n");
  const filePath = resolve(i18nDir, `${locale}.json`);
  if (existsSync(filePath)) {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  }
  // Fallback to English
  const enPath = resolve(i18nDir, "en.json");
  return JSON.parse(readFileSync(enPath, "utf-8"));
}

function getNestedValue(obj: I18nMessages, path: string): string {
  const parts = path.split(".");
  let current: I18nMessages | string = obj;
  for (const part of parts) {
    if (typeof current === "string" || current === undefined) return path;
    current = current[part];
  }
  return typeof current === "string" ? current : path;
}

/**
 * Translate a key with optional interpolation.
 * Usage: t("messages.welcome") or t("messages.task_delegated", { agent: "VulnAnalyst" })
 */
export function t(key: string, params?: Record<string, string>): string {
  let value = getNestedValue(messages, key);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      value = value.replace(`{{${k}}}`, v);
    }
  }
  return value;
}

// ---------------------------------------------------------------------------
// Connector Interface
// ---------------------------------------------------------------------------

export interface ConnectorConfig {
  [key: string]: unknown;
}

export interface QueryParams {
  query?: string;
  filters?: Record<string, unknown>;
  limit?: number;
  offset?: number;
  timeRange?: { start: string; end: string };
}

export interface QueryResult {
  data: unknown[];
  total: number;
  metadata?: Record<string, unknown>;
}

export interface PushAction {
  action: string;
  target: string;
  payload: unknown;
}

export interface PushResult {
  success: boolean;
  id?: string;
  message?: string;
}

export interface SecurityConnector {
  id: string;
  type:
    | "siem"
    | "edr"
    | "vuln_scanner"
    | "appsec"
    | "itsm"
    | "cloud"
    | "identity";
  connect(config: ConnectorConfig): Promise<void>;
  disconnect(): Promise<void>;
  query(params: QueryParams): Promise<QueryResult>;
  push?(action: PushAction): Promise<PushResult>;
}

// Connector registry
const connectors = new Map<string, SecurityConnector>();

export function registerConnector(connector: SecurityConnector): void {
  connectors.set(connector.id, connector);
}

export function getConnector(id: string): SecurityConnector | undefined {
  return connectors.get(id);
}

export function listConnectors(): SecurityConnector[] {
  return Array.from(connectors.values());
}

// ---------------------------------------------------------------------------
// Severity & Risk Utilities
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface RiskScore {
  score: number; // 0-100
  severity: Severity;
  factors: string[];
}

export function computeRiskScore(params: {
  cvss?: number;
  epss?: number;
  isKev?: boolean;
  internetFacing?: boolean;
  assetCriticality?: "critical" | "high" | "medium" | "low";
  hasExploit?: boolean;
}): RiskScore {
  let score = 0;
  const factors: string[] = [];

  if (params.cvss !== undefined) {
    score += params.cvss * 5; // 0-50 from CVSS
    factors.push(`CVSS: ${params.cvss}`);
  }

  if (params.epss !== undefined) {
    score += params.epss * 20; // 0-20 from EPSS
    factors.push(`EPSS: ${(params.epss * 100).toFixed(1)}%`);
  }

  if (params.isKev) {
    score += 15;
    factors.push("In CISA KEV catalog");
  }

  if (params.hasExploit) {
    score += 10;
    factors.push("Public exploit available");
  }

  if (params.internetFacing) {
    score += 10;
    factors.push("Internet-facing asset");
  }

  const criticalityBonus: Record<string, number> = {
    critical: 10,
    high: 5,
    medium: 0,
    low: -5,
  };
  if (params.assetCriticality) {
    score += criticalityBonus[params.assetCriticality] ?? 0;
    factors.push(`Asset criticality: ${params.assetCriticality}`);
  }

  score = Math.max(0, Math.min(100, score));

  let severity: Severity;
  if (score >= 80) severity = "critical";
  else if (score >= 60) severity = "high";
  else if (score >= 40) severity = "medium";
  else if (score >= 20) severity = "low";
  else severity = "info";

  return { score, severity, factors };
}

// ---------------------------------------------------------------------------
// Plugin Registration
// ---------------------------------------------------------------------------

const configSchema = Type.Object({
  locale: Type.Optional(Type.String({ default: "en" })),
});

const plugin = {
  id: "openkai-core",
  name: "OpenKai Core",
  description:
    "Core runtime for OpenKai — provides i18n, connector registry, risk scoring, and shared security context",
  configSchema,

  register(api: OpenClawPluginApi) {
    // Initialize i18n
    const config = api.pluginConfig as { locale?: string } | undefined;
    currentLocale = config?.locale ?? "en";
    try {
      messages = loadLocale(currentLocale);
    } catch {
      // Silently fall back — messages stay empty, t() returns keys
    }

    // Inject security context before every agent starts
    api.on("before_agent_start", async () => {
      return {
        prependContext: [
          "You are part of the OpenKai cybersecurity agent platform.",
          "Your role is to perform security analysis and operations autonomously with human-expert accuracy.",
          "Always prioritize findings by risk. Always provide specific, actionable recommendations.",
          "Never take destructive actions without explicit human confirmation.",
          `Current locale: ${currentLocale}`,
        ].join("\n"),
      };
    });

    // Register utility tools

    // Risk scoring tool
    api.registerTool({
      name: "openkai_risk_score",
      label: t("core.name") + " — Risk Score Calculator",
      description:
        "Calculate a risk score for a vulnerability or finding based on multiple factors (CVSS, EPSS, KEV, asset context)",
      parameters: Type.Object({
        cvss: Type.Optional(
          Type.Number({ description: "CVSS base score (0-10)", minimum: 0, maximum: 10 })
        ),
        epss: Type.Optional(
          Type.Number({
            description: "EPSS probability (0-1)",
            minimum: 0,
            maximum: 1,
          })
        ),
        is_kev: Type.Optional(
          Type.Boolean({ description: "Is this CVE in the CISA KEV catalog?" })
        ),
        internet_facing: Type.Optional(
          Type.Boolean({ description: "Is the affected asset internet-facing?" })
        ),
        asset_criticality: Type.Optional(
          Type.String({
            description: "Asset criticality tier",
            enum: ["critical", "high", "medium", "low"],
          })
        ),
        has_exploit: Type.Optional(
          Type.Boolean({ description: "Is a public exploit available?" })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const result = computeRiskScore({
          cvss: params.cvss as number | undefined,
          epss: params.epss as number | undefined,
          isKev: params.is_kev as boolean | undefined,
          internetFacing: params.internet_facing as boolean | undefined,
          assetCriticality: params.asset_criticality as
            | "critical"
            | "high"
            | "medium"
            | "low"
            | undefined,
          hasExploit: params.has_exploit as boolean | undefined,
        });
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Risk Score: ${result.score}/100 (${result.severity.toUpperCase()})`,
                "",
                "### Contributing Factors",
                ...result.factors.map((f) => `- ${f}`),
              ].join("\n"),
            },
          ],
        };
      },
    });

    // List connectors tool
    api.registerTool({
      name: "openkai_list_connectors",
      label: "List Security Connectors",
      description:
        "List all registered security tool connectors and their status",
      parameters: Type.Object({}),
      async execute() {
        const all = listConnectors();
        if (all.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No security connectors are currently registered. Configure connectors in your .env file and enable them in openkai.yaml.",
              },
            ],
          };
        }
        const lines = all.map(
          (c) => `- **${c.id}** (${c.type})`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `## Registered Connectors\n\n${lines.join("\n")}`,
            },
          ],
        };
      },
    });
  },
};

export default plugin;
