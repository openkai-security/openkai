/**
 * OpenKai Log Optimization Extension
 *
 * Provides tools for log pipeline analysis and SIEM cost optimization.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-log-optimizer",
  name: "OpenKai Log Optimization",
  description: "Log pipeline analysis and SIEM cost optimization tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "log_analyze_pipeline",
      label: "Analyze Log Pipeline",
      description:
        "Analyze log sources to identify volume, security value, detection rule dependencies, and optimization opportunities.",
      parameters: Type.Object({
        log_sources: Type.Optional(
          Type.String({
            description:
              "JSON array of log source descriptions, or 'auto' to query connected SIEM. Each source: { name, volume_gb_day, type, description }",
          })
        ),
        siem_type: Type.Optional(
          Type.String({
            description: "SIEM platform type for cost estimation",
            enum: ["splunk", "elastic", "sentinel", "other"],
          })
        ),
        cost_per_gb: Type.Optional(
          Type.Number({
            description: "Current cost per GB/day of log ingestion in USD",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Log Pipeline Analysis`,
                ``,
                `**SIEM:** ${params.siem_type || "not specified"}`,
                `**Cost/GB:** ${params.cost_per_gb ? `$${params.cost_per_gb}` : "not specified"}`,
                ``,
                `_The agent should:_`,
                `1. _Catalog all log sources with daily volume_`,
                `2. _Classify each source by security value (high/medium/low)_`,
                `3. _Map detection rules to their required log sources_`,
                `4. _Calculate per-source cost_`,
                `5. _Identify optimization opportunities:_`,
                `   - _High-volume, low-value sources (route to cold storage)_`,
                `   - _Duplicate/redundant sources_`,
                `   - _Sources with no detection rule dependencies_`,
                `   - _Sampling opportunities for noisy sources_`,
                `6. _Estimate total savings potential_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "log_optimize_routing",
      label: "Optimize Log Routing",
      description:
        "Generate routing rules to direct low-value logs to cold/archive storage while preserving detection coverage.",
      parameters: Type.Object({
        analysis_results: Type.Optional(
          Type.String({
            description:
              "Results from log_analyze_pipeline (JSON), or describe the optimization request",
          })
        ),
        target_savings_pct: Type.Optional(
          Type.Number({
            description: "Target cost reduction percentage (e.g., 30 for 30%)",
            default: 30,
          })
        ),
        preserve_rules: Type.Optional(
          Type.String({
            description:
              "Detection rule IDs that must NOT lose data sources (comma-separated)",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Log Routing Optimization`,
                ``,
                `**Target savings:** ${params.target_savings_pct || 30}%`,
                `**Protected rules:** ${params.preserve_rules || "all active rules"}`,
                ``,
                `_The agent should:_`,
                `1. _Generate routing rules for the target SIEM format_`,
                `2. _Route low-value logs to cold/archive tier_`,
                `3. _Apply sampling to high-volume, medium-value sources_`,
                `4. _Verify no protected detection rules lose data_`,
                `5. _Estimate cost savings per routing change_`,
                `6. _Provide rollback instructions for each change_`,
                `7. _Output a phased implementation plan_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
