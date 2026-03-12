/**
 * OpenKai Identity Security Extension
 *
 * Provides tools for IAM auditing and least-privilege policy enforcement.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-identity",
  name: "OpenKai Identity Security",
  description: "IAM audit and least-privilege enforcement tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "identity_audit_permissions",
      label: "Audit IAM Permissions",
      description:
        "Audit IAM policies to identify over-privileged accounts, stale credentials, missing MFA, and privilege escalation paths.",
      parameters: Type.Object({
        platform: Type.String({
          description: "IAM platform to audit",
          enum: ["aws", "azure", "gcp", "okta", "active_directory", "custom"],
        }),
        scope: Type.Optional(
          Type.String({
            description:
              "Audit scope (e.g., 'all', specific account/tenant, or OU/group)",
          })
        ),
        iam_data: Type.Optional(
          Type.String({
            description:
              "IAM policy data (JSON). If not provided, will query via connector.",
          })
        ),
        focus_areas: Type.Optional(
          Type.String({
            description:
              "Comma-separated focus areas: over_privileged, stale, mfa, escalation_paths, service_accounts",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## IAM Permission Audit`,
                ``,
                `**Platform:** ${params.platform}`,
                `**Scope:** ${params.scope || "full"}`,
                `**Focus:** ${params.focus_areas || "all areas"}`,
                ``,
                `_The agent should:_`,
                `1. _Enumerate all identities (users, roles, service accounts, groups)_`,
                `2. _Analyze assigned vs. used permissions_`,
                `3. _Identify over-privileged accounts (assigned > used)_`,
                `4. _Flag stale accounts (no activity in 90+ days)_`,
                `5. _Check MFA enforcement status_`,
                `6. _Map privilege escalation paths_`,
                `7. _Score each identity by risk level_`,
                `8. _Generate prioritized remediation recommendations_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "identity_generate_policy",
      label: "Generate Least-Privilege Policy",
      description:
        "Generate a right-sized IAM policy based on actual usage patterns, eliminating unnecessary permissions.",
      parameters: Type.Object({
        identity: Type.String({
          description:
            "Identity to generate policy for (user ARN, principal name, or service account)",
        }),
        platform: Type.String({
          description: "IAM platform",
          enum: ["aws", "azure", "gcp"],
        }),
        usage_data: Type.Optional(
          Type.String({
            description:
              "Usage/access log data (JSON) showing actual API calls made by this identity",
          })
        ),
        time_period_days: Type.Optional(
          Type.Number({
            description:
              "Number of days of usage data to analyze for policy generation",
            default: 90,
          })
        ),
        output_format: Type.Optional(
          Type.String({
            description: "Policy output format",
            enum: ["json", "terraform", "cloudformation", "pulumi"],
            default: "json",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Least-Privilege Policy Generation`,
                ``,
                `**Identity:** ${params.identity}`,
                `**Platform:** ${params.platform}`,
                `**Analysis period:** ${params.time_period_days || 90} days`,
                `**Output format:** ${params.output_format || "json"}`,
                ``,
                `_The agent should:_`,
                `1. _Analyze usage data to determine actually-used permissions_`,
                `2. _Generate a minimal policy covering only used actions_`,
                `3. _Add resource-level restrictions where possible_`,
                `4. _Include condition keys for additional security (IP, MFA, time)_`,
                `5. _Output in the requested format_`,
                `6. _Document what permissions were removed and why_`,
                `7. _Flag any removed permissions that may be needed seasonally_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
