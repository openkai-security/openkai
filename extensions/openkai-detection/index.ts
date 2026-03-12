/**
 * OpenKai Detection Engineering Extension
 *
 * Provides tools for creating, tuning, and validating SIEM detection rules.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-detection",
  name: "OpenKai Detection Engineering",
  description: "Detection rule generation, tuning, and validation tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    // -----------------------------------------------------------------------
    // Tool: detection_generate_rule
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "detection_generate_rule",
      label: "Generate Detection Rule",
      description:
        "Create a SIEM detection rule for a specified threat pattern. Supports Sigma (universal), SPL (Splunk), KQL (Sentinel), and EQL (Elastic) formats.",
      parameters: Type.Object({
        threat_description: Type.String({
          description:
            "Description of the threat to detect (e.g., 'PowerShell encoded command execution', 'lateral movement via PsExec')",
        }),
        format: Type.Optional(
          Type.String({
            description: "Output format for the detection rule",
            enum: ["sigma", "spl", "kql", "eql"],
            default: "sigma",
          })
        ),
        mitre_technique: Type.Optional(
          Type.String({
            description:
              "MITRE ATT&CK technique ID (e.g., T1059.001) to map this detection to",
          })
        ),
        log_source: Type.Optional(
          Type.String({
            description:
              "Log source type (e.g., 'windows_process_creation', 'proxy', 'firewall')",
          })
        ),
        severity: Type.Optional(
          Type.String({
            description: "Detection rule severity level",
            enum: ["critical", "high", "medium", "low", "informational"],
            default: "medium",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const threat = String(params.threat_description);
        const format = String(params.format || "sigma");
        const mitre = params.mitre_technique
          ? String(params.mitre_technique)
          : "Unknown";
        const logSource = params.log_source
          ? String(params.log_source)
          : "to be determined";
        const severity = String(params.severity || "medium");

        const context = [
          `## Detection Rule Generation Request`,
          ``,
          `**Threat:** ${threat}`,
          `**Format:** ${format.toUpperCase()}`,
          `**MITRE ATT&CK:** ${mitre}`,
          `**Log Source:** ${logSource}`,
          `**Severity:** ${severity}`,
          ``,
          `---`,
          ``,
          `_The agent should generate a complete detection rule with:_`,
          `1. _Full rule syntax in the requested format_`,
          `2. _MITRE ATT&CK technique mapping_`,
          `3. _Description of what the rule detects_`,
          `4. _Known false positive conditions_`,
          `5. _Recommended tuning parameters_`,
          `6. _Expected alert volume estimate_`,
        ];

        if (format === "sigma") {
          context.push(
            ``,
            `### Sigma Template`,
            "```yaml",
            `title: [Rule Name]`,
            `id: [generate UUID]`,
            `status: experimental`,
            `description: ${threat}`,
            `references:`,
            `  - https://attack.mitre.org/techniques/${mitre}/`,
            `author: OpenKai DetectionEng`,
            `date: ${new Date().toISOString().split("T")[0].replace(/-/g, "/")}`,
            `tags:`,
            `  - attack.${mitre.toLowerCase()}`,
            `logsource:`,
            `  category: ${logSource}`,
            `detection:`,
            `  selection:`,
            `    # Define selection criteria`,
            `  condition: selection`,
            `falsepositives:`,
            `  - [List known false positive scenarios]`,
            `level: ${severity}`,
            "```"
          );
        }

        return {
          content: [{ type: "text" as const, text: context.join("\n") }],
        };
      },
    });

    // -----------------------------------------------------------------------
    // Tool: detection_tune_rule
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "detection_tune_rule",
      label: "Tune Detection Rule",
      description:
        "Analyze and optimize an existing detection rule to reduce false positives while maintaining detection coverage.",
      parameters: Type.Object({
        rule: Type.String({
          description:
            "The existing detection rule to tune (full rule text in any supported format)",
        }),
        false_positive_samples: Type.Optional(
          Type.String({
            description:
              "JSON array of sample events that triggered false positives",
          })
        ),
        current_fp_rate: Type.Optional(
          Type.Number({
            description:
              "Current false positive rate as a percentage (e.g., 74 for 74%)",
          })
        ),
        target_fp_rate: Type.Optional(
          Type.Number({
            description:
              "Target false positive rate as a percentage (e.g., 10 for 10%)",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const rule = String(params.rule);
        const fpRate = params.current_fp_rate
          ? `${params.current_fp_rate}%`
          : "unknown";
        const targetRate = params.target_fp_rate
          ? `${params.target_fp_rate}%`
          : "< 15%";

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Detection Rule Tuning`,
                ``,
                `**Current FP rate:** ${fpRate}`,
                `**Target FP rate:** ${targetRate}`,
                ``,
                `### Current Rule`,
                "```",
                rule,
                "```",
                ``,
                params.false_positive_samples
                  ? `### False Positive Samples\n\`\`\`json\n${params.false_positive_samples}\n\`\`\`\n`
                  : "",
                `---`,
                ``,
                `_The agent should analyze the rule and suggest specific tuning:_`,
                `1. _Identify patterns in false positive samples_`,
                `2. _Suggest exclusion criteria_`,
                `3. _Recommend threshold adjustments_`,
                `4. _Verify true positive detection is preserved_`,
                `5. _Provide the tuned rule_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    // -----------------------------------------------------------------------
    // Tool: detection_validate_rule
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "detection_validate_rule",
      label: "Validate Detection Rule",
      description:
        "Validate a detection rule for syntax correctness, performance, and coverage against test data.",
      parameters: Type.Object({
        rule: Type.String({
          description: "The detection rule to validate",
        }),
        format: Type.String({
          description: "Rule format",
          enum: ["sigma", "spl", "kql", "eql"],
        }),
        test_data: Type.Optional(
          Type.String({
            description:
              "JSON array of test events. Each should include 'expected_match: true|false'",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const rule = String(params.rule);
        const format = String(params.format);

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Detection Rule Validation`,
                ``,
                `**Format:** ${format.toUpperCase()}`,
                ``,
                `### Rule`,
                "```",
                rule,
                "```",
                ``,
                params.test_data
                  ? `### Test Data\n\`\`\`json\n${params.test_data}\n\`\`\`\n`
                  : "",
                `---`,
                ``,
                `_The agent should validate:_`,
                `1. _Syntax correctness for the target SIEM_`,
                `2. _Logical soundness (no impossible conditions)_`,
                `3. _Performance impact estimate (query cost)_`,
                `4. _Coverage assessment against test data if provided_`,
                `5. _Recommendations for improvement_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
