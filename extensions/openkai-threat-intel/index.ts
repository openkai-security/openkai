/**
 * OpenKai Threat Intelligence Extension
 *
 * Provides tools for threat intelligence analysis, TTP mapping, and threat modeling.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-threat-intel",
  name: "OpenKai Threat Intelligence",
  description: "Threat intelligence analysis, TTP mapping, and threat modeling tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "threat_intel_analyze",
      label: "Analyze Threat Intelligence",
      description:
        "Process and analyze threat intelligence data — extract IOCs, identify TTPs, and generate actionable intelligence. Accepts threat reports, STIX bundles, or IOC lists.",
      parameters: Type.Object({
        input: Type.String({
          description:
            "Threat intelligence input: report text, STIX JSON, or comma-separated IOCs",
        }),
        input_type: Type.Optional(
          Type.String({
            description: "Input format",
            enum: ["report", "stix", "iocs", "auto"],
            default: "auto",
          })
        ),
        context: Type.Optional(
          Type.String({
            description:
              "Organization context for relevance assessment (e.g., industry, tech stack, geography)",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Threat Intelligence Analysis`,
                ``,
                `**Input type:** ${params.input_type || "auto-detect"}`,
                `**Organization context:** ${params.context || "not specified"}`,
                ``,
                `### Input Data`,
                "```",
                String(params.input).substring(0, 2000),
                String(params.input).length > 2000 ? "\n... (truncated)" : "",
                "```",
                ``,
                `_The agent should:_`,
                `1. _Extract IOCs (IPs, domains, hashes, URLs, email addresses)_`,
                `2. _Identify TTPs and map to MITRE ATT&CK_`,
                `3. _Assess relevance to the organization's industry and tech stack_`,
                `4. _Generate actionable recommendations_`,
                `5. _Suggest detection rules (hand off to detection-engineer if needed)_`,
                `6. _Rate confidence and severity_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "threat_intel_map_ttps",
      label: "Map TTPs to MITRE ATT&CK",
      description:
        "Map observed threat actor techniques to the MITRE ATT&CK framework. Identify tactics, techniques, sub-techniques, and associated mitigations.",
      parameters: Type.Object({
        techniques: Type.String({
          description:
            "Description of observed techniques, or comma-separated MITRE technique IDs (e.g., 'T1566.001, T1059.001')",
        }),
        threat_actor: Type.Optional(
          Type.String({
            description: "Known or suspected threat actor group name",
          })
        ),
        target_platform: Type.Optional(
          Type.String({
            description:
              "Target platform for mitigation mapping (e.g., 'windows', 'linux', 'cloud', 'ot')",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## MITRE ATT&CK TTP Mapping`,
                ``,
                `**Input:** ${params.techniques}`,
                `**Threat actor:** ${params.threat_actor || "unknown"}`,
                `**Platform:** ${params.target_platform || "all"}`,
                ``,
                `_The agent should:_`,
                `1. _Map each technique to ATT&CK tactic → technique → sub-technique_`,
                `2. _Provide technique descriptions and real-world examples_`,
                `3. _List associated mitigations (M-series)_`,
                `4. _Identify detection opportunities (DS-series data sources)_`,
                `5. _Assess coverage gaps in current detection rules_`,
                `6. _Generate an ATT&CK Navigator layer if requested_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "threat_model_generate",
      label: "Generate Threat Model",
      description:
        "Create a threat model for an application, system, or business process using STRIDE, MITRE ATT&CK, or custom frameworks.",
      parameters: Type.Object({
        target: Type.String({
          description:
            "What to threat model (e.g., 'web application login flow', 'OT network SCADA system', 'cloud data pipeline')",
        }),
        framework: Type.Optional(
          Type.String({
            description: "Threat modeling framework to use",
            enum: ["stride", "mitre_attack", "pasta", "custom"],
            default: "stride",
          })
        ),
        architecture: Type.Optional(
          Type.String({
            description:
              "System architecture description or diagram (text format)",
          })
        ),
        data_flows: Type.Optional(
          Type.String({
            description:
              "Description of data flows within the system (sources, sinks, trust boundaries)",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Threat Model Generation`,
                ``,
                `**Target:** ${params.target}`,
                `**Framework:** ${String(params.framework || "stride").toUpperCase()}`,
                ``,
                params.architecture
                  ? `### Architecture\n${params.architecture}\n`
                  : "",
                params.data_flows
                  ? `### Data Flows\n${params.data_flows}\n`
                  : "",
                `---`,
                ``,
                `_The agent should generate a complete threat model:_`,
                `1. _Identify assets and trust boundaries_`,
                `2. _Enumerate threats using the selected framework_`,
                `3. _Assess likelihood and impact for each threat_`,
                `4. _Map threats to MITRE ATT&CK techniques where applicable_`,
                `5. _Recommend controls and mitigations for each threat_`,
                `6. _Prioritize by risk score_`,
                `7. _Generate a summary suitable for stakeholder review_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
