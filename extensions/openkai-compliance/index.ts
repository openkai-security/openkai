/**
 * OpenKai Compliance Automation Extension
 *
 * Provides tools for compliance assessment, evidence collection, and gap analysis.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-compliance",
  name: "OpenKai Compliance Automation",
  description: "Compliance assessment, evidence collection, and gap analysis tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "compliance_assess",
      label: "Assess Compliance",
      description:
        "Evaluate security compliance posture against a specified framework. Supports NIST CSF, NIST 800-53, ISO 27001, SOC 2, PCI DSS, HIPAA, CIS Controls.",
      parameters: Type.Object({
        framework: Type.String({
          description: "Compliance framework to assess against",
          enum: [
            "nist_csf",
            "nist_800_53",
            "iso_27001",
            "soc2",
            "pci_dss",
            "hipaa",
            "cis_controls",
          ],
        }),
        scope: Type.Optional(
          Type.String({
            description:
              "Assessment scope (e.g., 'all', specific control families, or system boundaries)",
          })
        ),
        current_controls: Type.Optional(
          Type.String({
            description:
              "JSON description of currently implemented controls, or 'auto' to gather from connected systems",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const frameworkNames: Record<string, string> = {
          nist_csf: "NIST Cybersecurity Framework 2.0",
          nist_800_53: "NIST SP 800-53 Rev. 5",
          iso_27001: "ISO/IEC 27001:2022",
          soc2: "SOC 2 Type II",
          pci_dss: "PCI DSS v4.0",
          hipaa: "HIPAA Security Rule",
          cis_controls: "CIS Controls v8",
        };

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Compliance Assessment`,
                ``,
                `**Framework:** ${frameworkNames[String(params.framework)] || params.framework}`,
                `**Scope:** ${params.scope || "full assessment"}`,
                ``,
                `_The agent should:_`,
                `1. _List all control requirements for the selected framework and scope_`,
                `2. _Assess current implementation status for each control_`,
                `3. _Score compliance by control family_`,
                `4. _Identify gaps classified as: critical, major, minor, observation_`,
                `5. _Provide specific remediation recommendations for each gap_`,
                `6. _Calculate overall compliance score_`,
                `7. _Generate an executive summary_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "compliance_collect_evidence",
      label: "Collect Compliance Evidence",
      description:
        "Automatically gather compliance evidence from connected systems — configurations, audit logs, policies, and screenshots.",
      parameters: Type.Object({
        framework: Type.String({
          description: "Framework for which to collect evidence",
        }),
        controls: Type.Optional(
          Type.String({
            description:
              "Specific control IDs to collect evidence for (comma-separated), or 'all'",
          })
        ),
        sources: Type.Optional(
          Type.String({
            description:
              "Data sources to query (e.g., 'aws,azure,splunk,jira'). Defaults to all configured.",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Evidence Collection`,
                ``,
                `**Framework:** ${params.framework}`,
                `**Controls:** ${params.controls || "all"}`,
                `**Sources:** ${params.sources || "all configured"}`,
                ``,
                `_The agent should:_`,
                `1. _Map each control to required evidence types_`,
                `2. _Query connected systems for relevant data_`,
                `3. _Capture configurations, logs, and policy documents_`,
                `4. _Verify evidence freshness (flag anything >90 days old)_`,
                `5. _Organize evidence by control ID_`,
                `6. _Report collection status: gathered, missing, stale_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "compliance_gap_analysis",
      label: "Compliance Gap Analysis",
      description:
        "Identify compliance gaps between current state and framework requirements, with prioritized remediation recommendations.",
      parameters: Type.Object({
        framework: Type.String({
          description: "Compliance framework",
        }),
        assessment_data: Type.Optional(
          Type.String({
            description:
              "Previous assessment results (JSON) to analyze for gaps. If not provided, a new assessment will be performed.",
          })
        ),
        risk_appetite: Type.Optional(
          Type.String({
            description: "Organization's risk appetite level",
            enum: ["conservative", "moderate", "aggressive"],
            default: "moderate",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Compliance Gap Analysis`,
                ``,
                `**Framework:** ${params.framework}`,
                `**Risk appetite:** ${params.risk_appetite || "moderate"}`,
                ``,
                `_The agent should:_`,
                `1. _Compare current control implementations against requirements_`,
                `2. _Classify each gap: critical, major, minor, observation_`,
                `3. _Estimate remediation effort (hours/days) per gap_`,
                `4. _Prioritize based on risk impact and audit timeline_`,
                `5. _Generate a remediation roadmap_`,
                `6. _Identify quick wins (high impact, low effort)_`,
                `7. _Produce audit-ready gap analysis documentation_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
