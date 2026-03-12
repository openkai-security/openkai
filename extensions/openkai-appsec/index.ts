/**
 * OpenKai Application Security Extension
 *
 * Provides tools for SAST/SCA finding analysis and code fix generation.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-appsec",
  name: "OpenKai Application Security",
  description: "SAST/SCA analysis and code fix generation tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "appsec_analyze_sast",
      label: "Analyze SAST Findings",
      description:
        "Triage static analysis findings to identify true-positive code vulnerabilities. Analyzes reachability, exploitability, and framework protections.",
      parameters: Type.Object({
        findings: Type.String({
          description:
            "JSON array of SAST findings. Each: { id, rule, severity, file, line, code_snippet, description, cwe }",
        }),
        language: Type.Optional(
          Type.String({
            description: "Primary programming language of the codebase",
          })
        ),
        framework: Type.Optional(
          Type.String({
            description:
              "Web framework in use (e.g., 'express', 'django', 'spring', 'rails')",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        let findingCount = 0;
        try {
          const parsed = JSON.parse(String(params.findings));
          findingCount = Array.isArray(parsed) ? parsed.length : 0;
        } catch {
          // count estimation
        }

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## SAST Finding Analysis`,
                ``,
                `**Findings to analyze:** ${findingCount || "see input"}`,
                `**Language:** ${params.language || "auto-detect"}`,
                `**Framework:** ${params.framework || "auto-detect"}`,
                ``,
                `_The agent should analyze each finding:_`,
                `1. _Is the vulnerable code path reachable from untrusted input?_`,
                `2. _Are there framework-level protections (auto-escaping, CSRF tokens, etc.)?_`,
                `3. _Is there input validation before the vulnerable sink?_`,
                `4. _What is the actual exploitability and impact?_`,
                `5. _Classify as: True Positive, False Positive, Needs Review_`,
                `6. _For true positives, describe the attack scenario_`,
                `7. _Generate a triage summary with false positive reduction percentage_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "appsec_analyze_sca",
      label: "Analyze SCA Findings",
      description:
        "Analyze software composition analysis findings to determine if vulnerable dependency functions are actually called in the codebase.",
      parameters: Type.Object({
        findings: Type.String({
          description:
            "JSON array of SCA findings. Each: { id, package, version, cve, severity, description, fix_version }",
        }),
        manifest_file: Type.Optional(
          Type.String({
            description:
              "Path to package manifest (package.json, requirements.txt, pom.xml, etc.)",
          })
        ),
        transitive: Type.Optional(
          Type.Boolean({
            description: "Include transitive dependency analysis",
            default: true,
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## SCA Finding Analysis`,
                ``,
                `**Include transitive deps:** ${params.transitive !== false ? "yes" : "no"}`,
                ``,
                `_The agent should analyze each finding:_`,
                `1. _Is the vulnerable function/module actually imported and called?_`,
                `2. _Is this a direct or transitive dependency?_`,
                `3. _Is the vulnerability reachable through the application's usage?_`,
                `4. _What is the upgrade path? Any breaking changes?_`,
                `5. _Classify as: Exploitable, Not Exploitable, Needs Review_`,
                `6. _For exploitable findings, describe the attack vector_`,
                `7. _Generate upgrade recommendations with compatibility notes_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "appsec_generate_fix",
      label: "Generate Code Fix",
      description:
        "Generate developer-ready code fixes for identified application vulnerabilities. Produces diffs, test cases, and PR descriptions.",
      parameters: Type.Object({
        vulnerability: Type.String({
          description:
            "Description of the vulnerability to fix, including file, line, CWE, and code context",
        }),
        fix_type: Type.Optional(
          Type.String({
            description: "Type of fix to generate",
            enum: ["code_patch", "dependency_upgrade", "config_change", "auto"],
            default: "auto",
          })
        ),
        include_tests: Type.Optional(
          Type.Boolean({
            description: "Generate test cases to verify the fix",
            default: true,
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Code Fix Generation`,
                ``,
                `**Fix type:** ${params.fix_type || "auto"}`,
                `**Include tests:** ${params.include_tests !== false ? "yes" : "no"}`,
                ``,
                `### Vulnerability`,
                String(params.vulnerability),
                ``,
                `_The agent should:_`,
                `1. _Analyze the vulnerable code pattern_`,
                `2. _Generate a minimal, targeted fix_`,
                `3. _Provide before/after code diff_`,
                `4. _Generate test cases proving the fix works_`,
                `5. _Verify the fix doesn't introduce regressions_`,
                `6. _Format as a pull request description_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
