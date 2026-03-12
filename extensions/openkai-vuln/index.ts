/**
 * OpenKai Vulnerability Management Extension
 *
 * Provides tools for vulnerability triage, search, and remediation.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-vuln",
  name: "OpenKai Vulnerability Management",
  description: "Vulnerability triage, search, and remediation tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    // -----------------------------------------------------------------------
    // Tool: vuln_triage
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "vuln_triage",
      label: "Triage Vulnerabilities",
      description:
        "Analyze and prioritize a batch of vulnerabilities based on exploitability, asset context, and business impact. Accepts vulnerability data in JSON format.",
      parameters: Type.Object({
        vulnerabilities: Type.String({
          description:
            "JSON array of vulnerability objects. Each should include: cve_id, cvss, description, affected_asset, and optionally: epss, is_kev, has_exploit, asset_criticality, internet_facing",
        }),
        output_format: Type.Optional(
          Type.String({
            description: "Output format: summary | detailed | json",
            enum: ["summary", "detailed", "json"],
            default: "detailed",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        try {
          const vulns = JSON.parse(params.vulnerabilities as string);

          if (!Array.isArray(vulns) || vulns.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: "Error: Please provide a non-empty JSON array of vulnerability objects.",
                },
              ],
            };
          }

          const triaged = vulns.map((v: Record<string, unknown>) => {
            let score = 0;
            const factors: string[] = [];

            // CVSS contribution (0-50)
            const cvss = Number(v.cvss) || 0;
            score += cvss * 5;
            if (cvss > 0) factors.push(`CVSS: ${cvss}`);

            // EPSS contribution (0-20)
            const epss = Number(v.epss) || 0;
            if (epss > 0) {
              score += epss * 20;
              factors.push(`EPSS: ${(epss * 100).toFixed(1)}%`);
            }

            // KEV bonus
            if (v.is_kev) {
              score += 15;
              factors.push("CISA KEV");
            }

            // Exploit availability
            if (v.has_exploit) {
              score += 10;
              factors.push("Public exploit");
            }

            // Asset context
            if (v.internet_facing) {
              score += 10;
              factors.push("Internet-facing");
            }

            const critBonus: Record<string, number> = {
              critical: 10,
              high: 5,
              medium: 0,
              low: -5,
            };
            const crit = String(v.asset_criticality || "medium");
            score += critBonus[crit] ?? 0;
            if (v.asset_criticality) factors.push(`Asset: ${crit}`);

            score = Math.max(0, Math.min(100, score));

            let severity: string;
            if (score >= 80) severity = "CRITICAL";
            else if (score >= 60) severity = "HIGH";
            else if (score >= 40) severity = "MEDIUM";
            else if (score >= 20) severity = "LOW";
            else severity = "INFO";

            return {
              cve_id: v.cve_id || "UNKNOWN",
              original_cvss: cvss,
              risk_score: score,
              severity,
              factors,
              asset: v.affected_asset || "unknown",
              description: v.description || "",
            };
          });

          // Sort by risk score descending
          triaged.sort(
            (a: { risk_score: number }, b: { risk_score: number }) =>
              b.risk_score - a.risk_score
          );

          if (params.output_format === "json") {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(triaged, null, 2),
                },
              ],
            };
          }

          // Build summary
          const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
          for (const t of triaged) {
            counts[t.severity as keyof typeof counts]++;
          }

          const lines = [
            `## Vulnerability Triage Results`,
            ``,
            `**Total:** ${triaged.length} findings`,
            `- Critical: ${counts.CRITICAL}`,
            `- High: ${counts.HIGH}`,
            `- Medium: ${counts.MEDIUM}`,
            `- Low: ${counts.LOW}`,
            `- Informational: ${counts.INFO}`,
            ``,
          ];

          if (params.output_format !== "summary") {
            lines.push(`## Priority Findings`, ``);
            for (const t of triaged.slice(0, 20)) {
              lines.push(
                `### ${t.cve_id} — Risk: ${t.risk_score}/100 (${t.severity})`,
                `- **Asset:** ${t.asset}`,
                `- **CVSS:** ${t.original_cvss}`,
                `- **Factors:** ${t.factors.join(", ")}`,
                `- **Description:** ${t.description}`,
                ``
              );
            }
            if (triaged.length > 20) {
              lines.push(
                `... and ${triaged.length - 20} more findings. Use json output for full results.`
              );
            }
          }

          return {
            content: [{ type: "text" as const, text: lines.join("\n") }],
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error parsing vulnerability data: ${err instanceof Error ? err.message : String(err)}`,
              },
            ],
          };
        }
      },
    });

    // -----------------------------------------------------------------------
    // Tool: vuln_search
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "vuln_search",
      label: "Search Vulnerabilities",
      description:
        "Search vulnerability databases (NVD, EPSS, CISA KEV) for specific CVEs or keywords. Returns CVE details, CVSS scores, EPSS probabilities, and KEV status.",
      parameters: Type.Object({
        query: Type.String({
          description:
            "CVE ID (e.g., CVE-2024-1234) or keyword search (e.g., 'Apache Log4j RCE')",
        }),
        source: Type.Optional(
          Type.String({
            description: "Data source to search: nvd | epss | kev | all",
            enum: ["nvd", "epss", "kev", "all"],
            default: "all",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        const query = String(params.query);
        const source = String(params.source || "all");

        const results: string[] = [
          `## Vulnerability Search: ${query}`,
          `**Source:** ${source}`,
          ``,
        ];

        // NVD lookup
        if (source === "all" || source === "nvd") {
          try {
            const cveMatch = query.match(/CVE-\d{4}-\d{4,}/i);
            if (cveMatch) {
              const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveMatch[0]}`;
              const resp = await fetch(url);
              if (resp.ok) {
                const data = (await resp.json()) as {
                  vulnerabilities?: Array<{
                    cve: {
                      id: string;
                      descriptions?: Array<{ lang: string; value: string }>;
                      metrics?: {
                        cvssMetricV31?: Array<{
                          cvssData: { baseScore: number; baseSeverity: string };
                        }>;
                      };
                      references?: Array<{ url: string }>;
                    };
                  }>;
                };
                if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                  const cve = data.vulnerabilities[0].cve;
                  const desc =
                    cve.descriptions?.find((d) => d.lang === "en")?.value ??
                    "No description";
                  const cvss =
                    cve.metrics?.cvssMetricV31?.[0]?.cvssData;
                  results.push(`### NVD: ${cve.id}`);
                  results.push(`- **Description:** ${desc}`);
                  if (cvss) {
                    results.push(
                      `- **CVSS 3.1:** ${cvss.baseScore} (${cvss.baseSeverity})`
                    );
                  }
                  if (cve.references?.length) {
                    results.push(
                      `- **References:** ${cve.references
                        .slice(0, 3)
                        .map((r) => r.url)
                        .join(", ")}`
                    );
                  }
                  results.push(``);
                }
              }
            } else {
              results.push(
                `_NVD search requires a CVE ID (e.g., CVE-2024-1234). Use keyword search for general queries._`,
                ``
              );
            }
          } catch (err) {
            results.push(
              `_NVD lookup failed: ${err instanceof Error ? err.message : String(err)}_`,
              ``
            );
          }
        }

        // EPSS lookup
        if (source === "all" || source === "epss") {
          try {
            const cveMatch = query.match(/CVE-\d{4}-\d{4,}/i);
            if (cveMatch) {
              const url = `https://api.first.org/data/v1/epss?cve=${cveMatch[0]}`;
              const resp = await fetch(url);
              if (resp.ok) {
                const data = (await resp.json()) as {
                  data?: Array<{
                    cve: string;
                    epss: string;
                    percentile: string;
                  }>;
                };
                if (data.data && data.data.length > 0) {
                  const epss = data.data[0];
                  results.push(`### EPSS: ${epss.cve}`);
                  results.push(
                    `- **Exploit probability (30 days):** ${(Number(epss.epss) * 100).toFixed(2)}%`
                  );
                  results.push(
                    `- **Percentile:** ${(Number(epss.percentile) * 100).toFixed(1)}%`
                  );
                  results.push(``);
                }
              }
            }
          } catch (err) {
            results.push(
              `_EPSS lookup failed: ${err instanceof Error ? err.message : String(err)}_`,
              ``
            );
          }
        }

        // KEV check
        if (source === "all" || source === "kev") {
          try {
            const cveMatch = query.match(/CVE-\d{4}-\d{4,}/i);
            if (cveMatch) {
              const url =
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
              const resp = await fetch(url);
              if (resp.ok) {
                const data = (await resp.json()) as {
                  vulnerabilities?: Array<{
                    cveID: string;
                    vendorProject: string;
                    product: string;
                    dateAdded: string;
                    dueDate: string;
                    knownRansomwareCampaignUse: string;
                  }>;
                };
                const match = data.vulnerabilities?.find(
                  (v) =>
                    v.cveID.toLowerCase() === cveMatch[0].toLowerCase()
                );
                if (match) {
                  results.push(`### CISA KEV: ${match.cveID} — **IN CATALOG**`);
                  results.push(
                    `- **Vendor:** ${match.vendorProject} — ${match.product}`
                  );
                  results.push(`- **Date added:** ${match.dateAdded}`);
                  results.push(`- **Due date:** ${match.dueDate}`);
                  results.push(
                    `- **Ransomware use:** ${match.knownRansomwareCampaignUse}`
                  );
                  results.push(``);
                } else {
                  results.push(
                    `### CISA KEV: ${cveMatch[0]} — Not in catalog`,
                    ``
                  );
                }
              }
            }
          } catch (err) {
            results.push(
              `_KEV lookup failed: ${err instanceof Error ? err.message : String(err)}_`,
              ``
            );
          }
        }

        return {
          content: [{ type: "text" as const, text: results.join("\n") }],
        };
      },
    });

    // -----------------------------------------------------------------------
    // Tool: vuln_remediate
    // -----------------------------------------------------------------------
    api.registerTool({
      name: "vuln_remediate",
      label: "Generate Remediation Guidance",
      description:
        "Generate step-by-step remediation guidance for a specific vulnerability, including patches, workarounds, and compensating controls.",
      parameters: Type.Object({
        cve_id: Type.String({
          description: "CVE identifier (e.g., CVE-2024-1234)",
        }),
        affected_software: Type.Optional(
          Type.String({
            description:
              "Affected software name and version (e.g., 'Apache httpd 2.4.49')",
          })
        ),
        environment_context: Type.Optional(
          Type.String({
            description:
              "Additional context about the environment (OS, deployment type, constraints)",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        // This tool provides a structured template that the LLM agent fills in
        // with its knowledge. The tool itself gathers NVD data to assist.
        const cveId = String(params.cve_id);
        const software = params.affected_software
          ? String(params.affected_software)
          : "Not specified";
        const context = params.environment_context
          ? String(params.environment_context)
          : "Not specified";

        let nvdInfo = "";
        try {
          const cveMatch = cveId.match(/CVE-\d{4}-\d{4,}/i);
          if (cveMatch) {
            const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveMatch[0]}`;
            const resp = await fetch(url);
            if (resp.ok) {
              const data = (await resp.json()) as {
                vulnerabilities?: Array<{
                  cve: {
                    descriptions?: Array<{ lang: string; value: string }>;
                    metrics?: {
                      cvssMetricV31?: Array<{
                        cvssData: {
                          baseScore: number;
                          baseSeverity: string;
                          attackVector: string;
                        };
                      }>;
                    };
                    references?: Array<{ url: string; tags?: string[] }>;
                  };
                }>;
              };
              if (data.vulnerabilities?.[0]) {
                const cve = data.vulnerabilities[0].cve;
                const desc =
                  cve.descriptions?.find((d) => d.lang === "en")?.value ??
                  "";
                const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
                const patchRefs = cve.references
                  ?.filter((r) => r.tags?.includes("Patch"))
                  ?.map((r) => r.url);

                nvdInfo = [
                  `\n### NVD Data`,
                  `- **Description:** ${desc}`,
                  cvss
                    ? `- **CVSS:** ${cvss.baseScore} (${cvss.baseSeverity}), Vector: ${cvss.attackVector}`
                    : "",
                  patchRefs?.length
                    ? `- **Patch references:** ${patchRefs.join(", ")}`
                    : "",
                ].filter(Boolean).join("\n");
              }
            }
          }
        } catch {
          // NVD lookup failure is non-fatal
        }

        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Remediation Guidance: ${cveId}`,
                ``,
                `**Affected software:** ${software}`,
                `**Environment:** ${context}`,
                nvdInfo,
                ``,
                `---`,
                ``,
                `_Use this data to generate specific remediation steps. The agent should:_`,
                `1. _Identify the specific patch or upgrade needed_`,
                `2. _Provide step-by-step remediation instructions_`,
                `3. _List workarounds if patching is not immediately possible_`,
                `4. _Describe compensating controls_`,
                `5. _Include a rollback plan_`,
                `6. _Note any service disruption expected_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
