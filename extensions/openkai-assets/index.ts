/**
 * OpenKai Asset Management Extension
 *
 * Provides tools for asset discovery, enrichment, and ownership mapping.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const plugin = {
  id: "openkai-assets",
  name: "OpenKai Asset Management",
  description: "Asset discovery, enrichment, and ownership mapping tools",
  configSchema: Type.Object({}),

  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "asset_discover",
      label: "Discover Assets",
      description:
        "Scan and discover IT/OT assets from connected data sources. Aggregates asset data from CMDB, cloud APIs, network scans, and endpoint agents.",
      parameters: Type.Object({
        sources: Type.Optional(
          Type.String({
            description:
              "Comma-separated list of data sources to query (e.g., 'cmdb,aws,azure,network_scan'). Defaults to all configured sources.",
          })
        ),
        scope: Type.Optional(
          Type.String({
            description:
              "Discovery scope filter (e.g., 'subnet:10.0.0.0/8', 'cloud:aws', 'type:ot')",
          })
        ),
        include_shadow_it: Type.Optional(
          Type.Boolean({
            description:
              "Include shadow IT detection (unauthorized cloud services, unmanaged devices). Default: true",
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
                `## Asset Discovery Request`,
                ``,
                `**Sources:** ${params.sources || "all configured"}`,
                `**Scope:** ${params.scope || "full environment"}`,
                `**Shadow IT:** ${params.include_shadow_it !== false ? "included" : "excluded"}`,
                ``,
                `_The agent should use available connectors to:_`,
                `1. _Query each configured data source for asset records_`,
                `2. _Deduplicate across sources (match by hostname, IP, MAC, cloud ID)_`,
                `3. _Identify unmanaged/shadow assets_`,
                `4. _Classify assets by type (server, workstation, network, IoT, OT, cloud, container)_`,
                `5. _Output a structured inventory_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "asset_enrich",
      label: "Enrich Asset",
      description:
        "Enrich an asset record with business context (owner, criticality), technical context (OS, services, patches), and network context (zone, exposure).",
      parameters: Type.Object({
        asset_id: Type.String({
          description: "Asset identifier (hostname, IP, or internal ID)",
        }),
        enrichment_types: Type.Optional(
          Type.String({
            description:
              "Comma-separated enrichment types: business, technical, network, compliance, vulnerability. Defaults to all.",
          })
        ),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Asset Enrichment Request`,
                ``,
                `**Asset:** ${params.asset_id}`,
                `**Enrichment types:** ${params.enrichment_types || "all"}`,
                ``,
                `_The agent should gather context from available sources:_`,
                `1. _Business: owner, department, criticality tier, data classification_`,
                `2. _Technical: OS, services, open ports, software inventory, patch level_`,
                `3. _Network: subnet, VLAN, zone (DMZ/internal/OT/cloud), internet-facing status_`,
                `4. _Compliance: applicable frameworks, last audit date_`,
                `5. _Vulnerability: open vulnerability count, highest severity_`,
              ].join("\n"),
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "asset_map_ownership",
      label: "Map Asset Ownership",
      description:
        "Determine and assign ownership for discovered assets using directory services, cloud tags, CMDB records, and usage patterns.",
      parameters: Type.Object({
        assets: Type.String({
          description:
            "JSON array of asset identifiers to map ownership for, or 'orphaned' to find all assets without owners",
        }),
      }),
      async execute(_id, params: Record<string, unknown>) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                `## Asset Ownership Mapping`,
                ``,
                `**Input:** ${params.assets}`,
                ``,
                `_The agent should:_`,
                `1. _Query directory services (AD, LDAP, cloud IAM) for ownership signals_`,
                `2. _Check CMDB records for assigned owners_`,
                `3. _Analyze cloud resource tags for ownership metadata_`,
                `4. _Infer ownership from network proximity and usage patterns_`,
                `5. _Flag orphaned assets requiring manual assignment_`,
                `6. _Output ownership mapping with confidence levels_`,
              ].join("\n"),
            },
          ],
        };
      },
    });
  },
};

export default plugin;
