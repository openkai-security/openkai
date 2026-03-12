# OpenKai — Open-Source Agentic AI Cybersecurity Platform

**OpenKai** transforms [OpenClaw](https://github.com/openclaw/openclaw) into an autonomous cybersecurity agent platform. It gives every enterprise security team the power to build, run, and evolve their own AI-driven security operations — without depending on proprietary security vendors.

> **Our thesis:** In the age of AI, enterprise security teams should not need to buy a security platform from a vendor. They should build and operate their own — powered by open-source agentic AI, tailored to their own IT/OT environment, and continuously improved with tools like Claude Code and OpenAI Codex.

## Why OpenKai?

The cybersecurity industry has a structural problem: **fragmentation**. Enterprises run dozens of disconnected security tools — vulnerability scanners, SIEM, SOAR, EDR, CSPM, SAST, SCA, identity platforms — each producing alerts, each requiring manual triage, each operating in a silo. Security teams drown in tickets, dashboards, and handoffs while attackers move at machine speed.

**OpenKai eliminates this gap.** It provides an agentic AI layer that sits above your existing security stack, autonomously reasoning, analyzing, and executing security work end-to-end. Unlike commercial platforms that lock you into a vendor's worldview, OpenKai is:

- **Open-source** — inspect, modify, and extend every component
- **Self-hosted** — your data never leaves your environment
- **Composable** — plug in only the modules you need
- **Developer-friendly** — use Claude Code, Codex, or any coding AI agent to customize it for your specific environment
- **Community-driven** — connectors, tools, and skills contributed by the global security community

## Architecture

OpenKai is **not a fork of OpenClaw**. It is an overlay — a set of configurations, extensions, agents, skills, and connectors — that transforms a standard OpenClaw installation into a cybersecurity-focused autonomous agent platform.

```
┌──────────────────────────────────────────────────────────┐
│                      OpenKai Layer                       │
│                                                          │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────────┐  │
│  │ Agents  │ │Extensions│ │  Skills   │ │Connectors │  │
│  │         │ │          │ │           │ │           │  │
│  │Commander│ │Core      │ │Vuln Triage│ │Splunk     │  │
│  │Vuln     │ │Vuln Mgmt │ │SAST/SCA   │ │Elastic    │  │
│  │Detection│ │Detection │ │Threat Mdl │ │CrowdStrike│  │
│  │Asset    │ │Asset Mgmt│ │Detection  │ │Qualys     │  │
│  │ThreatInt│ │Threat Int│ │Compliance │ │Tenable    │  │
│  │Complianc│ │Compliance│ │Asset Disc │ │Snyk       │  │
│  │AppSec   │ │Log Optim │ │Log Anlysis│ │Sentinel   │  │
│  │Identity │ │Identity  │ │Identity   │ │Jira       │  │
│  │LogOptim │ │AppSec    │ │           │ │ServiceNow │  │
│  └─────────┘ └──────────┘ └───────────┘ └───────────┘  │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                OpenClaw (Autonomous Agent Runtime)        │
│  Gateway · Agent Runtime · Memory · Channels · Plugin SDK│
└──────────────────────────────────────────────────────────┘
```

## Core Capabilities

### 1. Vulnerability Management
Triage millions of vulnerabilities at machine speed. Automatically classify exploitability, correlate with asset context, eliminate false positives, and generate remediation steps.

### 2. Application Security (SAST/SCA)
Analyze static analysis and software composition findings. Filter noise, identify true-positive exploitable paths, and produce developer-ready fix guidance.

### 3. Detection Engineering
Generate, tune, and validate detection rules across your SIEM. Reduce alert fatigue by optimizing signal-to-noise ratio based on your environment's baseline.

### 4. Asset Management
Continuously discover, enrich, and map asset ownership — including shadow IT and OT devices. Build a living asset inventory that feeds into every other security function.

### 5. Threat Intelligence
Ingest, distill, and operationalize threat intelligence. Map TTPs to your environment's exposure surface and generate actionable defense recommendations.

### 6. Compliance Automation
Map controls to frameworks (NIST, ISO 27001, SOC 2, etc.), automate evidence collection, identify gaps, and generate audit-ready documentation.

### 7. Identity Security
Analyze IAM configurations, detect excessive privileges, generate least-privilege policies, and audit identity-related risks across cloud and on-premise environments.

### 8. Log Optimization
Analyze log pipelines to identify redundant, non-security data. Route low-value logs to cold storage, reducing SIEM costs while preserving detection coverage.

### 9. Threat Modeling
Automatically generate threat models for applications and infrastructure. Map to MITRE ATT&CK, STRIDE, or custom frameworks in minutes instead of weeks.

## Quick Start

### Prerequisites

- [OpenClaw](https://github.com/nicepkg/openclaw) installed and running
- Node.js 20+
- An LLM API key (Claude, OpenAI, etc.)

### Installation

```bash
# Clone OpenKai
git clone https://github.com/your-org/openkai.git
cd openkai

# Run the setup script — this configures OpenClaw as a security agent
./setup.sh

# Or install manually
./setup.sh --openclaw-path /path/to/your/openclaw
```

### Configuration

```bash
# Copy the environment template
cp .env.example .env

# Edit with your API keys and connector credentials
# Then apply the configuration
./setup.sh --apply-config
```

### Start

```bash
# Start the OpenKai-configured OpenClaw gateway
cd /path/to/openclaw
openclaw gateway
```

The commander agent will be available on all configured channels (Slack, Discord, Teams, etc.) and via the WebChat UI.

## Project Structure

```
openkai/
├── config/                    # OpenClaw configuration overlay
│   └── openkai.yaml          # Main config — agents, plugins, identity
├── agents/                    # Agent definitions & system prompts
│   ├── openkai-commander/    # Orchestrator agent (routes & coordinates)
│   ├── vuln-analyst/         # Vulnerability management specialist
│   ├── detection-engineer/   # Detection rule engineering
│   ├── asset-manager/        # Asset discovery & enrichment
│   ├── threat-intel/         # Threat intelligence analysis
│   ├── compliance-auditor/   # Compliance & audit automation
│   ├── appsec-analyst/       # AppSec (SAST/SCA) analysis
│   ├── identity-guardian/    # Identity & access security
│   └── log-optimizer/        # Log pipeline optimization
├── extensions/                # OpenClaw plugins (tools & hooks)
│   ├── openkai-core/         # Core runtime, shared utilities, i18n
│   ├── openkai-vuln/         # Vulnerability management tools
│   ├── openkai-detection/    # Detection engineering tools
│   ├── openkai-assets/       # Asset management tools
│   ├── openkai-threat-intel/ # Threat intelligence tools
│   ├── openkai-compliance/   # Compliance automation tools
│   ├── openkai-log-optimizer/# Log optimization tools
│   ├── openkai-identity/     # Identity security tools
│   └── openkai-appsec/       # Application security tools
├── skills/                    # Pre-built security skills
├── connectors/                # Open-source integrations
│   ├── splunk/               # Splunk SIEM connector
│   ├── elastic/              # Elasticsearch/Kibana connector
│   ├── sentinel/             # Microsoft Sentinel connector
│   ├── crowdstrike/          # CrowdStrike EDR connector
│   ├── qualys/               # Qualys vulnerability scanner
│   ├── tenable/              # Tenable/Nessus connector
│   ├── snyk/                 # Snyk SCA/SAST connector
│   ├── github-security/      # GitHub Advanced Security connector
│   ├── jira/                 # Jira issue tracking connector
│   ├── servicenow/           # ServiceNow ITSM connector
│   └── ...                   # Community-contributed connectors
├── i18n/                      # Internationalization
│   ├── en.json               # English (default)
│   └── es.json               # Spanish
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
├── setup.sh                   # One-command installer
└── .env.example              # Environment variable template
```

## Connectors

Connectors are the integration layer between OpenKai and your existing security stack. They are designed to be:

- **Open-source** — anyone can contribute a connector
- **Standardized** — consistent interface across all integrations
- **Composable** — enable only what you need
- **Bidirectional** — read from and write to external systems

### Available Connectors

| Category | Connectors |
|----------|-----------|
| **SIEM/Log** | Splunk, Elastic/Kibana, Microsoft Sentinel |
| **EDR/XDR** | CrowdStrike, Microsoft Defender |
| **Vulnerability** | Qualys, Tenable/Nessus, Wiz, Orca |
| **AppSec** | Snyk, Semgrep, SonarQube, GitHub Advanced Security |
| **ITSM** | Jira, ServiceNow |
| **Cloud** | AWS Security Hub, Azure Security Center, GCP SCC |

### Contributing a Connector

See [docs/contributing-connectors.md](docs/contributing-connectors.md) for the connector development guide.

## Customization

OpenKai is designed to be customized by every security team for their own environment. Use any AI coding agent (Claude Code, OpenAI Codex, etc.) to:

1. **Add custom tools** — wrap your internal APIs as OpenClaw tools
2. **Create new agents** — define specialist agents for your unique workflows
3. **Build connectors** — integrate with your proprietary security tools
4. **Extend skills** — package reusable security analysis patterns
5. **Tune prompts** — adjust agent system prompts for your threat landscape

### Example: Add a Custom Vulnerability Source

```typescript
// extensions/my-vuln-source/index.ts
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

export default {
  id: "my-vuln-source",
  name: "My Vulnerability Source",
  register(api: OpenClawPluginApi) {
    api.registerTool({
      name: "fetch_vulns_from_internal_scanner",
      label: "Fetch Internal Scanner Vulns",
      description: "Pull vulnerabilities from our internal scanning platform",
      parameters: Type.Object({
        severity: Type.Optional(Type.String()),
        limit: Type.Optional(Type.Number({ default: 100 })),
      }),
      async execute(_id, params) {
        const response = await fetch("https://scanner.internal/api/v1/vulns", {
          headers: { Authorization: `Bearer ${process.env.SCANNER_TOKEN}` },
        });
        const vulns = await response.json();
        return {
          content: [{ type: "text", text: JSON.stringify(vulns, null, 2) }],
        };
      },
    });
  },
};
```

## Philosophy

### Why Open-Source Security Agents?

Commercial security platforms are built on a premise that is becoming obsolete: that security teams cannot build their own tools. With the rise of agentic AI and AI coding assistants, this is no longer true. A senior security engineer with Claude Code can now build, in hours, what used to require a product team and months of development.

**OpenKai embodies this shift.** We believe:

1. **Security teams should own their platform.** Your security posture is too important to outsource to a vendor's one-size-fits-all product. Your environment is unique — your security agent should be too.

2. **AI agents should be transparent.** When an AI agent makes a security decision (triage a vulnerability, suppress an alert, generate a detection rule), you need to understand *why*. Open-source is the only way to guarantee this.

3. **The community is smarter than any vendor.** Security connectors, detection rules, threat models, and analysis patterns should be shared openly. A connector contributed by a Splunk expert benefits every OpenKai user.

4. **AI-powered customization changes everything.** With Claude Code or Codex, a security engineer can say "add a connector for our internal CMDB" and have it working in an afternoon. This was impossible before; now it's the expected workflow.

### OpenKai vs. Commercial Platforms

| Aspect | Commercial (e.g., Kai.security) | OpenKai |
|--------|-------------------------------|---------|
| **Customization** | Limited to vendor's API | Unlimited — full source access |
| **Data sovereignty** | Vendor-hosted or hybrid | Fully self-hosted |
| **Vendor lock-in** | High | None |
| **Cost** | $100K+/year enterprise license | Free (you run it) |
| **Speed to customize** | Weeks (feature requests) | Hours (AI-assisted development) |
| **Community** | Closed ecosystem | Open connector & skill marketplace |
| **Transparency** | Black box AI decisions | Full auditability |

## Internationalization (i18n)

OpenKai supports multiple languages. Currently available:

- **English** (en) — default
- **Spanish** (es)

Agent responses, tool descriptions, and UI strings are all localizable. See [i18n/](i18n/) for translation files.

## Contributing

We welcome contributions in all areas:

- **Connectors** — integrate with more security tools
- **Skills** — package reusable security analysis patterns
- **Agents** — specialized agents for niche security domains
- **Translations** — help us reach more security teams worldwide
- **Documentation** — tutorials, guides, and examples

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

**OpenKai** is built for the security teams who refuse to wait for vendors to solve their problems. If that's you, start building.
