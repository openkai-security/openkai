# CLAUDE.md — OpenKai Development Guide

## Project Overview

OpenKai is an open-source overlay that transforms OpenClaw into an agentic AI cybersecurity platform. It does NOT modify OpenClaw source code. Instead, it provides configurations, extensions (plugins), agents, skills, and connectors that OpenClaw loads at runtime.

## Design Philosophy

**Core thesis:** Enterprise security teams should build and operate their own AI security platform using open-source autonomous agents and AI coding assistants — not buy proprietary security products from vendors.

**Key principles:**
1. **Overlay, not fork** — OpenKai configures OpenClaw; it never patches OpenClaw internals.
2. **Composable** — each capability (vuln mgmt, detection, compliance, etc.) is an independent extension. Enable only what you need.
3. **Connector-first** — integrations with security tools (Splunk, CrowdStrike, Qualys, etc.) are first-class citizens, open-source, and community-contributed.
4. **AI-customizable** — the project is designed so that security engineers can use Claude Code, Codex, or similar tools to extend it for their specific environment.
5. **Multi-agent architecture** — specialized agents (vuln-analyst, detection-engineer, etc.) coordinated by a commander agent.

## Architecture

```
openkai/
├── config/openkai.yaml       # Main OpenClaw config overlay
├── agents/                    # Agent definitions (system prompts)
├── extensions/                # OpenClaw plugins (TypeScript)
├── skills/                    # Reusable security analysis skills
├── connectors/                # Integration plugins for security tools
├── i18n/                      # Internationalization (en, es)
├── setup.sh                   # Installer script
└── scripts/                   # Utility scripts
```

## How OpenClaw Extension Works

- **Extensions** are TypeScript plugins registered via `OpenClawPluginApi`. They provide tools, hooks, and services.
- **Agents** are defined in `config/openkai.yaml` under `agents.list[]`. Each has a system prompt in `agents/<id>/system-prompt.md`.
- **Skills** are bundled capabilities declared in extension manifests via `openclaw.skills`.
- **Connectors** are specialized extensions that integrate with external security tools (SIEM, scanners, ITSM, etc.).

## Extension Pattern

Every extension follows this structure:
```
extensions/<name>/
├── index.ts        # Plugin entry — exports { id, name, register(api) }
├── package.json    # Manifest with openclaw config
├── tools/          # Tool implementations (optional)
└── README.md       # Extension docs (optional)
```

Tools are registered via `api.registerTool()`. Hooks via `api.on()`. HTTP routes via `api.registerHttpRoute()`.

## Connector Pattern

Connectors extend the base extension pattern with a standardized interface:
```typescript
interface SecurityConnector {
  id: string;
  type: "siem" | "edr" | "vuln_scanner" | "appsec" | "itsm" | "cloud" | "identity";
  connect(config: ConnectorConfig): Promise<void>;
  disconnect(): Promise<void>;
  query(params: QueryParams): Promise<QueryResult>;
  push?(action: PushAction): Promise<PushResult>;
}
```

## i18n

All user-facing strings go through the i18n system in `i18n/`. Currently: `en.json` (English), `es.json` (Spanish). Extensions access translations via `api.t("key")` or the `t()` helper from `openkai-core`.

## Agent Naming

- `openkai-commander` — orchestrator, routes tasks to specialists
- `vuln-analyst` — vulnerability management
- `detection-engineer` — detection rules, SIEM tuning
- `asset-manager` — asset discovery & enrichment
- `threat-intel` — threat intelligence
- `compliance-auditor` — compliance & audit
- `appsec-analyst` — SAST/SCA analysis
- `identity-guardian` — IAM & identity security
- `log-optimizer` — log pipeline optimization

## Code Conventions

- TypeScript for all extensions
- Use `@sinclair/typebox` for tool parameter schemas
- Import from `openclaw/plugin-sdk/core` for plugin API types
- Connector configs use environment variables with `${VAR}` syntax
- All tool names are snake_case, prefixed by domain (e.g., `vuln_triage`, `detection_generate_rule`)
- Keep extensions stateless where possible; use OpenClaw's memory system for state

## Testing

- Unit tests: `vitest` (mirrors OpenClaw's test setup)
- Integration tests: require running OpenClaw gateway
- Connector tests: mock external APIs unless `--live` flag is set

## Common Tasks

### Add a new connector
1. Create `connectors/<name>/` with `index.ts` and `package.json`
2. Implement the `SecurityConnector` interface
3. Register tools via `api.registerTool()`
4. Add connector config to `config/openkai.yaml`
5. Add environment variables to `.env.example`

### Add a new agent
1. Create `agents/<name>/system-prompt.md`
2. Add agent definition to `config/openkai.yaml` under `agents.list[]`
3. Update commander's system prompt to know about the new specialist

### Add a new skill
1. Create `skills/<name>/` with `index.ts` and `manifest.json`
2. Register in the relevant extension's `package.json` under `openclaw.skills`

### Add translations
1. Add keys to `i18n/en.json`
2. Add translations to `i18n/es.json`
3. Use `t("key")` in extension code
