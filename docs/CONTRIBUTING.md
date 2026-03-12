# Contributing to OpenKai

Thank you for your interest in making enterprise security teams more autonomous. OpenKai is built by and for the security community.

## Ways to Contribute

### Connectors
Integrate OpenKai with more security tools. See [contributing-connectors.md](contributing-connectors.md) for the detailed guide.

### Skills
Package reusable security analysis patterns as skills. A good skill includes expert-level methodology that agents can follow.

### Agents
Create specialized agents for niche security domains not yet covered (e.g., cloud security posture, API security, mobile security).

### Translations
Help us reach more security teams worldwide. Add translations to `i18n/` for your language.

### Documentation
Tutorials, guides, examples, and use case write-ups are always welcome.

### Bug Fixes & Improvements
Check the issue tracker for open issues, or report new ones.

## Development Setup

```bash
# Clone OpenKai and OpenClaw
git clone https://github.com/openkai-security/openkai.git
git clone https://github.com/openclaw/openclaw.git

# Set up OpenClaw
cd openclaw
pnpm install

# Set up OpenKai overlay
cd ../openkai
./setup.sh --openclaw-path ../openclaw

# Configure and start
cp .env.example .env
# Edit .env with your API keys
cd ../openclaw
openclaw gateway --verbose
```

## Code Standards

- **TypeScript** for all extensions and connectors
- **`@sinclair/typebox`** for tool parameter schemas
- Tool names: `snake_case`, prefixed by domain
- Plugin IDs: `kebab-case`
- Keep extensions stateless where possible

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add tests if applicable
5. Ensure all existing tests pass
6. Submit a pull request

## Code of Conduct

Be respectful, constructive, and collaborative. We're all here to make security better.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
