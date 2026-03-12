#!/usr/bin/env bash
# =============================================================================
# OpenKai Setup Script
# =============================================================================
# Transforms an OpenClaw installation into an OpenKai cybersecurity agent.
#
# Usage:
#   ./setup.sh                              # Auto-detect OpenClaw in ../openclaw
#   ./setup.sh --openclaw-path /path/to/oc  # Specify OpenClaw path
#   ./setup.sh --apply-config               # Apply config only (skip symlinks)
#   ./setup.sh --uninstall                  # Remove OpenKai overlay
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

OPENKAI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCLAW_PATH=""
APPLY_ONLY=false
UNINSTALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --openclaw-path)
      OPENCLAW_PATH="$2"
      shift 2
      ;;
    --apply-config)
      APPLY_ONLY=true
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    -h|--help)
      echo "Usage: ./setup.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --openclaw-path PATH   Path to OpenClaw installation"
      echo "  --apply-config         Apply config only (skip extension symlinks)"
      echo "  --uninstall            Remove OpenKai overlay from OpenClaw"
      echo "  -h, --help             Show this help"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      exit 1
      ;;
  esac
done

# Auto-detect OpenClaw
if [[ -z "$OPENCLAW_PATH" ]]; then
  # Check common locations
  for candidate in \
    "$OPENKAI_DIR/../openclaw" \
    "$HOME/.openclaw" \
    "$(command -v openclaw 2>/dev/null | xargs dirname 2>/dev/null)/.." \
  ; do
    if [[ -d "$candidate" && (-f "$candidate/package.json" || -f "$candidate/openclaw.mjs") ]]; then
      OPENCLAW_PATH="$(cd "$candidate" && pwd)"
      break
    fi
  done
fi

if [[ -z "$OPENCLAW_PATH" ]]; then
  echo -e "${RED}Error: Could not find OpenClaw installation.${NC}"
  echo "Please specify the path: ./setup.sh --openclaw-path /path/to/openclaw"
  exit 1
fi

echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          OpenKai Setup v0.1.0            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "OpenKai source: ${GREEN}$OPENKAI_DIR${NC}"
echo -e "OpenClaw path:  ${GREEN}$OPENCLAW_PATH${NC}"
echo ""

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if $UNINSTALL; then
  echo -e "${YELLOW}Removing OpenKai overlay...${NC}"

  # Remove symlinked extensions
  if [[ -d "$OPENCLAW_PATH/.openclaw/extensions" ]]; then
    for ext in "$OPENCLAW_PATH/.openclaw/extensions/openkai-"* "$OPENCLAW_PATH/.openclaw/extensions/connector-"*; do
      if [[ -L "$ext" ]]; then
        echo "  Removing symlink: $(basename "$ext")"
        rm "$ext"
      fi
    done
  fi

  # Remove agent directories
  if [[ -d "$OPENCLAW_PATH/agents" ]]; then
    for agent in openkai-commander vuln-analyst detection-engineer asset-manager threat-intel compliance-auditor appsec-analyst identity-guardian log-optimizer; do
      if [[ -L "$OPENCLAW_PATH/agents/$agent" ]]; then
        echo "  Removing agent: $agent"
        rm "$OPENCLAW_PATH/agents/$agent"
      fi
    done
  fi

  echo -e "${GREEN}OpenKai overlay removed. OpenClaw is back to default.${NC}"
  exit 0
fi

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Step 1: Create directories
echo -e "${BLUE}[1/4] Creating directories...${NC}"
mkdir -p "$OPENCLAW_PATH/.openclaw/extensions"
mkdir -p "$OPENCLAW_PATH/agents"

# Step 2: Symlink extensions
if ! $APPLY_ONLY; then
  echo -e "${BLUE}[2/4] Linking OpenKai extensions...${NC}"

  # Core extensions
  for ext_dir in "$OPENKAI_DIR"/extensions/*/; do
    ext_name="$(basename "$ext_dir")"
    target="$OPENCLAW_PATH/.openclaw/extensions/$ext_name"
    if [[ -L "$target" ]]; then
      rm "$target"
    fi
    if [[ ! -e "$target" ]]; then
      ln -s "$ext_dir" "$target"
      echo -e "  ${GREEN}✓${NC} $ext_name"
    else
      echo -e "  ${YELLOW}⊘${NC} $ext_name (already exists, skipped)"
    fi
  done

  # Connector extensions
  for conn_dir in "$OPENKAI_DIR"/connectors/*/; do
    conn_name="connector-$(basename "$conn_dir")"
    target="$OPENCLAW_PATH/.openclaw/extensions/$conn_name"
    if [[ -L "$target" ]]; then
      rm "$target"
    fi
    if [[ ! -e "$target" ]]; then
      ln -s "$conn_dir" "$target"
      echo -e "  ${GREEN}✓${NC} $conn_name"
    else
      echo -e "  ${YELLOW}⊘${NC} $conn_name (already exists, skipped)"
    fi
  done

  # Step 3: Symlink agents
  echo -e "${BLUE}[3/4] Linking OpenKai agents...${NC}"
  for agent_dir in "$OPENKAI_DIR"/agents/*/; do
    agent_name="$(basename "$agent_dir")"
    target="$OPENCLAW_PATH/agents/$agent_name"
    if [[ -L "$target" ]]; then
      rm "$target"
    fi
    if [[ ! -e "$target" ]]; then
      ln -s "$agent_dir" "$target"
      echo -e "  ${GREEN}✓${NC} $agent_name"
    else
      echo -e "  ${YELLOW}⊘${NC} $agent_name (already exists, skipped)"
    fi
  done
else
  echo -e "${BLUE}[2/4] Skipping extension links (--apply-config)${NC}"
  echo -e "${BLUE}[3/4] Skipping agent links (--apply-config)${NC}"
fi

# Step 4: Copy config
echo -e "${BLUE}[4/4] Applying configuration...${NC}"
OPENCLAW_CONFIG="$HOME/.openclaw/config.yaml"
if [[ -f "$OPENCLAW_CONFIG" ]]; then
  BACKUP="$OPENCLAW_CONFIG.backup.$(date +%Y%m%d%H%M%S)"
  cp "$OPENCLAW_CONFIG" "$BACKUP"
  echo -e "  ${YELLOW}Backed up existing config to: $BACKUP${NC}"
fi
mkdir -p "$HOME/.openclaw"
cp "$OPENKAI_DIR/config/openkai.yaml" "$OPENCLAW_CONFIG"
echo -e "  ${GREEN}✓${NC} Config written to $OPENCLAW_CONFIG"

# Step 5: Env file
if [[ ! -f "$OPENKAI_DIR/.env" ]]; then
  echo ""
  echo -e "${YELLOW}Note: No .env file found.${NC}"
  echo -e "Copy the template and add your credentials:"
  echo -e "  cp $OPENKAI_DIR/.env.example $OPENKAI_DIR/.env"
fi

# Done
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      OpenKai setup complete! 🛡️          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Configure your .env file: ${BLUE}cp .env.example .env${NC}"
echo -e "  2. Enable connectors in config: ${BLUE}$OPENCLAW_CONFIG${NC}"
echo -e "  3. Start OpenClaw: ${BLUE}cd $OPENCLAW_PATH && openclaw gateway${NC}"
echo ""
echo -e "The OpenKai commander agent is ready on all configured channels."
