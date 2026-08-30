#!/usr/bin/env bash
#
# NZINGA install helper.
#
# Builds nzinga from source and installs it with an icon and desktop entry.
#   ./install.sh            user install (default, no root required)
#   ./install.sh --system   system-wide install under /usr/local (may need sudo)
#   ./install.sh --help     usage
#
# Alternatively use the Makefile targets directly:
#   make install        # system-wide (/usr/local)
#   make install-user   # per-user (~/.local)
set -euo pipefail

FAIL='\033[31m'
GREEN='\033[32m'
CYAN='\033[36m'
NC='\033[0m'

fail() { echo -e "${FAIL}[ERROR]${NC} $*" >&2; exit 1; }
log()  { echo -e "${CYAN}[NZINGA]${NC} $*"; }
pass() { echo -e "${GREEN}  ok${NC}  $*"; }

MODE="user"

usage() {
  echo "Usage: $0 [--system] [--help]"
  echo "  --system   install system-wide under /usr/local"
  echo "  (default)  install per-user under ~/.local"
  echo ""
  echo "Installs: nzinga binary, share icon, and desktop entry."
}

while [ $# -gt 0 ]; do
  case "$1" in
    --system) MODE="system"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown option: $1 (try --help)" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log "Building nzinga from source..."
make build || fail "build failed"

if [ "$MODE" = "system" ]; then
  log "Installing nzinga system-wide (/usr/local)..."
  make install
else
  log "Installing nzinga for user ($HOME/.local)..."
  make install-user
fi

pass "nzinga installed. Run 'nzinga version' to verify."
echo ""
echo "Next steps:"
echo "  nzinga                     start the interactive console"
echo "  nzinga assess --sim        run the discovery->report pipeline against the offline demo"
echo "  nzinga assess -y domain:example.com    assess an authorized live domain"