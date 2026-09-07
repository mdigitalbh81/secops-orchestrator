#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
TARGET="${INSTALL_DIR}/secops"
SOURCE="${REPO_ROOT}/secops"

mkdir -p "$INSTALL_DIR"
chmod +x "$SOURCE"

ln -sf "$SOURCE" "$TARGET"
echo "SecOps CLI installed to $TARGET"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Warning: $INSTALL_DIR is not in your PATH."
    echo "Add it by running:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo "or adding it to your ~/.bashrc or ~/.zshrc."
fi
