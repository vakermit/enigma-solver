#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v uv &>/dev/null; then
    echo "uv not found. Install it: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

echo "Creating virtual environment..."
uv venv .venv

echo "Installing dependencies..."
uv pip install --python .venv/bin/python -r requirements.txt

echo ""
echo "Done. Activate with:"
echo "  source .venv/bin/activate"
echo ""
echo "Then run:"
echo "  python esolve.py --help"
