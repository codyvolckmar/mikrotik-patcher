#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   MikroTik CPE Patch Cycle - Setup                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "   Install Python 3.7+ and try again."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION found"

# Create venv
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate venv
echo "✓ Virtual environment ready"

# Install dependencies
echo "📥 Installing dependencies..."
.venv/bin/pip install -q -r requirements.txt 2>/dev/null || {
    echo "⚠️  Some dependencies may not have installed cleanly, but trying anyway..."
}

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   ✓ Setup Complete!                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To start patching, run:"
echo ""
echo "  python3 patch_cycle.py"
echo ""
echo "Or to test a single device:"
echo ""
echo "  python3 test_patch.py"
echo ""
