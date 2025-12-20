#!/bin/bash
# install-ptk.sh - Install Perl Toolkit

set -e

echo "Installing Perl Toolkit (ptk)..."

# Check for Perl
if ! command -v perl &> /dev/null; then
    echo "Error: Perl not found. Please install Perl first."
    exit 1
fi

# Check Perl version
PERL_VERSION=$(perl -e 'print $^V' | sed 's/v//')
REQUIRED_VERSION="5.32.0"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PERL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Perl $REQUIRED_VERSION or higher required (found $PERL_VERSION)"
    exit 1
fi

# Install required modules
echo "Installing required Perl modules..."
cpan -i List::Util Time::Piece JSON::PP

# Install ptk
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

if [ -f "ptk" ]; then
    cp ptk "$INSTALL_DIR/ptk"
    chmod +x "$INSTALL_DIR/ptk"
    echo "✓ Installed to $INSTALL_DIR/ptk"
else
    echo "Error: ptk script not found"
    exit 1
fi

# Check if directory is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "⚠ Warning: $INSTALL_DIR is not in your PATH"
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Installation complete! Run 'ptk help' to get started."
