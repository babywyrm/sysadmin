#!/usr/bin/env bash
set -euo pipefail
##
##

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $1"; }
step() { echo -e "${BLUE}[→]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

PROJECT_NAME="${1:-myproject}"
PROJECT_DIR="$HOME/dev/$PROJECT_NAME"

echo "================================================================"
echo "  UV Python Environment Setup"
echo "================================================================"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
  info "Detected: macOS"
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  if [[ "$ID" == "ubuntu" ]] || [[ "$ID_LIKE" =~ ubuntu|debian ]]; then
    OS="linux"
    info "Detected: Linux ($ID)"
  fi
else
  warn "Unknown OS, continuing anyway..."
  OS="unknown"
fi

# Check if UV is installed
if ! command -v uv &> /dev/null; then
  info "Installing UV..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.cargo/bin:$PATH"
else
  info "UV already installed ($(uv --version))"
  step "Updating UV..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Ensure UV is in PATH for current session
export PATH="$HOME/.cargo/bin:$PATH"

# Add to shell config if not present
if [[ "$OS" == "macos" ]]; then
  SHELL_RC="$HOME/.zshrc"
  [[ "$SHELL" == *"bash"* ]] && SHELL_RC="$HOME/.bash_profile"
elif [[ "$OS" == "linux" ]]; then
  SHELL_RC="$HOME/.bashrc"
  [[ "$SHELL" == *"zsh"* ]] && SHELL_RC="$HOME/.zshrc"
else
  SHELL_RC="$HOME/.profile"
fi

if ! grep -q '.cargo/bin' "$SHELL_RC" 2>/dev/null; then
  info "Adding UV to PATH in $SHELL_RC"
  echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$SHELL_RC"
fi

# Install latest Python with UV
info "Installing Python 3.12 with UV..."
uv python install 3.12 2>/dev/null || warn "Python already installed"

info "Installing Python 3.13 with UV..."
uv python install 3.13 2>/dev/null || warn "Python already installed"

# List available Python versions
step "Available Python versions:"
uv python list

# Create project directory
info "Creating project: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# Initialize UV project with Python 3.12
info "Initializing UV project..."
uv init --name "$PROJECT_NAME" --python 3.12 2>/dev/null || true

# Install common dev tools
info "Installing development tools..."
uv add --dev \
  ipython \
  black \
  ruff \
  pytest \
  mypy

info "Installing common packages..."
uv add \
  requests \
  python-dotenv

# Create example files
info "Creating example files..."

cat > main.py <<'EOF'
#!/usr/bin/env python3
"""Example Python script."""

import requests


def main():
    print("Hello from UV!")
    print(f"Python version: {__import__('sys').version}")
    
    # Test requests
    response = requests.get("https://httpbin.org/get")
    print(f"HTTP Status: {response.status_code}")


if __name__ == "__main__":
    main()
EOF

cat > README.md <<EOF
# $PROJECT_NAME

Python project managed with UV.

## Setup

\`\`\`bash
# Install dependencies
uv sync

# Run the app
uv run python main.py
\`\`\`

## Development

\`\`\`bash
# Add a package
uv add requests

# Add dev dependency
uv add --dev pytest

# Run tests
uv run pytest

# Format code
uv run black .
uv run ruff check .
\`\`\`
EOF

cat > .env.example <<'EOF'
# Environment variables
API_KEY=your_api_key_here
DEBUG=true
EOF

# Create .gitignore
cat > .gitignore <<'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
.venv/
venv/

# UV
.python-version

# Environment
.env

# IDE
.vscode/
.idea/
*.swp
*.swo
EOF

echo
echo "================================================================"
echo "  ✓ Setup Complete!"
echo "================================================================"
echo "Project:     $PROJECT_DIR"
echo "Python:      $(uv run python --version 2>/dev/null || echo 'N/A')"
echo "UV:          $(uv --version)"
echo
echo "Quick Start:"
echo "  cd $PROJECT_DIR"
echo "  uv run python main.py"
echo
echo "Common Commands:"
echo "  uv add <package>           # Add package"
echo "  uv add --dev <package>     # Add dev package"
echo "  uv run python script.py    # Run script"
echo "  uv run ipython             # Interactive shell"
echo "  uv run pytest              # Run tests"
echo "  uv sync                    # Sync dependencies"
echo
echo "Update UV:"
echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
echo
echo "Python Management:"
echo "  uv python list             # List Python versions"
echo "  uv python install 3.13     # Install Python 3.13"
echo "  uv python pin 3.13         # Use Python 3.13 for project"
echo "================================================================"
