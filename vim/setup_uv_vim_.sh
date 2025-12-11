#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $1"; }
step() { echo -e "${BLUE}[→]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "================================================================"
echo "  Modern Vim/Neovim + UV Python Setup"
echo "================================================================"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
  info "Detected: macOS"
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS="linux"
  info "Detected: Linux"
fi

# Install Neovim (recommended)
info "Installing Neovim..."
if [[ "$OS" == "macos" ]]; then
  brew install neovim
elif [[ "$OS" == "linux" ]]; then
  sudo apt update
  sudo apt install -y neovim
fi

# Ensure UV is installed
if ! command -v uv &> /dev/null; then
  info "Installing UV..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.cargo/bin:$PATH"
else
  info "UV already installed"
fi

# Install Python with UV
info "Installing Python 3.12 with UV..."
uv python install 3.12 2>/dev/null || true

# Create global Python environment for Neovim
info "Creating Neovim Python environment..."
mkdir -p ~/.config/nvim-python
cd ~/.config/nvim-python

# Initialize UV project for Neovim
uv init --name nvim-python --python 3.12 2>/dev/null || true

# Install Neovim Python provider
uv add pynvim msgpack

# Get Python path for Neovim config
PYTHON_PATH="$HOME/.config/nvim-python/.venv/bin/python"

# Setup Neovim config
info "Configuring Neovim..."
mkdir -p ~/.config/nvim

# Backup existing config
if [[ -f ~/.config/nvim/init.vim ]]; then
  cp ~/.config/nvim/init.vim ~/.config/nvim/init.vim.backup.$(date +%Y%m%d_%H%M%S)
fi

# Create modern init.lua (better than init.vim)
cat > ~/.config/nvim/init.lua <<EOF
-- Neovim Configuration with UV Python Support
-- Generated: $(date)

-- Set Python provider
vim.g.python3_host_prog = '$PYTHON_PATH'

-- Basic settings
vim.opt.number = true
vim.opt.relativenumber = true
vim.opt.tabstop = 4
vim.opt.shiftwidth = 4
vim.opt.expandtab = true
vim.opt.smartindent = true
vim.opt.termguicolors = true

-- Bootstrap lazy.nvim plugin manager
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git",
    "clone",
    "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable",
    lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

-- Plugin setup
require("lazy").setup({
  -- LSP Support
  {
    'neovim/nvim-lspconfig',
    dependencies = {
      'williamboman/mason.nvim',
      'williamboman/mason-lspconfig.nvim',
    },
  },
  
  -- Autocompletion
  {
    'hrsh7th/nvim-cmp',
    dependencies = {
      'hrsh7th/cmp-nvim-lsp',
      'hrsh7th/cmp-buffer',
      'hrsh7th/cmp-path',
      'L3MON4D3/LuaSnip',
    },
  },
  
  -- Python support
  { 'Vimjas/vim-python-pep8-indent' },
  
  -- File explorer
  { 'nvim-tree/nvim-tree.lua', dependencies = { 'nvim-tree/nvim-web-devicons' } },
  
  -- Fuzzy finder
  { 'nvim-telescope/telescope.nvim', dependencies = { 'nvim-lua/plenary.nvim' } },
  
  -- Status line
  { 'nvim-lualine/lualine.nvim', dependencies = { 'nvim-tree/nvim-web-devicons' } },
  
  -- Color scheme
  { 'folke/tokyonight.nvim' },
  
  -- Git integration
  { 'lewis6991/gitsigns.nvim' },
  
  -- Syntax highlighting
  { 'nvim-treesitter/nvim-treesitter', build = ':TSUpdate' },
})

-- Color scheme
vim.cmd[[colorscheme tokyonight-night]]

-- Key mappings
vim.g.mapleader = ","
vim.keymap.set('n', '<leader>e', ':NvimTreeToggle<CR>')
vim.keymap.set('n', '<leader>ff', ':Telescope find_files<CR>')
vim.keymap.set('n', '<leader>fg', ':Telescope live_grep<CR>')

-- LSP setup
require('mason').setup()
require('mason-lspconfig').setup({
  ensure_installed = { 'pyright', 'ruff_lsp' }
})

-- Python LSP
require('lspconfig').pyright.setup{}
require('lspconfig').ruff_lsp.setup{}

-- Autocompletion
local cmp = require('cmp')
cmp.setup({
  mapping = cmp.mapping.preset.insert({
    ['<C-Space>'] = cmp.mapping.complete(),
    ['<CR>'] = cmp.mapping.confirm({ select = true }),
  }),
  sources = {
    { name = 'nvim_lsp' },
    { name = 'buffer' },
    { name = 'path' },
  },
})

-- Status line
require('lualine').setup()

-- File explorer
require('nvim-tree').setup()

-- Git signs
require('gitsigns').setup()

-- Treesitter
require('nvim-treesitter.configs').setup({
  ensure_installed = { "python", "lua", "vim", "bash" },
  highlight = { enable = true },
})
EOF

# Create helper script for project setup
cat > ~/.local/bin/setup-nvim-project <<'SCRIPT'
#!/usr/bin/env bash
set -e

PROJECT_DIR="${1:-.}"
cd "$PROJECT_DIR"

echo "Setting up Neovim for UV project..."

# Ensure UV project exists
if [[ ! -f "pyproject.toml" ]]; then
  uv init
fi

# Add development tools
uv add --dev python-lsp-server pylsp-mypy pyls-isort

# Create nvim project config
mkdir -p .nvim
cat > .nvim/init.lua <<EOF
-- Project-specific Neovim config
vim.opt.tabstop = 4
vim.opt.shiftwidth = 4
EOF

echo "✓ Done! Open with: nvim ."
SCRIPT

chmod +x ~/.local/bin/setup-nvim-project

# Shell config
SHELL_RC="$HOME/.zshrc"
[[ "$SHELL" == *"bash"* ]] && SHELL_RC="$HOME/.bashrc"

# Add to PATH
if ! grep -q '.local/bin' "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
fi

if ! grep -q '.cargo/bin' "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$SHELL_RC"
fi

echo
echo "================================================================"
echo "  ✓ Setup Complete!"
echo "================================================================"
echo "Neovim:      $(nvim --version | head -1)"
echo "UV:          $(uv --version)"
echo "Python:      $PYTHON_PATH"
echo
echo "Quick Start:"
echo "  1. exec \$SHELL                    # Reload shell"
echo "  2. mkdir ~/myproject && cd ~/myproject"
echo "  3. uv init                         # Create UV project"
echo "  4. setup-nvim-project              # Setup Neovim for project"
echo "  5. nvim .                          # Open Neovim"
echo
echo "First Time Setup (in Neovim):"
echo "  - Plugins will auto-install on first launch"
echo "  - Wait for completion"
echo "  - Restart Neovim: :qa then nvim ."
echo
echo "Verify Python Support:"
echo "  nvim -c 'checkhealth provider' -c 'qa'"
echo
echo "Key Bindings:"
echo "  ,e          - Toggle file explorer"
echo "  ,ff         - Find files"
echo "  ,fg         - Live grep"
echo "  gd          - Go to definition"
echo "  K           - Show hover docs"
echo "================================================================"
