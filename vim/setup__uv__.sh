#!/usr/bin/env bash
set -euo pipefail

#
# Unified Python Development Environment Setup
# ---------------------------------------------
# Supports: Pyenv + Pipenv  OR  Pyenv + UV
# Includes: Neovim integration, linting, python-ev, asyncio tooling
#
# Works on Ubuntu and macOS.
#

PY_VERSION="3.11.9"
PROJECT_NAME="myproject"
PROJECT_DIR="$HOME/dev/$PROJECT_NAME"

echo "==============================================================="
echo "Python Development Environment Setup"
echo "==============================================================="

#--- Detect OS --------------------------------------------------------------
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/os-release && $(grep -i ubuntu /etc/os-release) ]]; then
    OS="ubuntu"
else
    echo "Unsupported OS. Only Ubuntu and macOS supported."
    exit 1
fi
echo "Detected OS: $OS"

#--- Install system dependencies -------------------------------------------
echo "Installing system dependencies..."
if [[ "$OS" == "ubuntu" ]]; then
    sudo apt update -y
    sudo apt install -y \
        git curl build-essential libssl-dev zlib1g-dev \
        libbz2-dev libreadline-dev libsqlite3-dev wget llvm \
        libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev \
        libffi-dev liblzma-dev python3-pip python3-venv \
        neovim exuberant-ctags ack-grep
elif [[ "$OS" == "macos" ]]; then
    brew update
    brew install git curl openssl readline sqlite3 xz zlib neovim
fi

#--- Install pyenv ----------------------------------------------------------
if [ ! -d "$HOME/.pyenv" ]; then
    echo "Installing pyenv..."
    curl https://pyenv.run | bash
fi

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

#--- Install requested Python version --------------------------------------
if ! pyenv versions | grep -q "$PY_VERSION"; then
    echo "Installing Python $PY_VERSION..."
    env PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install "$PY_VERSION"
fi
pyenv global "$PY_VERSION"
pyenv rehash

echo "Using Python: $(python --version)"

#--- Ask user for environment manager --------------------------------------
echo
echo "Choose Python environment manager:"
echo "1) pipenv  (classic)"
echo "2) uv      (modern ultrafast package manager)"
read -rp "Select [1-2]: " ENV_CHOICE

mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"
pyenv local "$PY_VERSION"

#--- Common dependencies ----------------------------------------------------
DEV_PACKAGES=(neovim flake8 pylint isort black msgpack pynvim bpython ipython python-ev)

#--- Option 1: Pipenv -------------------------------------------------------
if [[ "$ENV_CHOICE" == "1" ]]; then
    echo "Installing Pipenv..."
    pip install --user pipenv
    export PATH="$HOME/.local/bin:$PATH"

    echo "Creating Pipenv environment..."
    pipenv --python "$(pyenv which python)"
    pipenv install --dev "${DEV_PACKAGES[@]}"

    ACTIVATE_CMD="pipenv shell --fancy"
    NVIM_CMD="pipenv run nvim ."

#--- Option 2: UV -----------------------------------------------------------
elif [[ "$ENV_CHOICE" == "2" ]]; then
    echo "Installing UV..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"

    echo "Creating UV project..."
    uv init "$PROJECT_NAME" --python "$(pyenv which python)"
    cd "$PROJECT_NAME"

    echo "Installing dev packages with UV..."
    uv add --dev "${DEV_PACKAGES[@]}"

    ACTIVATE_CMD="source .venv/bin/activate"
    NVIM_CMD="uv run nvim ."
else
    echo "Invalid option."
    exit 1
fi

#--- Neovim configuration ---------------------------------------------------
mkdir -p "$HOME/.config/nvim"
cat > "$HOME/.config/nvim/init.vim" <<'EOVIM'
" Neovim Python IDE configuration

set nocompatible
set number
set relativenumber
syntax on
filetype plugin indent on

if has('nvim')
  let g:python3_host_prog = expand('~/.local/share/virtualenvs/*/bin/python')
endif

if empty(glob('~/.local/share/nvim/site/autoload/plug.vim'))
  silent !curl -fLo ~/.local/share/nvim/site/autoload/plug.vim --create-dirs \
       https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
endif

call plug#begin('~/.local/share/nvim/plugged')
Plug 'dense-analysis/ale'
Plug 'neoclide/coc.nvim', {'branch': 'release'}
Plug 'tpope/vim-fugitive'
Plug 'jiangmiao/auto-pairs'
Plug 'preservim/nerdtree'
call plug#end()

let g:ale_linters = {'python': ['flake8', 'pylint']}
let g:ale_fixers = {'python': ['black', 'isort']}
let g:ale_fix_on_save = 1
nmap <C-n> :NERDTreeToggle<CR>
EOVIM

#--- Summary ---------------------------------------------------------------
echo
echo "==============================================================="
echo "Setup Complete"
echo "---------------------------------------------------------------"
echo "Project Directory: $PROJECT_DIR"
echo "Python: $(pyenv version-name)"
echo "Virtualenv Manager: ${ENV_CHOICE:-pipenv}"
echo
echo "To activate your environment:"
echo "  cd $PROJECT_DIR"
echo "  $ACTIVATE_CMD"
echo
echo "To open Neovim with project environment:"
echo "  $NVIM_CMD"
echo "---------------------------------------------------------------"
echo "Installed dev packages:"
printf '  - %s\n' "${DEV_PACKAGES[@]}"
echo "==============================================================="

##
##
