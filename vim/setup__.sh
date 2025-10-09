#!/usr/bin/env bash
set -euo pipefail

#
# Unified Development Environment Setup
# --------------------------------------
# pyenv + pipenv + neovim + python/ev support
#
# Works on:
#   - Ubuntu 20.04 / 22.04 / 24.04
#   - macOS (with Homebrew)
#

echo "==============================================================="
echo "Setting up Python + Pyenv + Pipenv + Neovim development stack"
echo "==============================================================="

#--- Detect OS --------------------------------------------------------------
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/os-release && $(grep -i ubuntu /etc/os-release) ]]; then
    OS="ubuntu"
else
    echo "Unsupported OS. Only Ubuntu and macOS are supported."
    exit 1
fi
echo "Detected OS: $OS"

#--- Install system dependencies -------------------------------------------
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

#--- Install pyenv + plugins -----------------------------------------------
if [ ! -d "$HOME/.pyenv" ]; then
    echo "Installing pyenv..."
    curl https://pyenv.run | bash
else
    echo "pyenv already installed."
fi

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# pyenv plugins
mkdir -p "$(pyenv root)/plugins"
[ ! -d "$(pyenv root)/plugins/pyenv-virtualenv" ] && \
    git clone https://github.com/pyenv/pyenv-virtualenv.git "$(pyenv root)/plugins/pyenv-virtualenv"

#--- Install desired Python version ----------------------------------------
PY_VERSION="3.11.9"
if ! pyenv versions | grep -q "$PY_VERSION"; then
    echo "Installing Python $PY_VERSION..."
    env PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install "$PY_VERSION"
fi
pyenv global "$PY_VERSION"
pyenv rehash

echo "Python version:"
python --version

#--- Install Pipenv --------------------------------------------------------
if ! command -v pipenv >/dev/null 2>&1; then
    echo "Installing Pipenv..."
    pip install --user pipenv
fi
export PATH="$HOME/.local/bin:$PATH"

#--- Setup project directory -----------------------------------------------
PROJECT_DIR="$HOME/dev/myproject"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

pyenv local "$PY_VERSION"
echo "pyenv local set to $(pyenv version-name)"

# Create Pipenv environment
pipenv --python "$(pyenv which python)"
pipenv install --dev neovim flake8 pylint isort black msgpack pynvim bpython ipython python-ev

#--- Neovim configuration --------------------------------------------------
mkdir -p "$HOME/.config/nvim"
cat > "$HOME/.config/nvim/init.vim" <<'EOVIM'
" Neovim base configuration for Python projects

set nocompatible
set number
set relativenumber
syntax on
filetype plugin indent on

" Python providers
let g:python3_host_prog = expand('~/.local/share/virtualenvs/*/bin/python')

" Plugins via vim-plug
if empty(glob('~/.local/share/nvim/site/autoload/plug.vim'))
  silent !curl -fLo ~/.local/share/nvim/site/autoload/plug.vim --create-dirs \
       https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
endif

call plug#begin('~/.local/share/nvim/plugged')
Plug 'dense-analysis/ale'              " Linting
Plug 'neoclide/coc.nvim', {'branch': 'release'} " LSP/Completion
Plug 'tpope/vim-fugitive'              " Git integration
Plug 'jiangmiao/auto-pairs'            " Auto-closing brackets
Plug 'preservim/nerdtree'              " File explorer
call plug#end()

" ALE configuration
let g:ale_linters = {'python': ['flake8', 'pylint']}
let g:ale_fixers = {'python': ['black', 'isort']}
let g:ale_fix_on_save = 1

" NERDTree toggle
nmap <C-n> :NERDTreeToggle<CR>

EOVIM

#--- Optional: pipenvwrapper ------------------------------------------------
if [ ! -f "$HOME/.pipenvwrapper" ]; then
    cat > "$HOME/.pipenvwrapper" <<'EOSH'
# Simple Pipenvwrapper functions
workon() {
    local project=$1
    if [ -z "$project" ]; then
        echo "Usage: workon <project_dir>"
        return 1
    fi
    cd "$HOME/dev/$project" || return 1
    pipenv shell --fancy
}
EOSH
    echo "source ~/.pipenvwrapper" >> "$HOME/.bashrc"
fi

#--- Final instructions ----------------------------------------------------
echo
echo "==============================================================="
echo "Setup complete!"
echo "---------------------------------------------------------------"
echo "Project directory: $PROJECT_DIR"
echo "To activate environment:"
echo "  cd $PROJECT_DIR"
echo "  pipenv shell --fancy"
echo
echo "To open Neovim with project virtualenv:"
echo "  pipenv run nvim ."
echo "---------------------------------------------------------------"
echo "Installed Python: $(pyenv version-name)"
echo "Installed via: pyenv + pipenv + neovim + python-ev support"
echo "==============================================================="

##
##
