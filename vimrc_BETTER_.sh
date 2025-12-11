#!/usr/bin/env bash

##
##
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }

# Check required dependencies
check_dependencies() {
  local missing=()
  
  for cmd in curl git vim; do
    if ! command -v "$cmd" &> /dev/null; then
      missing+=("$cmd")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing required dependencies: ${missing[*]}"
    error "Please install them and try again."
    exit 1
  fi
}

# Backup existing config
backup_config() {
  if [ -f ~/.vimrc ]; then
    local backup_file=~/.vimrc.backup.$(date +%Y%m%d_%H%M%S)
    warn "Existing .vimrc found, backing up to $backup_file"
    cp ~/.vimrc "$backup_file"
  fi
}

main() {
  info "Checking dependencies..."
  check_dependencies
  
  backup_config
  
  info "Creating ~/.vim/autoload for vim-plug..."
  mkdir -p ~/.vim/autoload ~/.vim/plugged
  
  info "Installing vim-plug..."
  curl -fsSLo ~/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
  
  info "Writing ~/.vimrc..."
  cat > ~/.vimrc <<'EOF'
set nocompatible

call plug#begin('~/.vim/plugged')

Plug 'sheerun/vim-polyglot'
Plug 'dense-analysis/ale'
Plug 'jmcantrell/vim-virtualenv'
Plug 'altercation/vim-colors-solarized'
Plug 'vim-airline/vim-airline'
Plug 'vim-airline/vim-airline-themes'

call plug#end()

filetype plugin indent on
syntax enable

let mapleader = ","

set encoding=utf-8
set number
set ruler
set showmode
set showcmd
set laststatus=2
set ttyfast
set scrolloff=3
set visualbell
set wrap

nnoremap j gj
nnoremap k gk

set textwidth=79
set formatoptions=tcqrn1
set tabstop=2
set shiftwidth=2
set softtabstop=2
set expandtab
set noshiftround

set hlsearch
set incsearch
set ignorecase
set smartcase
set showmatch
nnoremap / /\v
vnoremap / /\v
nnoremap <leader><space> :nohlsearch<CR>

set backspace=indent,eol,start
set matchpairs+=<:>
runtime! macros/matchit.vim

set hidden
set modelines=0

set listchars=tab:▸\ ,eol:¬
nnoremap <leader>l :set list!<CR>

nnoremap <F1> :set invfullscreen<CR>
vnoremap <F1> :set invfullscreen<CR>
inoremap <F1> <ESC>:set invfullscreen<CR>a

nnoremap <leader>q gqip

set t_Co=256
set background=dark
let g:solarized_termcolors=256
let g:solarized_termtrans=1
colorscheme solarized

let g:ale_linters = {
\   'python': ['flake8', 'mypy', 'pylint']
\}
let g:ale_fixers = {
\   'python': ['black', 'isort']
\}
let g:ale_python_flake8_executable = 'flake8'
let g:ale_python_flake8_options = '--max-line-length=88'
let g:ale_python_black_executable = 'black'
let g:ale_fix_on_save = 1

let g:virtualenv_auto_activate = 1
EOF
  
  info "Installing Vim plugins..."
  vim +PlugInstall +qall
  
  info "✓ Setup complete! Your Vim is ready to use."
  info "Restart Vim to see the changes."
}

main "$@"
