#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# vim bootstrap: vim-plug + .vimrc
# -----------------------------

# Print a useful error on failure
on_err() {
  local exit_code=$?
  printf '✗ Error: command failed (exit=%s) at line %s: %s\n' \
    "$exit_code" "${BASH_LINENO[0]}" "${BASH_COMMAND}" >&2
  exit "$exit_code"
}
trap on_err ERR

# --- Colors (auto-disable if not a TTY) ---
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  NC="$(tput sgr0)"
else
  RED="" GREEN="" YELLOW="" NC=""
fi

info()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*"; }
error() { printf '%s[✗]%s %s\n' "$RED" "$NC" "$*" >&2; }

# --- Config ---
VIMRC_PATH="${HOME}/.vimrc"
VIM_DIR="${HOME}/.vim"
AUTOLOAD_DIR="${VIM_DIR}/autoload"
PLUGGED_DIR="${VIM_DIR}/plugged"
PLUG_VIM="${AUTOLOAD_DIR}/plug.vim"
PLUG_URL="https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim"

# --- Dependency checks ---
check_dependencies() {
  local -a missing=()
  local -a required=(curl vim)

  for cmd in "${required[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done

  if ((${#missing[@]} > 0)); then
    error "Missing required dependencies: ${missing[*]}"
    error "Install them and re-run."
    exit 1
  fi
}

backup_config() {
  if [[ -f "$VIMRC_PATH" ]]; then
    local backup_file="${VIMRC_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
    warn "Existing .vimrc found; backing up to: $backup_file"
    cp -p -- "$VIMRC_PATH" "$backup_file"
  fi
}

ensure_dirs() {
  info "Ensuring Vim directories exist..."
  mkdir -p -- "$AUTOLOAD_DIR" "$PLUGGED_DIR"
}

install_vim_plug() {
  if [[ -s "$PLUG_VIM" ]]; then
    info "vim-plug already present: $PLUG_VIM"
    return 0
  fi

  info "Installing vim-plug..."
  curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10 \
    -o "$PLUG_VIM" "$PLUG_URL"
}

write_vimrc() {
  info "Writing $VIMRC_PATH ..."
  umask 077
  cat > "$VIMRC_PATH" <<'EOF'
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

" NOTE: 'invfullscreen' is not a standard Vim option and may error on many builds.
" Keeping your mapping, but be aware it may not work everywhere.
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
}

install_plugins() {
  info "Installing Vim plugins (headless)..."
  # -E  : improved Ex mode
  # -s  : silent
  # -u  : use our vimrc explicitly (avoids weird env surprises)
  # +qa : quit all
  vim -Es -u "$VIMRC_PATH" +PlugInstall +qall
}

main() {
  info "Checking dependencies..."
  check_dependencies

  backup_config
  ensure_dirs
  install_vim_plug
  write_vimrc
  install_plugins

  info "✓ Setup complete! Vim is configured."
  info "Open Vim to verify plugins + theme."
}

main "$@"
