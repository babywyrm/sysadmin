#!/bin/bash

set -e

echo "[+] Creating ~/.vim/autoload for vim-plug..."
mkdir -p ~/.vim/autoload ~/.vim/plugged

echo "[+] Installing vim-plug..."
curl -fLo ~/.vim/autoload/plug.vim --create-dirs \
  https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

echo "[+] Writing ~/.vimrc..."
cat <<EOF > ~/.vimrc
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
nnoremap / /\\v
vnoremap / /\\v
nnoremap <leader><space> :nohlsearch<CR>

set backspace=indent,eol,start
set matchpairs+=<:>
runtime! macros/matchit.vim

set hidden
set modelines=0

set listchars=tab:▸\\ ,eol:¬
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
\\   'python': ['flake8', 'mypy', 'pylint']
\\}
let g:ale_fixers = {
\\   'python': ['black', 'isort']
\\}
let g:ale_python_flake8_executable = 'flake8'
let g:ale_python_flake8_options = '--max-line-length=88'
let g:ale_python_black_executable = 'black'
let g:ale_fix_on_save = 1

let g:virtualenv_auto_activate = 1
EOF

echo "[+] Installing Solarized colorscheme for offline support..."
git clone https://github.com/altercation/vim-colors-solarized.git ~/.vim/plugged/vim-colors-solarized || true

echo "[+] Done. Now open Vim and run :PlugInstall"

##
##
