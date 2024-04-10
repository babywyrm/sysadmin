# Vim Tips & Tricks

# Vim Tips

| Type | Action | Command |
| :--- | :--- | :--- |
| Editor | Reload window | `:e`<br>`:edit` |
| | Horizontal split | `Ctrl w`, `s`<br>`:sp`<br>`:split` |
| | Vertical split | `Ctrl w`, `v`<br>`:vs`<br>`:vsplit` |
| | Switch between windows | `Ctrl w`, (xor `Ctrl w`, `h`, `j`, `k`, `l`) |
| | Open new tab | `:tabe` |
| | Go to next tab | `gt` |
| | Go to previous tab | `gT` |
| | Tab move left | `:-tabm` |
| | Tab move right | `:+tabm` |
| | Open buffer in new tab | `:tabe %` |
| | See relative path | `Ctrl g` |
| | See absolute path | `1`, `Ctrl g` |
| | Reopen closed buffer | `:vs#` |
| | Go back to previous buffer | `:e#`<br>`Ctrl-^` |
| Movement | Jump to top | `gg` |
| | Jump to bottom | `G` |
| | Go back to location of last edit | `g;` |
| | Go forward in edit history | `g,` |
| Edit | Re-indent | Visual select, `=` |
| | Re-indent document | `gg=G` |
| | Replace first in current line | `:s/original/new` |
| | Replace all in current line | `:s/original/new/g` |
| | [Search and replace](http://vim.wikia.com/wiki/Search_and_replace) | `:%s/foo/bar/g` |
| Misc | Copy to clipboard | `:w !pbcopy` |
| | Paste from clipboard | `:r !pbpaste` |
| | Suspend Vim | `Ctrl z` |
| | Resume from suspension (commandline) | `fg` |
| | Show trailing whitespace | `:set list`<br>`/\s\+$` |




### Customise preferences

Vim has a bunch of really useful settings that are not enabled by default, you can change them at runtime like so:

    : set number

The command above will turn on line numbering, to change settings permanently create a Vim preferences file here:

    ~/.vimrc

and fill it with you desired settings.

Here's a snapshot of the settings currently specified in my preferences file:

    " Show line numbers
    set number                
     
    " Highlight matching brace
    set showmatch
    
    " Use visual bell (no beeping)
    set visualbell  

    " Highlight all search results
    set hlsearch
    
    " Enable smart-case search
    set smartcase
    
    " Always case-insensitive
    set ignorecase
    
    " Searches for strings incrementally
    set incsearch

    " Auto-indent new lines
    set autoindent
    
    " Use 'C' style program indenting
    set cindent
    
    " Use spaces instead of tabs
    set expandtab
    
    " Number of auto-indent spaces
    set shiftwidth=4
    
    " Enable smart-indent
    set smartindent
    
    " Enable smart-tabs
    set smarttab
    
    " Number of spaces per Tab
    set softtabstop=4
    
    " Show row and column ruler information
    set ruler
    
    " Number of undo levels
    set undolevels=1000
    
    " Backspace behaviour
    set backspace=indent,eol,start  
           
    " Enable syntax highlighting
    syntax on
    
    " 
    filetype plugin indent on

### Navigation

To move the cursor you can use the arrow keys as well as:

    k   " up 1 line
    j   " down 1 line
    h   " left 1 character
    l   " right 1 character

To navigate quicky you can specify multipliers:

    10k   " up 10 lines
    10j   " down 10 lines
    10h   " left 10 characters
    10l   " right 10 characters


Vim has its own file browser, pull it up with:

    :e .
    
However, the NERDTree plugin is much better, so use that instead!

Vim supports multiple window panes, to tab between them use:

    <CTRL w> w
    
This will allow you to tab between the file browser and the currently opened file.


#### Windows

Add the following shortcuts to your ~/.vimrc file to work with multiple windows:

    map  <C-l> :tabn<CR>
    map  <C-h> :tabp<CR>
    map  <C-n> :tabnew<CR>
    
Then:

    <CTRL h>  " Move to the next window to the left
    <CTRL l>  " Move to the next window to the right
    <CTRL n>  " Create a new window
    :q        " Close windows as normal
    

Add the following to your ~/.vimrc file to get Vim to automatically name your windows.

    let &titlestring = hostname() . "[vim(" . expand("%:t") . ")]"
    
    if &term == "screen"
       set t_ts=^[k
       set t_fs=^[\
    endif
    
    if &term == "screen" || &term == "xterm"
       set title
    endif

### Useful commands

#### History

You can roll back changes with:

    :undo

However, the Gundo plugin is much better for this.
    
#### Copy Pasta

You can copy a block of text by pressing:

    v

then moving the cursor to select, and pressing:

    y

to yank. Now you can move elsewhere and press:
    
    p

to paste the text after the cursor.


#### Search

To forward search for 'stringToFind': stringToFind stringToFind

    :/stringToFind

Now press 'n' to itterate through the search and 'N' to reverse itterate through the search.

To backward search for 'stringToFind':

    :?/stringToFind

Vim maintains a search history. Type '/' or '?' and use the arrow up/down keys to recall previous search patterns.

To clear the search highlighting until the next search:

    :noh 

#### Replace

Find the all instances of 'stringToFind' on the current line and replace them with 'replacementString':

    :s/stringToFind/replacementString/g

To search and replace across the whole document add '%' (which represents the whole document):

    :%s/stringToFind/replacementString/g

To make the search case insensitive add 'i':

    :%s/stringToFind/replacementString/gi

To add a confirmation prompt add 'c':

    :%s/stringToFind/replacementString/gc


### Plugins

#### [Pathogen Plugin Manager](http://www.vim.org/scripts/script.php?script_id=2332)

Pathogen is a plugin manager for Vim. It lets you install plugins in their own directory under .vim/bundle/<newplugin>, keeping each plugin separate from the others, and making it easy to uninstall/reinstall later.

To install Pathogen, save [this](https://raw.github.com/tpope/vim-pathogen/master/autoload/pathogen.vim) file to ~/.vim/autoload/.

Then add this to your ~/.vimrc:

    call pathogen#infect()

That's it. Now just download the plugin you want to install to ~/.vim/bundle/<new plugin>.


#### [NERD Tree](https://github.com/scrooloose/nerdtree)

To install:

    git clone https://github.com/scrooloose/nerdtree.git ~/.vim/bundle/nerdtree

Then add this to your ~/.vimrc:

    " Open NERD Tree on Vim startup
    autocmd StdinReadPre * let s:std_in=1
    autocmd VimEnter * if argc() == 0 && !exists("s:std_in") | NERDTree | endif
 
    " Toggle NERD Tree with F5
    nnoremap <F5> :NERDTreeToggle<CR>

#### [Gundo](http://sjl.bitbucket.org/gundo.vim/)

To install:

    git clone http://github.com/sjl/gundo.vim.git ~/.vim/bundle/gundo


Then add this to your ~/.vimrc:

    " Toggle Gundo with F6 
    nnoremap <F6> :GundoToggle<CR>

