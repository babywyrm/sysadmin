# Vim Tips & Tricks

##
#
https://gist.github.com/bsolomon1124/7ed6c7a5cffff7c92b18e33b73f4884d
#
##

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



# Vim tips!
(Note: this is a post from a legacy blog. This post was intended to help new OSU students get started with Vim)

I'd consider myself some sort of Vim - evangelist. It's an incredible tool and has ALOT of power. If there's something you wish Vim could do, there's probably a plugin for it or a way to make Vim do it with scripting (in its own language!). Moderate proficiency in Vim is a skill that nearly every developer could benefit from. Being able to modify files directly on a server is necessary in almost every development sphere. 

## Get Vim

Most unix like operating systems (including MacOS) should come pre-packaged with Vim. If not, you can install it with yum:
```
yum install vim
```
Or apt-get
```
sudo apt-get update
sudo apt-get install vim
```

On windows you'll want to use the installation wizard [provided by the vim organization](https://www.vim.org/download.php)

On MacOS, if for some reason you're missing Vim, you can install it with the Homebrew installer (a great [package manager and installer](https://brew.sh/)):
```
brew install macvim
```

## Getting started:

### Command cheat sheets:
Cheat sheets are really great to have printed off at your desk for quick reference. Here are a few of my favorites:
* [fprintf.net](https://www.fprintf.net/vimCheatSheet.html)
* [Linux Training Academy](https://www.linuxtrainingacademy.com/vim-cheat-sheet/)
* [VimSheet.com](http://vimsheet.com/)

### Interactive Tutorials 
* [The Vim browser game](https://vim-adventures.com/) 
This is a great way to learn the movement keys to get around a file and do basic operations. Here are some other great resources on getting started in Vim:

* vimtutor
Vim is packaged with its own tutorial named vimtutor! To start the tutorial, simple enter the name of the program! You can exit vimtutor the same way you would normally exit vim (see the section below)
```
vimtutor
```

* [Vim in 4 weeks](https://medium.com/actualize-network/how-to-learn-vim-a-four-week-plan-cd8b376a9b85)
A comprehensive, in depth plan to learning the various aspects of Vim. This article gets talked alot about when people are learning Vim.

* Only use Vim!
If you only use Vim, and don't let yourself use anything else (like sublime text or VS Code), you'll learn fast (but I would recommend going through one of the interactive tutorials first)!

## Exiting Vim:

Alot of people start up vim and then get frustrated by not being able to save and exit. It's confusing initially! Here are a few different ways to save and exit!

### Saving and Exiting
1. Hit esc to ensure you're in normal mode
2. Enter the command palette by hitting ` : `
3. Type `qw` and hit enter. This will "write" the file and than "quit" Vim

Alternatively: in normal mode, hitting `ZZ` (yes both capitalized) will save and exit vim for you!

### Making a hard exit
1. Hit esc to ensure you're in normal mode
2. Enter the command palette by hitting ` : `
3. Type `q!` and enter to force vim to quite without writing (saving) anything. Danger! All things you typed since your last "write" will NOT be saved 

### Just saving
1. Hit esc to ensure you're in normal mode
2. Enter the command palette by hitting ` : `
3. Type `w` and enter to "write" your changes

## Customize Vim: 

When starting Vim, it will search for a `.vimrc` file in your home directory (based on your home path name). If you don't have one, you can create one (right in your home directory, usually the same directory as your .bashrc) and use it to customize how vim functions on startup! The following are some basics that everyone should have (The reader should note that " are comments in Vimscript):

```vimscript
" Turns on nice colors
colo desert
" Turns on the syntax for code. Automatically will recognize various file types
syntax on
```

Placing these (and other vimscript things) into your `.vimrc` will change the behavior of vim when it starts. Here's a vimscript for setting tabs to be 4 spaces!

```vimscript
filetype plugin indent on
" show existing tab with 4 spaces width
set tabstop=4
" when indenting with '>', use 4 spaces width
set shiftwidth=4
" On pressing tab, insert 4 spaces
set expandtab
```

This next one is more involved, but it auto creates closing parenthesis for us! We can see that the `h` and `i` in this vimscript are the literal movement commands given to vim after auto completing the parenthesis to get the cursor back to the it's correct position. 

```vimscript
" For mapping the opening paran with the closing one
inoremap ( ()<Esc>hi
```

This should give you a small taste of what vimscript is like and what it's capable of. It can do alot and it's very powerful. If there's something you want Vim to do (like something special with spacing, indents, comments, etc), search online for it. Someone has likely tried to do the same thing and wrote a Vim script for it. 

[This cool IBM guide](https://www.ibm.com/developerworks/library/l-vim-script-1/index.html) goes into some depth with how vim scripting works and what you can build.

## Search in Vim:

Vim makes it super easy to search and find expressions in the file you have open; it's very powerful.

To search, when in normal mode (hit esc a few times):
1. hit the forward-slash key ` / `
2. Begin typing the phrase or keyword you are looking for
3. Hit enter
4. The cursor will be placed on the first instance of that phrase!
5. While still in normal mode, hit `n` to go to the next instance of that phrase!
6. Hitting `N` will go to the previous instance of that phrase
7. To turn off the highlighted phrases you searched for, in normal mode, hit the colon ` : ` to enter the command palette 
8. Type `noh` into the command palette to set "no highlighting" and the highlights will be turned off

## Split window view!

You can have two instances of Vim open at once in a split window on the terminal. This is like tmux, but it's managed exclusively by vim!

### Horizontal split
When in normal mode, enter this into the command palette to enter a horizontal split. The "name of file to load" is the path to a file you want to open. The path is relative to where Vim was started from.
```
:split <name of file to load> 
```

To achieve a vertical split:
```
:vsplit <name of file to load>
```

To change the current active panel, (when in normal mode) hit `Ctrl w Ctrl w` (yes, that's ctrl w twice)

## Inception
Start a bash shell (or any other unix-y command) right in Vim! (in other words, yes Inception is real). When in normal mode, start the command palette and use the following command to bring up a bash shell

```
:!bash
```
Note the exclamation mark telling Vim to execute the command.

Here's where it gets crazy. Your initial shell you used to enter Vim is still running. On top of that shell, Vim is running. Now, on top of that, a bash shell instance is now running! It's sort of like an onion with all the layers you can go down into. To get back to Vim, exit your bash instance with the `exit` command. If you than exit Vim, you will be back to your original shell. A word of warning though, all this job handling and nested processes can get fairly processor hungry. So, if your noticing some chugging, back off alittle on the inception. 

You can execute almost any unix command like this. For example:
```
:!wc sample.txt
```

This will run the word count program for the sample.txt file! Command inception is crazy cool!

## Block Comments
I find this extremely helpful when doing full Vim development. This is taken from the following [Stack Overflow discussion](https://stackoverflow.com/questions/1676632/whats-a-quick-way-to-comment-uncomment-lines-in-vim) 

For commenting a block of text:
 
 "First, go to the first line you want to comment, press Ctrl V. This will put the editor in the VISUAL BLOCK mode. 
 
 Now using the arrow key, select up to the last line you want commented. Now press Shift i, which will put the editor in INSERT mode and then press #. 
 
 This will add a hash to the first line. (if this was a C file, just type //). Then press Esc (give it a second), and it will insert a # character on all other selected lines."

Un-commenting is nearly the same, but in opposite order using the visual block mode!

## Time traveling!

Yes, you heard that right, vim makes time travel possible! Note, this ONLY works within current Vim sessions. So, if you exit vim, you will lose your current session's stack of edits. 

On the Vim command palette, which you can enter from Normal mode by hitting the colon `:`, you can type 'earlier' and 'later' to go back and forth in your current session stack of edits. This is super helpful if you need to revert a few small changes you've made in the last minute or want to revert everything you did in the last hour. Or if you decide you do want those changes, go forward in time too! 

``` vimscript
:earlier 3m
:later 5s
```

## Plugins

One of the reasons Vim is so great is that there are TONS of awesome plugins for Vim. If you're having a hard time scripting something on your own with vimscript, there's probably a plugin for it! They range anywhere from super useful to super silly. Some of my favorites include the file system NERD tree, the fugitive git client, and ordering pizza with Vim Pizza (yes that's right, you can order pizza with Vim! It can really do it all!)

Check out [this great resource](https://vimawesome.com/) for discovering Vim plugins, instructions to install them, and buzz around the Vim community.

# Conclusion:

This by no means is a comprehensive guide. There are a ton of great resources for Vim out there and its capabilities. This guide should serve more as a small taste to what Vim can do and maybe peaked your interest to learning more about it.

Take heart! Vim has a steep learning curve, and, like any complex tool set, it takes alot of time and practice to get good with. Google is your friend here. 

Feel free to reach out to me if something from this guide was not super clear!



# Vim

## Resources & References

- https://www.vim.org/
- https://realpython.com/vim-and-python-a-match-made-in-heaven/
- https://dougblack.io/words/a-good-vimrc.html
- https://github.com/vim/vim
- https://github.com/vim-scripts/pyfold
- https://github.com/fatih/vim-go
- https://github.com/VundleVim/Vundle.vim
- http://heather.cs.ucdavis.edu/~matloff/vim.html
- http://vimdoc.sourceforge.net/htmldoc/intro.html#book
- https://www.linux.com/learn/vim-101-beginners-guide-vim

## Common Way to Start Vim

```bash
$ vim [options] [file ..]
```

## Useful Command-Line Options

From the man page, in order of usefulness.  These should be all that you need:

       +[num]      For the first file the cursor will be positioned on line "num".
                   If "num" is missing, the cursor will be positioned on the last line.

       -o[N]       Open N windows stacked.  When N is omitted, open one window for each file.

       -O[N]       Open N windows side by side (columns).  When N is omitted, open one window for each file.
                   Example: `vim -O2`

       -p[N]       Open N tab pages.  When N is omitted, open one tab page for each file.

       --help      Give a help message and exit, just like "-h".

       -r          List swap files, with information about using them for recovery.

       -r {file}   Recovery  mode.   The  swap file is used to recover a crashed editing session.
                   The swap file is a file with the same filename as the text file with
                   ".swp" appended.  See ":help recovery".

       +/{pat}     For the first file the cursor will be positioned in the line with the first occurrence of {pat}.
                   See ":help search-pattern" for the available search patterns.

       --version   Print version information and exit.

## Modes

Vim is a model editor, behaving differently depending on which mode you are in.

- Normal (command) mode: bottom of screen displays file name or is blank.  You use ex-style commands (prefaced with colon `:`) from here.
- Insert mode.  Bottom of screen displays `--INSERT--`.
- Visual mode.  Bottom of screen displays `--VISUAL--`.

To enter insert mode, type `i`.  To exit, press <Esc>.

## Configuration

`~/.vimrc` is for your personal Vim initializations.

### Example `vimrc` File

```
" .vimrc, Vim configuration file
" This is a comment

" If no file type, default to "python"
autocmd BufEnter * if &filetype == "" | setlocal ft=python | endif

set nocompatible   " required by Vundle
filetype off       " required by Vundle

:set background=dark
:set backspace=indent,eol,start
:set autoindent
:set autowrite
:set hlsearch
:set incsearch
:set number
:set ruler
:set shiftwidth=4
:set smarttab
:set softtabstop=0
:set expandtab
:set textwidth=0
:set tabstop=8

:syntax on
```

## Cursor (Direction) Keys

`k` is up, `h` is left, `l` si right, `j` is down:

      k
    h   l
      j

Mnemonic: `j` key looks like down arrow.

## Commands

The general syntax of commands is `[number]command[motion]`.

You can optionally precede all movement commands with a number.

Examples:

- `9dd` to delete 9 lines
- `5o` to insert 5 lines
- `5fx` to move up 5 occurrences of "x"
- `d3w` deletes 3 words

For example, add three exclamation points after the cursor with `3a!`.

For commands like `yw` (yank/copy one word) and `c$` (delete from cursor to end of line), the first character is the command, and the second is the motion.

General commands:

Insertion, deletion, copying & pasting:

    i               enter insert mode.  will insert text *before* the character under cursor
    a               enter insert mode, but will insert text *after* character under cursor
    x               delete character under cursor

    O               insert line *above* the cursor, then enter insert mode
    o               insert line *below* the cursor, then enter insert mode

    d{motion}       delete.  doesn't enter insert mode after
    dd              delete current line
    dw              delete current word

    p               put previously deleted text after the cursor.  (like paste)
    yw              yank (copy) one word

    c{motion}       change text.  like d{motion}, but puts you in insert mode after
    c$              delete from cursor to end of line
    cw              delete from cursor to end of word, then enter insert word

    r{x}            replace single character under the cursor with character {x}

    .               repeat last change or delete command

Undoing and redoing:

    u               undo last edit
    <Ctrl> + R      redo
    U               undo whole line.  undoes all the changes made on the last line that was edited

Searching:

    /{phrase}       search forward for {phrase}.  to get rid of the highlights, use `:noh`
    ?{phrase}       search backwards for {phrase}

    n               get next search result
    N               get previous search result

Other:

    ZZ              write and exit.  note the Z's are capitalized

    ~               change current character's case.  can be used with a count (like everything else)

    >               indents selected lines by one "shift width."
                    amount of whitespace is set with the `:set shiftwidth` option
    <               de-dents selected lines by one "shift width."

    J               join next line with current one

    v               visual mode (highlight text with cursor keys)

    <Ctrl> + G      show file status and your location in the file

## Motions

Movement motions (all of these can take optional numeric arguments):

    w               start of next word (2w, 3w, 4w)
    e               end of current word (2e, 3e, 4e)
    b               start of previous word

    $               end of line.  2$: end of next line, etc
    0               start of line
    ^               first non-blank character of the line

    gg              go to top of file
    G               go to bottom of file

    <Ctrl> + U      scrolls up half a screen of text
    <Ctrl> + D      scrolls you down half a screen

    %               jump cursor to a matching ), ], or }

    f{c}            move to the next occurence of character c on current line.
                    for example, if you are at start of the line "Searching Along a Single Line,"
                    fS will move to the S in "Single"
                    this cmd is case sensitive

## Ex-Style Commands

Any command that begins with a colon `:` is considered an ex-style command.

All of these must be finished by pressing <Enter>.

    :q                  exit Vim
    :q!                 exit and discard changes without writing/saving
    :qa!                exit/discard *all* changes.  this is for multiple tabs/windows/buffers
    :wq [filename]      write (save) file and exit

    :{number}           go to a line number (or, use `{number}G`)

    :set {option}       set an option i.e. :set ic.  See "setting options" section

    :shell              takes you to the shell temporarily.  you can exit back to Vim with `exit` (from shell)
    :!`cmd`             execute the external shell command `cmd`.  example: :!ls

    :s/old/new          substitute first occurrence of `new` for `old` in current line
    :s/old/new/g        substitute all occurrences of `new` for `old` in current line
    :%s/old/new/g       substitute all occurrences of `new` for `old` in entire file
    :%s/old/new/gc      find every occurrence in the whole file, with a prompt whether to substitute or not

    :e {file}           edit file
    :r {file}           read file
    :!rm {file}         remove file

    :next               change files, allowing you to edit the next file
    :previous           like next, but move back
    :wnext              like :w plus :next, combined as one command

    :args               displays the list of the files currently being edited
    :split [file]       split vertical.  by default, opens the same file in two windows
    :new                like split, but open up new file

    :syntax [on|off]    syntax highlighting

    :noh                clear current highlighting

    :digraphs           show currently defined digraphs.
                        digraphs are used to enter characters that normally cannot be entered by an ordinary keyboard.
                        these are mostly printable non-ASCII characters.

### Setting Options

For help:

    :help set

General/meta options:

    :set                    show all options that differ from their default value
    :set all                show all but terminal options
    :se[t] {option}?        show value of {option}
    :se[t] {option}         for "toggle" options, switch it on.  for anything else, shows the value
    :se[t] no{option}       for "toggle" options: reset/switch it off
    :se[t] {option}&        reset option to its default value
    :se[t] all&             set all options to their default value
    :se[t] {option}={val}   set string or number option to {value}

Specific options listed below.

Toggle options (optionally preface the "positive" form with `no` i.e. `ic` or `noic`):

    :set [no]ic             ignore case in global search patterns
    :set [no]number         turn line numbering on
    :set [no]paste          put Vim in Paste mode.  This is useful if you want to cut or copy
                            some text from one window and paste it in Vim.
    :set [no]autowrite

    :set [no]incsearch      incremental search.  search as characters are entered
    :set [no]hlsearch       turn highlighting on in search.  highlight matches

    :set [no]autoindent
    :set [no]smarttab       if on: tabs inserted at the beginning of a line are treated like soft tabs of size 'shiftwidth'
    :set [no]expandtab

    :set [no]ruler          show line and column number of cursor position, separated by comma

Numeric options:

    :set shiftwidth         defaults to 'tabstop'
    :set tabstop            number of spaces that a <Tab> in the file counts for
    :set sotftabstop
    :set scroll             number of lines to scroll with <CTRL> + U and <CTRL> + D commands
    :set textwidth          maximum width of text. a longer line will be broken after white space to
                            get this width.  A zero value disables this.
                            set to 0 when the 'paste' option is set and restored when 'paste' is reset
    :set colorcolumn        set a line-length colored column marker

String options:

    :set syntax
    :set background
    :set filetype
    :set helplang

## Plugins/Extensions & Language-Specific Features

## Using a Package Manager (Vundle)

[Vundle](https://github.com/VundleVim/Vundle.vim) is a popular Vim package manager.

To [install](https://github.com/VundleVim/Vundle.vim#quick-start):

```bash
$ git clone https://github.com/VundleVim/Vundle.vim.git ~/.vim/bundle/Vundle.vim
```

Make sure that `~/.vimrc` has these bare minimums:

```
set nocompatible
filetype off

" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')

" let Vundle manage Vundle, required
Plugin 'VundleVim/Vundle.vim'

"
" Specify plugins here
"

" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required
```

Launch Vim and run `:PluginInstall`.

For some examples, see [here](https://github.com/VundleVim/Vundle.vim/wiki/Examples).

## Installing Packages with Vundle

To install a new plugin (such as [YouCompleteMe](https://github.com/Valloric/YouCompleteMe) for code completion:

1. Add it to `~/.vimrc`, i.e. `Bundle 'Valloric/YouCompleteMe'`
2. Launch Vim, then run `:PluginInstall`.

The package will be downloaded to `~/.vim/bundle/`.

### Vim + Python

To check that your Vim install supports Python, see `vim --version | grep "[+-]python"`.  If `python` or `python3` has a plus-symbol next to it, it is supported.

To see which specific version of Python Vim is using, enter `vim` and then, in Vim, use:

```vim
:python3 import sys; print(sys.version)
```

## Column Typing

Stack Overflow: [In Vim how do I effectively insert the same characters across multiple lines?](https://stackoverflow.com/a/9549765/7954504).

You have the following:

```
a = (1, 2, 3)
b = (4, 5, 6)
c = (7, 8, 9)
```

And want:

```
a = list((1, 2, 3))
b = list((4, 5, 6))
c = list((7, 8, 9))
```

How to:

1. Move cursor to the `a`
2. Enter visual block mode with `<Ctrl> + v`
3. Press `j` (down) three times
4. Press `I`
5. Type the text
6. Press `<Esc>`

## Using Regex

    Example                 matches
    -------                 -------
    ab\{2,3}c               "abbc" or "abbbc"
    a\{5}                   "aaaaa"
    ab\{2,}c                "abbc", "abbbc", "abbbbc", etc.
    ab\{,3}c                "ac", "abc", "abbc" or "abbbc"
    a[bc]\{3}d              "abbbd", "abbcd", "acbcd", "acccd", etc.
    a\(bc\)\{1,2}d          "abcd" or "abcbcd"
    a[bc]\{-}[cd]           "abc" in "abcd"
    a[bc]*[cd]              "abcd" in "abcd"
