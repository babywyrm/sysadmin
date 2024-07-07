
##
#
https://gist.github.com/orliesaurus/e32ff6477680f143a960
#
https://gist.github.com/adamk33n3r/ae76889c92f5097bb63f
#
##


```
# Adam Keenan's Vim tips and tricks cheatsheet

## Commands
### Navigation
Learn these. It's tricky at first but it improves productivity by a lot.

- j: up
- k: down
- h: left
- l: right
- gg: top of file
- G: bottom of file
- w: next word
- e: end of word
- b: back word
- n: next search
- N: prev search

#### Modifiers
- t: up to
- T: back to

### Editing
- i: insert mode (at current character)
- I: insert mode (at beginning of line)
- a: insert mode (1 after current character)
- A: insert mode (at end of line)
- o: insert mode (new line under)
- O: insert mode (new line above)
- u: undo
- ctrl-r: redo

### Selection
- v: select mode
- V: line select mode
- ctrl-v: block select mode
- y: yank selection (copy)
- Y: yank line

### Deleting
- x: delete
- d: delete (prefix)
  - d: delete and copy current line
  - $: delete and copy do end of line

## Recommended configuration options
    set nocompatible            " Use Vim settings rather than Vi settings. Should have this first because it changes a lot of options
    set mouse=a                 " It is OK to use the mouse.....but try not to.
    set bg=dark                 " Set to having dark bg (if you have a dark bg)
    set t_Co=256                " Force 256 colors
    colorscheme xoria256        " My favorite as of now
    set shell=/bin/bash         " If using a non sh-compatible shell. Like fish
    
    filetype plugin indent on   " Set file specific settings
    set ai                      " Sets autoindent on
    set tabstop=4               " Sets how many columns a tab is
    set softtabstop=4           " Sets how many columns to insert when pusing tab
    set shiftwidth=4            " Sets how many columns to indent with << and >> and cindent
    set expandtab               " Makes spaces when pusing tab

    set nu                      " Shows numbers in left margin
    set hls                     " Highlights all matching words when searching
    set incsearch               " Search as you type
    set ruler                   " Always show cursor position
    set showcmd                 " Show command info in statusline like visual selection ranges
    set laststatus=2            " Always show statusline
    set noesckeys               " Remove delay when pushing escape in insert mode although makes things like the delete key not work
    set scrolloff=1             " Always show one line in advance when scrolling
    set splitright              " When vsplitting, open new pane to right
    set splitbelow              " When hsplitting, open new pane below

    set autochdir               " Automatically changes working dir to dir of file when opened
    set undofile                " Enables undo file which stores all history for every file
    set undodir=~/.vim/undo     " Place to store undofiles
    set directory=~/.vim/swap   " Place to store swapfiles
    set backupdir=~/.vim/backup " Place to store backupfiles

    set wildmenu                " Command line completion
    set wildmode=full           " Shows full list to tab through
    
    set iskeyword-=_            " Removes _ from being a keyword so commands like cw treat it as end of word
    " Turns on spell check. Use z=
    set invspell spelllang=en_us

    " Keybindings
    map <ScrollWheelUp> <C-Y>   " Sets scrolling to do one line at a time
    map <ScrollWheelDown> <C-E> " May only be useful on trackpads
    nnoremap "" :w<CR>          " Sets `""` in normal mode to save file (you could change to your own shortcut)
    nnoremap ^_ I// <esc>j      " Sets both ctrl-_ and ctrl-/ to put two slashes at beginning of line for commenting and goes to next line. Note that the ^ is an escape character not an actual ^. To insert this do ctrl-v ctrl-/. 

    " Jump back to last known cursor position when opening a file again
    autocmd BufReadPost *
        \ if line("'\"") > 1 && line("'\"") <= line("$") |
        \   exe "normal! g`\"" |
        \ endif

If you haven't noticed by now many configuration options can be shortcut with
using only part of the word or using letters of it like `set number;set nu` or
`colorscheme xoria;colo xoria` or even `set expandtab;set et`.

You can also prefix options with `no` to turn them off like `set nopaste` and
appending a `?` after an option will display what it is set to

## Recommended plugins - I use pathogen to load
- [vim-airline](https://github.com/bling/vim-airline)
- [vim-javascript](https://github.com/pangloss/vim-javascript)
- [vim-coffee-script](https://github.com/kchmck/vim-coffee-script)
```
# from http://zzapper.co.uk/vimtips.html
------------------------------------------------------------------------------
" new items marked [N] , corrected items marked [C]
" *best-searching*
/joe/e                      : cursor set to End of match
3/joe/e+1                   : find 3rd joe cursor set to End of match plus 1 [C]
/joe/s-2                    : cursor set to Start of match minus 2
/joe/+3                     : find joe move cursor 3 lines down
/^joe.*fred.*bill/          : find joe AND fred AND Bill (Joe at start of line)
/^[A-J]/                    : search for lines beginning with one or more A-J
/begin\_.*end               : search over possible multiple lines
/fred\_s*joe/               : any whitespace including newline [C]
/fred\|joe                  : Search for FRED OR JOE
/.*fred\&.*joe              : Search for FRED AND JOE in any ORDER!
/\<fred\>/                  : search for fred but not alfred or frederick [C]
/\<\d\d\d\d\>               : Search for exactly 4 digit numbers
/\D\d\d\d\d\D               : Search for exactly 4 digit numbers
/\<\d\{4}\>                 : same thing
/\([^0-9]\|^\)%.*%          : Search for absence of a digit or beginning of line
" finding empty lines
/^\n\{3}                    : find 3 empty lines
/^str.*\nstr                : find 2 successive lines starting with str
/\(^str.*\n\)\{2}           : find 2 successive lines starting with str
" using rexexp memory in a search find fred.*joe.*joe.*fred *C*
/\(fred\).*\(joe\).*\2.*\1
" Repeating the Regexp (rather than what the Regexp finds)
/^\([^,]*,\)\{8}
" visual searching
:vmap // y/<C-R>"<CR>       : search for visually highlighted text
:vmap <silent> //    y/<C-R>=escape(@", '\\/.*$^~[]')<CR><CR> : with spec chars
" \zs and \ze regex delimiters :h /\zs
/<\zs[^>]*\ze>              : search for tag contents, ignoring chevrons
" zero-width :h /\@=
/<\@<=[^>]*>\@=             : search for tag contents, ignoring chevrons
/<\@<=\_[^>]*>\@=           : search for tags across possible multiple lines
" searching over multiple lines \_ means including newline
/<!--\_p\{-}-->                   : search for multiple line comments
/fred\_s*joe/                     : any whitespace including newline *C*
/bugs\(\_.\)*bunny                : bugs followed by bunny anywhere in file
:h \_                             : help
" search for declaration of subroutine/function under cursor
:nmap gx yiw/^\(sub\<bar>function\)\s\+<C-R>"<CR>
" multiple file search
:bufdo /searchstr/                : use :rewind to recommence search
" multiple file search better but cheating
:bufdo %s/searchstr/&/gic   : say n and then a to stop
" How to search for a URL without backslashing
?http://www.vim.org/        : (first) search BACKWARDS!!! clever huh!
" Specify what you are NOT searching for (vowels)
/\c\v([^aeiou]&\a){4}       : search for 4 consecutive consonants
/\%>20l\%<30lgoat           : Search for goat between lines 20 and 30 [N]
/^.\{-}home.\{-}\zshome/e   : match only the 2nd occurence in a line of "home" [N]
:%s/home.\{-}\zshome/alone  : Substitute only the occurrence of home in any line [N]
" find str but not on lines containing tongue
^\(.*tongue.*\)\@!.*nose.*$
\v^((tongue)@!.)*nose((tongue)@!.)*$
.*nose.*\&^\%(\%(tongue\)\@!.\)*$ 
:v/tongue/s/nose/&/gic
'a,'bs/extrascost//gc       : trick: restrict search to between markers (answer n) [N]
"----------------------------------------
" *best-substitution*
:%s/fred/joe/igc            : general substitute command
:%s//joe/igc                : Substitute what you last searched for [N]
:%s/~/sue/igc               : Substitute your last replacement string [N]
:%s/\r//g                   : Delete DOS returns ^M
" Is your Text File jumbled onto one line? use following
:%s/\r/\r/g                 : Turn DOS returns ^M into real returns
:%s=  *$==                  : delete end of line blanks
:%s= \+$==                  : Same thing
:%s#\s*\r\?$##              : Clean both trailing spaces AND DOS returns
:%s#\s*\r*$##               : same thing
" deleting empty lines
:%s/^\n\{3}//               : delete blocks of 3 empty lines
:%s/^\n\+/\r/               : compressing empty lines
:%s#<[^>]\+>##g             : delete html tags, leave text (non-greedy)
:%s#<\_.\{-1,}>##g          : delete html tags possibly multi-line (non-greedy)
:%s#.*\(\d\+hours\).*#\1#   : Delete all but memorised string (\1) [N]
" parse xml/soap 
%s#><\([^/]\)#>\r<\1#g      : split jumbled up XML file into one tag per line [N]
%s/</\r&/g                  : simple split of html/xml/soap  [N]
:%s#<[^/]#\r&#gic           : simple split of html/xml/soap  but not closing tag [N]
:%s#<[^/]#\r&#gi            : parse on open xml tag [N]
:%s#\[\d\+\]#\r&#g          : parse on numbered array elements [1] [N]
" VIM Power Substitute
:'a,'bg/fred/s/dick/joe/igc : VERY USEFUL
" duplicating columns
:%s= [^ ]\+$=&&=            : duplicate end column
:%s= \f\+$=&&=              : Dupicate filename
:%s= \S\+$=&&               : usually the same
" memory
:%s#example#& = &#gic        : duplicate entire matched string [N]
:%s#.*\(tbl_\w\+\).*#\1#    : extract list of all strings tbl_* from text  [NC]
:s/\(.*\):\(.*\)/\2 : \1/   : reverse fields separated by :
:%s/^\(.*\)\n\1$/\1/        : delete duplicate lines
:%s/^\(.*\)\(\n\1\)\+$/\1/  : delete multiple duplicate lines [N]
" non-greedy matching \{-}
:%s/^.\{-}pdf/new.pdf/      : delete to 1st occurence of pdf only (non-greedy)
%s#^.\{-}\([0-9]\{3,4\}serial\)#\1#gic : delete up to 123serial or 1234serial [N]
" use of optional atom \?
:%s#\<[zy]\?tbl_[a-z_]\+\>#\L&#gc : lowercase with optional leading characters
" over possibly many lines
:%s/<!--\_.\{-}-->//        : delete possibly multi-line comments
:help /\{-}                 : help non-greedy
" substitute using a register
:s/fred/<c-r>a/g            : sub "fred" with contents of register "a"
:s/fred/<c-r>asome_text<c-r>s/g  
:s/fred/\=@a/g              : better alternative as register not displayed (not *) [C]
" multiple commands on one line
:%s/\f\+\.gif\>/\r&\r/g | v/\.gif$/d | %s/gif/jpg/
:%s/a/but/gie|:update|:next : then use @: to repeat
" ORing
:%s/goat\|cow/sheep/gc      : ORing (must break pipe)
:'a,'bs#\[\|\]##g           : remove [] from lines between markers a and b [N]
:%s/\v(.*\n){5}/&\r         : insert a blank line every 5 lines [N]
" Calling a VIM function
:s/__date__/\=strftime("%c")/ : insert datestring
:inoremap \zd <C-R>=strftime("%d%b%y")<CR>    : insert date eg 31Jan11 [N]
" Working with Columns sub any str1 in col3
:%s:\(\(\w\+\s\+\)\{2}\)str1:\1str2:
" Swapping first & last column (4 columns)
:%s:\(\w\+\)\(.*\s\+\)\(\w\+\)$:\3\2\1:
" format a mysql query 
:%s#\<from\>\|\<where\>\|\<left join\>\|\<\inner join\>#\r&#g
" filter all form elements into paste register
:redir @*|sil exec 'g#<\(input\|select\|textarea\|/\=form\)\>#p'|redir END
:nmap ,z :redir @*<Bar>sil exec 'g@<\(input\<Bar>select\<Bar>textarea\<Bar>/\=form\)\>@p'<Bar>redir END<CR>
" substitute string in column 30 [N]
:%s/^\(.\{30\}\)xx/\1yy/
" decrement numbers by 3
:%s/\d\+/\=(submatch(0)-3)/
" increment numbers by 6 on certain lines only
:g/loc\|function/s/\d/\=submatch(0)+6/
" better
:%s#txtdev\zs\d#\=submatch(0)+1#g
:h /\zs
" increment only numbers gg\d\d  by 6 (another way)
:%s/\(gg\)\@<=\d\+/\=submatch(0)+6/
:h zero-width
" rename a string with an incrementing number
:let i=10 | 'a,'bg/Abc/s/yy/\=i/ |let i=i+1 # convert yy to 10,11,12 etc
" as above but more precise
:let i=10 | 'a,'bg/Abc/s/xx\zsyy\ze/\=i/ |let i=i+1 # convert xxyy to xx11,xx12,xx13
" find replacement text, put in memory, then use \zs to simplify substitute
:%s/"\([^.]\+\).*\zsxx/\1/
" Pull word under cursor into LHS of a substitute
:nmap <leader>z :%s#\<<c-r>=expand("<cword>")<cr>\>#
" Pull Visually Highlighted text into LHS of a substitute
:vmap <leader>z :<C-U>%s/\<<c-r>*\>/
" substitute singular or plural
:'a,'bs/bucket\(s\)*/bowl\1/gic   [N]
----------------------------------------
" all following performing similar task, substitute within substitution
" Multiple single character substitution in a portion of line only
:%s,\(all/.*\)\@<=/,_,g     : replace all / with _ AFTER "all/"
" Same thing
:s#all/\zs.*#\=substitute(submatch(0), '/', '_', 'g')#
" Substitute by splitting line, then re-joining
:s#all/#&^M#|s#/#_#g|-j!
" Substitute inside substitute
:%s/.*/\='cp '.submatch(0).' all/'.substitute(submatch(0),'/','_','g')/
----------------------------------------
" *best-global* command 
:g/gladiolli/#              : display with line numbers (YOU WANT THIS!)
:g/fred.*joe.*dick/         : display all lines fred,joe & dick
:g/\<fred\>/                : display all lines fred but not freddy
:g/^\s*$/d                  : delete all blank lines
:g!/^dd/d                   : delete lines not containing string
:v/^dd/d                    : delete lines not containing string
:g/joe/,/fred/d             : not line based (very powerfull)
:g/fred/,/joe/j             : Join Lines [N]
:g/-------/.-10,.d          : Delete string & 10 previous lines
:g/{/ ,/}/- s/\n\+/\r/g     : Delete empty lines but only between {...}
:v/\S/d                     : Delete empty lines (and blank lines ie whitespace)
:v/./,/./-j                 : compress empty lines
:g/^$/,/./-j                : compress empty lines
:g/<input\|<form/p          : ORing
:g/^/put_                   : double space file (pu = put)
:g/^/m0                     : Reverse file (m = move)
:g/^/m$                     : No effect! [N]
:'a,'bg/^/m'b               : Reverse a section a to b
:g/^/t.                     : duplicate every line
:g/fred/t$                  : copy (transfer) lines matching fred to EOF
:g/stage/t'a                : copy (transfer) lines matching stage to marker a (cannot use .) [C]
:g/^Chapter/t.|s/./-/g      : Automatically underline selecting headings [N]
:g/\(^I[^^I]*\)\{80}/d      : delete all lines containing at least 80 tabs
" perform a substitute on every other line
:g/^/ if line('.')%2|s/^/zz / 
" match all lines containing "somestr" between markers a & b
" copy after line containing "otherstr"
:'a,'bg/somestr/co/otherstr/ : co(py) or mo(ve)
" as above but also do a substitution
:'a,'bg/str1/s/str1/&&&/|mo/str2/
:%norm jdd                  : delete every other line
" incrementing numbers (type <c-a> as 5 characters)
:.,$g/^\d/exe "norm! \<c-a>": increment numbers
:'a,'bg/\d\+/norm! ^A       : increment numbers
" storing glob results (note must use APPEND) you need to empty reg a first with qaq. 
"save results to a register/paste buffer
:g/fred/y A                 : append all lines fred to register a
:g/fred/y A | :let @*=@a    : put into paste buffer
:let @a=''|g/Barratt/y A |:let @*=@a
" filter lines to a file (file must already exist)
:'a,'bg/^Error/ . w >> errors.txt
" duplicate every line in a file wrap a print '' around each duplicate
:g/./yank|put|-1s/'/"/g|s/.*/Print '&'/
" replace string with contents of a file, -d deletes the "mark"
:g/^MARK$/r tmp.txt | -d
" display prettily
:g/<pattern>/z#.5           : display with context
:g/<pattern>/z#.5|echo "=========="  : display beautifully
" Combining g// with normal mode commands
:g/|/norm 2f|r*                      : replace 2nd | with a star
"send output of previous global command to a new window
:nmap <F3>  :redir @a<CR>:g//<CR>:redir END<CR>:new<CR>:put! a<CR><CR>
"----------------------------------------
" *Best-Global-combined-with-substitute* (*power-editing*)
:'a,'bg/fred/s/joe/susan/gic :  can use memory to extend matching
:/fred/,/joe/s/fred/joe/gic :  non-line based (ultra)
:/biz/,/any/g/article/s/wheel/bucket/gic:  non-line based [N]
----------------------------------------
" Find fred before beginning search for joe
:/fred/;/joe/-2,/sid/+3s/sally/alley/gIC
"----------------------------------------
" create a new file for each line of file eg 1.txt,2.txt,3,txt etc
:g/^/exe ".w ".line(".").".txt"
"----------------------------------------
" chain an external command
:.g/^/ exe ".!sed 's/N/X/'" | s/I/Q/    [N]
"----------------------------------------
" Operate until string found [N]
d/fred/                                :delete until fred
y/fred/                                :yank until fred
c/fred/e                               :change until fred end
v12|                                   : visualise/change/delete to column 12 [N]
"----------------------------------------
" Summary of editing repeats [N]
.      last edit (magic dot)
:&     last substitute
:%&    last substitute every line
:%&gic last substitute every line confirm
g%     normal mode repeat last substitute
g&     last substitute on all lines
@@     last recording
@:     last command-mode command
:!!    last :! command
:~     last substitute
:help repeating
----------------------------------------
" Summary of repeated searches
;      last f, t, F or T
,      last f, t, F or T in opposite direction
n      last / or ? search
N      last / or ? search in opposite direction
----------------------------------------
" *Absolutely-essential*
----------------------------------------
* # g* g#           : find word under cursor (<cword>) (forwards/backwards)
%                   : match brackets {}[]()
.                   : repeat last modification 
@:                  : repeat last : command (then @@)
matchit.vim         : % now matches tags <tr><td><script> <?php etc
<C-N><C-P>          : word completion in insert mode
<C-X><C-L>          : Line complete SUPER USEFUL
/<C-R><C-W>         : Pull <cword> onto search/command line
/<C-R><C-A>         : Pull <CWORD> onto search/command line
:set ignorecase     : you nearly always want this
:set smartcase      : overrides ignorecase if uppercase used in search string (cool)
:syntax on          : colour syntax in Perl,HTML,PHP etc
:set syntax=perl    : force syntax (usually taken from file extension)
:h regexp<C-D>      : type control-D and get a list all help topics containing
                      regexp (plus use TAB to Step thru list)
----------------------------------------
" MAKE IT EASY TO UPDATE/RELOAD _vimrc
:nmap ,s :source $VIM/_vimrc
:nmap ,v :e $VIM/_vimrc
:e $MYVIMRC         : edits your _vimrc whereever it might be  [N]
" How to have a variant in your .vimrc for different PCs [N]
if $COMPUTERNAME == "NEWPC"
ab mypc vista
else
ab mypc dell25
endif
----------------------------------------
" splitting windows
:vsplit other.php       # vertically split current file with other.php [N]
----------------------------------------
"VISUAL MODE (easy to add other HTML Tags)
:vmap sb "zdi<b><C-R>z</b><ESC>  : wrap <b></b> around VISUALLY selected Text
:vmap st "zdi<?= <C-R>z ?><ESC>  : wrap <?=   ?> around VISUALLY selected Text
----------------------------------------
"vim 7 tabs
vim -p fred.php joe.php             : open files in tabs
:tabe fred.php                      : open fred.php in a new tab
:tab ball                           : tab open files
:close                              : close a tab but leave the buffer *N*
" vim 7 forcing use of tabs from .vimrc
:nnoremap gf <C-W>gf
:cab      e  tabe
:tab sball                           : retab all files in buffer (repair) [N]
----------------------------------------
" Exploring
:e .                            : file explorer
:Exp(lore)                      : file explorer note capital Ex
:Sex(plore)                     : file explorer in split window
:browse e                       : windows style browser
:ls                             : list of buffers
:cd ..                          : move to parent directory
:args                           : list of files
:pwd                            : Print Working Directory (current directory) [N]
:args *.php                     : open list of files (you need this!)
:lcd %:p:h                      : change to directory of current file
:autocmd BufEnter * lcd %:p:h   : change to directory of current file automatically (put in _vimrc)
----------------------------------------
" Changing Case
guu                             : lowercase line
gUU                             : uppercase line
Vu                              : lowercase line
VU                              : uppercase line
g~~                             : flip case line
vEU                             : Upper Case Word
vE~                             : Flip Case Word
ggguG                           : lowercase entire file
" Titlise Visually Selected Text (map for .vimrc)
vmap ,c :s/\<\(.\)\(\k*\)\>/\u\1\L\2/g<CR>
" Title Case A Line Or Selection (better)
vnoremap <F6> :s/\%V\<\(\w\)\(\w*\)\>/\u\1\L\2/ge<cr> [N]
" titlise a line
nmap ,t :s/.*/\L&/<bar>:s/\<./\u&/g<cr>  [N]
" Uppercase first letter of sentences
:%s/[.!?]\_s\+\a/\U&\E/g
----------------------------------------
gf                              : open file name under cursor (SUPER)
:nnoremap gF :view <cfile><cr>  : open file under cursor, create if necessary
ga                              : display hex,ascii value of char under cursor
ggVGg?                          : rot13 whole file
ggg?G                           : rot13 whole file (quicker for large file)
:8 | normal VGg?                : rot13 from line 8
:normal 10GVGg?                 : rot13 from line 8
<C-A>,<C-X>                     : increment,decrement number under cursor
                                  win32 users must remap CNTRL-A
<C-R>=5*5                       : insert 25 into text (mini-calculator)
----------------------------------------
" Make all other tips superfluous
:h 42            : also http://www.google.com/search?q=42
:h holy-grail
:h!
----------------------------------------
" disguise text (watch out) [N]
ggVGg?                          : rot13 whole file (toggles)
:set rl!                        : reverse lines right to left (toggles)
:g/^/m0                         : reverse lines top to bottom (toggles)
:%s/\(\<.\{-}\>\)/\=join(reverse(split(submatch(1), '.\zs')), '')/g   : reverse all text *N*
----------------------------------------
" History, Markers & moving about (what Vim Remembers) [C]
'.               : jump to last modification line (SUPER)
`.               : jump to exact spot in last modification line
g;               : cycle thru recent changes (oldest first)
g,               : reverse direction 
:changes
:h changelist    : help for above
<C-O>            : retrace your movements in file (starting from most recent)
<C-I>            : retrace your movements in file (reverse direction)
:ju(mps)         : list of your movements
:help jump-motions
:history         : list of all your commands
:his c           : commandline history
:his s           : search history
q/               : Search history Window (puts you in full edit mode) (exit CTRL-C)
q:               : commandline history Window (puts you in full edit mode) (exit CTRL-C)
:<C-F>           : history Window (exit CTRL-C)
----------------------------------------
" Abbreviations & Maps
" Maps are commands put onto keys, abbreviations expand typed text [N]
" Following 4 maps enable text transfer between VIM sessions
:map   <f7>   :'a,'bw! c:/aaa/x       : save text to file x
:map   <f8>   :r c:/aaa/x             : retrieve text 
:map   <f11>  :.w! c:/aaa/xr<CR>      : store current line
:map   <f12>  :r c:/aaa/xr<CR>        : retrieve current line
:ab php          : list of abbreviations beginning php
:map ,           : list of maps beginning ,
" allow use of F10 for mapping (win32)
set wak=no       : :h winaltkeys
" For use in Maps
<CR>             : carriage Return for maps
<ESC>            : Escape
<LEADER>         : normally \
<BAR>            : | pipe
<BACKSPACE>      : backspace
<SILENT>         : No hanging shell window
"display RGB colour under the cursor eg #445588
:nmap <leader>c :hi Normal guibg=#<c-r>=expand("<cword>")<cr><cr>
map <f2> /price only\\|versus/ :in a map need to backslash the \
" type table,,, to get <table></table>       ### Cool ###
imap ,,, <esc>bdwa<<esc>pa><cr></<esc>pa><esc>kA
" list current mappings of all your function keys
:for i in range(1, 12) | execute("map <F".i.">") | endfor   [N]
" for your .vimrc
:cab ,f :for i in range(1, 12) \| execute("map <F".i.">") \| endfor
"chain commands in abbreviation
cabbrev vrep tabe class.inc \| tabe report.php   ## chain commands [N]
----------------------------------------
" Simple PHP debugging display all variables yanked into register a
iab phpdb exit("<hr>Debug <C-R>a  ");
----------------------------------------
" Using a register as a map (preload registers in .vimrc)
:let @m=":'a,'bs/"
:let @s=":%!sort -u"
----------------------------------------
" Useful tricks
"ayy@a           : execute "Vim command" in a text file
yy@"             : same thing using unnamed register
u@.              : execute command JUST typed in
"ddw             : store what you delete in register d [N]
"ccaw            : store what you change in register c [N]
----------------------------------------
" Get output from other commands (requires external programs)
:r!ls -R         : reads in output of ls
:put=glob('**')  : same as above                 [N]
:r !grep "^ebay" file.txt  : grepping in content   [N]
:20,25 !rot13    : rot13 lines 20 to 25   [N]
!!date           : same thing (but replaces/filters current line)
" Sorting with external sort
:%!sort -u       : use an external program to filter content
:'a,'b!sort -u   : use an external program to filter content
!1} sort -u      : sorts paragraph (note normal mode!!)
:g/^$/;/^$/-1!sort : Sort each block (note the crucial ;)
" Sorting with internal sort
:sort /.*\%2v/   : sort all lines on second column [N]
" number lines  (linux or cygwin only)
:new | r!nl #                  [N]
----------------------------------------
" Multiple Files Management (Essential)
:bn              : goto next buffer
:bp              : goto previous buffer
:wn              : save file and move to next (super)
:wp              : save file and move to previous
:bd              : remove file from buffer list (super)
:bun             : Buffer unload (remove window but not from list)
:badd file.c     : file from buffer list
:b3              : go to buffer 3 [C]
:b main          : go to buffer with main in name eg main.c (ultra)
:sav php.html    : Save current file as php.html and "move" to php.html
:sav! %<.bak     : Save Current file to alternative extension (old way)
:sav! %:r.cfm    : Save Current file to alternative extension
:sav %:s/fred/joe/           : do a substitute on file name
:sav %:s/fred/joe/:r.bak2    : do a substitute on file name & ext.
:!mv % %:r.bak   : rename current file (DOS use Rename or DEL)
:help filename-modifiers
:e!              : return to unmodified file
:w c:/aaa/%      : save file elsewhere
:e #             : edit alternative file (also cntrl-^)
:rew             : return to beginning of edited files list (:args)
:brew            : buffer rewind
:sp fred.txt     : open fred.txt into a split
:sball,:sb       : Split all buffers (super)
:scrollbind      : in each split window
:map   <F5> :ls<CR>:e # : Pressing F5 lists all buffer, just type number
:set hidden      : Allows to change buffer w/o saving current buffer
----------------------------------------
" Quick jumping between splits
map <C-J> <C-W>j<C-W>_
map <C-K> <C-W>k<C-W>_
----------------------------------------
" Recording (BEST Feature of ALL)
qq  # record to q
your complex series of commands
q   # end recording
@q to execute
@@ to Repeat
5@@ to Repeat 5 times
qQ@qq                             : Make an existing recording q recursive [N]
" editing a register/recording
"qp                               :display contents of register q (normal mode)
<ctrl-R>q                         :display contents of register q (insert mode)
" you can now see recording contents, edit as required
"qdd                              :put changed contacts back into q
@q                                :execute recording/register q
" Operating a Recording on a Visual BLOCK (blockwise)
1) define recording/register
qq:s/ to/ from/g^Mq
2) Define Visual BLOCK
V}
3) hit : and the following appears
:'<,'>
4)Complete as follows
:'<,'>norm @q
----------------------------------------
"combining a recording with a map (to end up in command mode)
"here we operate on a file with a recording, then move to the next file [N]
:nnoremap ] @q:update<bar>bd
----------------------------------------
" Visual is the newest and usually the most intuitive editing mode
" Visual basics
v                               : enter visual mode
V                               : visual mode whole line
<C-V>                           : enter VISUAL BLOCKWISE mode (remap on Windows to say C-Q *C*
gv                              : reselect last visual area (ultra)
o                               : navigate visual area
"*y or "+y                      : yank visual area into paste buffer  [C]
V%                              : visualise what you match
V}J                             : Join Visual block (great)
V}gJ                            : Join Visual block w/o adding spaces
`[v`]                           : Highlight last insert
:%s/\%Vold/new/g                : Do a substitute on last visual area [N]
----------------------------------------
" Delete 8th and 9th characters of 10 successive lines [C]
08l<c-v>10j2ld  (use Control Q on win32) [C]
----------------------------------------
" how to copy a set of columns using VISUAL BLOCK
" visual block (AKA columnwise selection) (NOT BY ordinary v command)
<C-V> then select "column(s)" with motion commands (win32 <C-Q>)
then c,d,y,r etc
----------------------------------------
" how to overwrite a visual-block of text with another such block [C]
" move with hjkl etc
Pick the first block: ctrl-v move y
Pick the second block: ctrl-v move P <esc>
----------------------------------------
" text objects :h text-objects                                     [C]
daW                                   : delete contiguous non whitespace
di<   yi<  ci<                        : Delete/Yank/Change HTML tag contents
da<   ya<  ca<                        : Delete/Yank/Change whole HTML tag
dat   dit                             : Delete HTML tag pair
diB   daB                             : Empty a function {}
das                                   : delete a sentence
----------------------------------------
" _vimrc essentials
:imap <TAB> <C-N>                     : set tab to complete [N]
:set incsearch : jumps to search word as you type (annoying but excellent)
:set wildignore=*.o,*.obj,*.bak,*.exe : tab complete now ignores these
:set shiftwidth=3                     : for shift/tabbing
:set vb t_vb=".                       : set silent (no beep)
:set browsedir=buffer                 : Maki GUI File Open use current directory
----------------------------------------
" launching Win IE
:nmap ,f :update<CR>:silent !start c:\progra~1\intern~1\iexplore.exe file://%:p<CR>
:nmap ,i :update<CR>: !start c:\progra~1\intern~1\iexplore.exe <cWORD><CR>
----------------------------------------
" FTPing from VIM
cmap ,r  :Nread ftp://209.51.134.122/public_html/index.html
cmap ,w  :Nwrite ftp://209.51.134.122/public_html/index.html
gvim ftp://www.somedomain.com/index.html # uses netrw.vim
----------------------------------------
" appending to registers (use CAPITAL)
" yank 5 lines into "a" then add a further 5
"a5yy
10j
"A5yy
----------------------------------------
[I     : show lines matching word under cursor <cword> (super)
----------------------------------------
" Conventional Shifting/Indenting
:'a,'b>>
" visual shifting (builtin-repeat)
:vnoremap < <gv
:vnoremap > >gv
" Block shifting (magic)
>i{
>a{
" also
>% and <%
==                            : index current line same as line above [N]
----------------------------------------
" Redirection & Paste register *
:redir @*                    : redirect commands to paste buffer
:redir END                   : end redirect
:redir >> out.txt            : redirect to a file
" Working with Paste buffer
"*yy                         : yank curent line to paste
"*p                          : insert from paste buffer
" yank to paste buffer (ex mode)
:'a,'by*                     : Yank range into paste
:%y*                         : Yank whole buffer into paste
:.y*                         : Yank Current line to paster
" filter non-printable characters from the paste buffer
" useful when pasting from some gui application
:nmap <leader>p :let @* = substitute(@*,'[^[:print:]]','','g')<cr>"*p
:set paste                    : prevent vim from formatting pasted in text *N*
----------------------------------------
" Re-Formatting text
gq}                          : Format a paragraph
gqap                         : Format a paragraph
ggVGgq                       : Reformat entire file
Vgq                          : current line
" break lines at 70 chars, if possible after a ;
:s/.\{,69\};\s*\|.\{,69\}\s\+/&\r/g
----------------------------------------
" Operate command over multiple files
:argdo %s/foo/bar/e          : operate on all files in :args
:bufdo %s/foo/bar/e
:windo %s/foo/bar/e
:argdo exe '%!sort'|w!       : include an external command
:bufdo exe "normal @q" | w   : perform a recording on open files
:silent bufdo !zip proj.zip %:p   : zip all current files
----------------------------------------
" Command line tricks
gvim -h                    : help
ls | gvim -                : edit a stream!!
cat xx | gvim - -c "v/^\d\d\|^[3-9]/d " : filter a stream
gvim -o file1 file2        : open into a horizontal split (file1 on top, file2 on bottom) [C]
gvim -O file1 file2        : open into a vertical split (side by side,for comparing code) [N]
" execute one command after opening file
gvim.exe -c "/main" joe.c  : Open joe.c & jump to "main"
" execute multiple command on a single file
vim -c "%s/ABC/DEF/ge | update" file1.c
" execute multiple command on a group of files
vim -c "argdo %s/ABC/DEF/ge | update" *.c
" remove blocks of text from a series of files
vim -c "argdo /begin/+1,/end/-1g/^/d | update" *.c
" Automate editing of a file (Ex commands in convert.vim)
vim -s "convert.vim" file.c
"load VIM without .vimrc and plugins (clean VIM) e.g. for HUGE files
gvim -u NONE -U NONE -N
" Access paste buffer contents (put in a script/batch file)
gvim -c 'normal ggdG"*p' c:/aaa/xp
" print paste contents to default printer
gvim -c 's/^/\=@*/|hardcopy!|q!'
" gvim's use of external grep (win32 or *nix)
:!grep somestring *.php     : creates a list of all matching files [C]
" use :cn(ext) :cp(rev) to navigate list
:h grep
" Using vimgrep with copen                              [N]
:vimgrep /keywords/ *.php
:copen
----------------------------------------
" GVIM Difference Function (Brilliant)
gvim -d file1 file2        : vimdiff (compare differences)
dp                         : "put" difference under cursor to other file
do                         : "get" difference under cursor from other file
" complex diff parts of same file [N]
:1,2yank a | 7,8yank b
:tabedit | put a | vnew | put b
:windo diffthis 
----------------------------------------
" Vim traps
In regular expressions you must backslash + (match 1 or more)
In regular expressions you must backslash | (or)
In regular expressions you must backslash ( (group)
In regular expressions you must backslash { (count)
/fred\+/                   : matches fred/freddy but not free
/\(fred\)\{2,3}/           : note what you have to break
----------------------------------------
" \v or very magic (usually) reduces backslashing
/codes\(\n\|\s\)*where  : normal regexp
/\vcodes(\n|\s)*where   : very magic
----------------------------------------
" pulling objects onto command/search line (SUPER)
<C-R><C-W> : pull word under the cursor into a command line or search
<C-R><C-A> : pull WORD under the cursor into a command line or search
<C-R>-                  : pull small register (also insert mode)
<C-R>[0-9a-z]           : pull named registers (also insert mode)
<C-R>%                  : pull file name (also #) (also insert mode)
<C-R>=somevar           : pull contents of a variable (eg :let sray="ray[0-9]")
----------------------------------------
" List your Registers
:reg             : display contents of all registers
:reg a           : display content of register a
:reg 12a         : display content of registers 1,2 & a [N]
"5p              : retrieve 5th "ring" 
"1p....          : retrieve numeric registers one by one
:let @y='yy@"'   : pre-loading registers (put in .vimrc)
qqq              : empty register "q"
qaq              : empty register "a"
:reg .-/%:*"     : the seven special registers [N]
:reg 0           : what you last yanked, not affected by a delete [N]
"_dd             : Delete to blackhole register "_ , don't affect any register [N]
----------------------------------------
" manipulating registers
:let @a=@_              : clear register a
:let @a=""              : clear register a
:let @a=@"              : Save unnamed register [N]
:let @*=@a              : copy register a to paste buffer
:let @*=@:              : copy last command to paste buffer
:let @*=@/              : copy last search to paste buffer
:let @*=@%              : copy current filename to paste buffer
----------------------------------------
" help for help (USE TAB)
:h quickref             : VIM Quick Reference Sheet (ultra)
:h tips                 : Vim's own Tips Help
:h visual<C-D><tab>     : obtain  list of all visual help topics
                        : Then use tab to step thru them
:h ctrl<C-D>            : list help of all control keys
:helpg uganda           : grep HELP Files use :cn, :cp to find next
:helpgrep edit.*director: grep help using regexp
:h :r                   : help for :ex command
:h CTRL-R               : normal mode
:h /\r                  : what's \r in a regexp (matches a <CR>)
:h \\zs                 : double up backslash to find \zs in help
:h i_CTRL-R             : help for say <C-R> in insert mode
:h c_CTRL-R             : help for say <C-R> in command mode
:h v_CTRL-V             : visual mode
:h tutor                : VIM Tutor
<C-]>                   : jump to {keyword} under  cursor in help file [C]
<C-[>, <C-T>            : Move back & Forth in HELP History
gvim -h                 : VIM Command Line Help
:cabbrev h tab help     : open help in a tab [N]
----------------------------------------
" where was an option set
:scriptnames            : list all plugins, _vimrcs loaded (super)
:verbose set history?   : reveals value of history and where set
:function               : list functions
:func SearchCompl       : List particular function
----------------------------------------
" making your own VIM help
:helptags /vim/vim64/doc  : rebuild all *.txt help files in /doc
:help add-local-help
" save this page as a VIM Help File [N]
:sav! $VIMRUNTIME/doc/vimtips.txt|:1,/^__BEGIN__/d|:/^__END__/,$d|:w!|:helptags $VIMRUNTIME/doc
----------------------------------------
" running file thru an external program (eg php)
map   <f9>   :w<CR>:!c:/php/php.exe %<CR>
map   <f2>   :w<CR>:!perl -c %<CR>
----------------------------------------
" capturing output of current script in a separate buffer
:new | r!perl #                   : opens new buffer,read other buffer
:new! x.out | r!perl #            : same with named file
:new+read!ls
----------------------------------------
" create a new buffer, paste a register "q" into it, then sort new buffer
:new +put q|%!sort
----------------------------------------
" Inserting DOS Carriage Returns
:%s/$/\<C-V><C-M>&/g          :  that's what you type
:%s/$/\<C-Q><C-M>&/g          :  for Win32
:%s/$/\^M&/g                  :  what you'll see where ^M is ONE character
----------------------------------------
" automatically delete trailing Dos-returns,whitespace
autocmd BufRead * silent! %s/[\r \t]\+$//
autocmd BufEnter *.php :%s/[ \t\r]\+$//e
----------------------------------------
" perform an action on a particular file or file type
autocmd VimEnter c:/intranet/note011.txt normal! ggVGg?
autocmd FileType *.pl exec('set fileformats=unix')
----------------------------------------
" Retrieving last command line command for copy & pasting into text
i<c-r>:
" Retrieving last Search Command for copy & pasting into text
i<c-r>/
----------------------------------------
" more completions
<C-X><C-F>                        :insert name of a file in current directory
----------------------------------------
" Substituting a Visual area
" select visual area as usual (:h visual) then type :s/Emacs/Vim/ etc
:'<,'>s/Emacs/Vim/g               : REMEMBER you dont type the '<.'>
gv                                : Re-select the previous visual area (ULTRA)
----------------------------------------
" inserting line number into file
:g/^/exec "s/^/".strpart(line(".")."    ", 0, 4)
:%s/^/\=strpart(line(".")."     ", 0, 5)
:%s/^/\=line('.'). ' '
----------------------------------------
" *numbering lines VIM way*
:set number                       : show line numbers
:map <F12> :set number!<CR>       : Show linenumbers flip-flop
:%s/^/\=strpart(line('.')."        ",0,&ts)
" numbering lines (need Perl on PC) starting from arbitrary number
:'a,'b!perl -pne 'BEGIN{$a=223} substr($_,2,0)=$a++'
" Produce a list of numbers
" Type in number on line say 223 in an empty file
qqmnYP`n^Aq                       : in recording q repeat with @q
" increment existing numbers to end of file (type <c-a> as 5 characters)
:.,$g/^\d/exe "normal! \<c-a>"
" advanced incrementing
http://vim.sourceforge.net/tip_view.php?tip_id=150
----------------------------------------
" *advanced incrementing* (really useful)
" put following in _vimrc
let g:I=0
function! INC(increment)
let g:I =g:I + a:increment
return g:I
endfunction
" eg create list starting from 223 incrementing by 5 between markers a,b
:let I=223
:'a,'bs/^/\=INC(5)/
" create a map for INC
cab viminc :let I=223 \| 'a,'bs/$/\=INC(5)/
----------------------------------------
" *generate a list of numbers*  23-64
o23<ESC>qqYp<C-A>q40@q
----------------------------------------
" editing/moving within current insert (Really useful)
<C-U>                             : delete all entered
<C-W>                             : delete last word
<HOME><END>                       : beginning/end of line
<C-LEFTARROW><C-RIGHTARROW>       : jump one word backwards/forwards
<C-X><C-E>,<C-X><C-Y>             : scroll while staying put in insert
----------------------------------------
#encryption (use with care: DON'T FORGET your KEY)
:X                                : you will be prompted for a key
:h :X
----------------------------------------
" modeline (make a file readonly etc) must be in first/last 5 lines
// vim:noai:ts=2:sw=4:readonly:
" vim:ft=html:                    : says use HTML Syntax highlighting
:h modeline
----------------------------------------
" Creating your own GUI Toolbar entry
amenu  Modeline.Insert\ a\ VIM\ modeline <Esc><Esc>ggOvim:ff=unix ts=4 ss=4<CR>vim60:fdm=marker<esc>gg
----------------------------------------
" A function to save word under cursor to a file
function! SaveWord()
   normal yiw
   exe ':!echo '.@0.' >> word.txt'
endfunction
map ,p :call SaveWord()
----------------------------------------
" function to delete duplicate lines
function! Del()
 if getline(".") == getline(line(".") - 1)
   norm dd
 endif
endfunction

:g/^/ call Del()
----------------------------------------
" Digraphs (non alpha-numerics)
:digraphs                         : display table
:h dig                            : help
i<C-K>e'                          : enters é
i<C-V>233                         : enters é (Unix)
i<C-Q>233                         : enters é (Win32)
ga                                : View hex value of any character
#Deleting non-ascii characters (some invisible)
:%s/[\x00-\x1f\x80-\xff]/ /g      : type this as you see it
:%s/[<C-V>128-<C-V>255]//gi       : where you have to type the Control-V
:%s/[€-ÿ]//gi                     : Should see a black square & a dotted y
:%s/[<C-V>128-<C-V>255<C-V>01-<C-V>31]//gi : All pesky non-asciis
:exec "norm /[\x00-\x1f\x80-\xff]/"        : same thing
#Pull a non-ascii character onto search bar
yl/<C-R>"                         :
/[^a-zA-Z0-9_[:space:][:punct:]]  : search for all non-ascii
----------------------------------------
" All file completions grouped (for example main_c.c)
:e main_<tab>                     : tab completes
gf                                : open file under cursor  (normal)
main_<C-X><C-F>                   : include NAME of file in text (insert mode)
----------------------------------------
" Complex Vim
" swap two words
:%s/\<\(on\|off\)\>/\=strpart("offon", 3 * ("off" == submatch(0)), 3)/g
" swap two words
:vnoremap <C-X> <Esc>`.``gvP``P
" Swap word with next word
nmap <silent> gw    "_yiw:s/\(\%#\w\+\)\(\_W\+\)\(\w\+\)/\3\2\1/<cr><c-o><c-l> [N]
----------------------------------------
" Convert Text File to HTML
:runtime! syntax/2html.vim        : convert txt to html
:h 2html
----------------------------------------
" VIM has internal grep
:grep some_keyword *.c            : get list of all c-files containing keyword
:cn                               : go to next occurrence
----------------------------------------
" Force Syntax coloring for a file that has no extension .pl
:set syntax=perl
" Remove syntax coloring (useful for all sorts of reasons)
:set syntax off
" change coloring scheme (any file in ~vim/vim??/colors)
:colorscheme blue
:colorscheme morning     : good fallback colorscheme *N*
" Force HTML Syntax highlighting by using a modeline
# vim:ft=html:
" Force syntax automatically (for a file with non-standard extension)
au BufRead,BufNewFile */Content.IE?/* setfiletype html
----------------------------------------
:set noma (non modifiable)        : Prevents modifications
:set ro (Read Only)               : Protect a file from unintentional writes
----------------------------------------
" Sessions (Open a set of files)
gvim file1.c file2.c lib/lib.h lib/lib2.h : load files for "session"
:mksession                        : Make a Session file (default Session.vim)
:mksession MySession.vim          : Make a Session file named file [C]
:q
gvim -S                           : Reload all files (loads Session.vim) [C]
gvim -S MySession.vim             : Reload all files from named session [C]
----------------------------------------
#tags (jumping to subroutines/functions)
taglist.vim                       : popular plugin
:Tlist                            : display Tags (list of functions)
<C-]>                             : jump to function under cursor
----------------------------------------
" columnise a csv file for display only as may crop wide columns
:let width = 20
:let fill=' ' | while strlen(fill) < width | let fill=fill.fill | endwhile
:%s/\([^;]*\);\=/\=strpart(submatch(1).fill, 0, width)/ge
:%s/\s\+$//ge
" Highlight a particular csv column (put in .vimrc)
function! CSVH(x)
    execute 'match Keyword /^\([^,]*,\)\{'.a:x.'}\zs[^,]*/'
    execute 'normal ^'.a:x.'f,'
endfunction
command! -nargs=1 Csv :call CSVH(<args>)
" call with
:Csv 5                             : highlight fifth column
----------------------------------------
zf1G      : fold everything before this line [N]
" folding : hide sections to allow easier comparisons
zf}                               : fold paragraph using motion
v}zf                              : fold paragraph using visual
zf'a                              : fold to mark
zo                                : open fold
zc                                : re-close fold
" also visualise a section of code then type zf [N]
:help folding
zfG      : fold everything after this line [N]
----------------------------------------
" displaying "non-asciis"
:set list
:h listchars
----------------------------------------
" How to paste "normal vim commands" w/o entering insert mode
:norm qqy$jq
----------------------------------------
" manipulating file names
:h filename-modifiers             : help
:w %                              : write to current file name
:w %:r.cfm                        : change file extention to .cfm
:!echo %:p                        : full path & file name
:!echo %:p:h                      : full path only
:!echo %:t                        : filename only
:reg %                            : display filename
<C-R>%                            : insert filename (insert mode)
"%p                               : insert filename (normal mode)
/<C-R>%                           : Search for file name in text
----------------------------------------
" delete without destroying default buffer contents
"_d                               : what you've ALWAYS wanted
"_dw                              : eg delete word (use blackhole)
----------------------------------------
" pull full path name into paste buffer for attachment to email etc
nnoremap <F2> :let @*=expand("%:p")<cr> :unix
nnoremap <F2> :let @*=substitute(expand("%:p"), "/", "\\", "g")<cr> :win32
----------------------------------------
" Simple Shell script to rename files w/o leaving vim
$ vim
:r! ls *.c
:%s/\(.*\).c/mv & \1.bla
:w !sh
:q!
----------------------------------------
" count words/lines in a text file
g<C-G>                                 # counts words
:echo line("'b")-line("'a")            # count lines between markers a and b [N]
:'a,'bs/^//n                           # count lines between markers a and b
:'a,'bs/somestring//gn                 # count occurences of a string
----------------------------------------
" example of setting your own highlighting
:syn match DoubleSpace "  "
:hi def DoubleSpace guibg=#e0e0e0
----------------------------------------
" reproduce previous line word by word
imap ]  @@@<ESC>hhkyWjl?@@@<CR>P/@@@<CR>3s
nmap ] i@@@<ESC>hhkyWjl?@@@<CR>P/@@@<CR>3s
" Programming keys depending on file type
:autocmd bufenter *.tex map <F1> :!latex %<CR>
:autocmd bufenter *.tex map <F2> :!xdvi -hush %<.dvi&<CR>
" allow yanking of php variables with their dollar [N]
:autocmd bufenter *.php :set iskeyword+=\$ 
----------------------------------------
" reading Ms-Word documents, requires antiword (not docx)
:autocmd BufReadPre *.doc set ro
:autocmd BufReadPre *.doc set hlsearch!
:autocmd BufReadPost *.doc %!antiword "%"
----------------------------------------
" a folding method
vim: filetype=help foldmethod=marker foldmarker=<<<,>>>
A really big section closed with a tag <<< 
--- remember folds can be nested --- 
Closing tag >>> 
----------------------------------------
" Return to last edit position (You want this!) [N]
autocmd BufReadPost *
     \ if line("'\"") > 0 && line("'\"") <= line("$") |
     \   exe "normal! g`\"" |
     \ endif
----------------------------------------
" store text that is to be changed or deleted in register a
"act<                                 :  Change Till < [N]
----------------------------------------
"installing/getting latest version of vim on Linux (replace tiny-vim) [N]
yum install vim-common vim-enhanced vim-minimal
----------------------------------------
# using gVIM with Cygwin on a Windows PC
if has('win32')
source $VIMRUNTIME/mswin.vim
behave mswin
set shell=c:\\cygwin\\bin\\bash.exe shellcmdflag=-c shellxquote=\"
endif
----------------------------------------
" *Just Another Vim Hacker JAVH*
vim -c ":%s%s*%Cyrnfr)fcbafbe[Oenz(Zbbyranne%|:%s)[[()])-)Ig|norm Vg?"
----------------------------------------
vim:tw=78:ts=8:ft=help:norl:
__END__
----------------------------------------
"Read Vimtips into a new vim buffer (needs w3m.sourceforge.net)
:tabe | :r ! w3m -dump "http://zzapper.co.uk/vimtips.html"    [C]
:silent r ! lynx -dump "http://zzapper.co.uk/vimtips.html" [N]
" read webpage source html into vim
gvim http://www.zzapper.co.uk/vimtips.html &
----------------------------------------
updated version at http://www.zzapper.co.uk/vimtips.html
----------------------------------------
Please email any errors, tips etc to
vim@rayninfo.co.uk
" Information Sources
----------------------------------------
www.vim.org
Vim Wiki *** VERY GOOD *** [N]
Vim Use VIM newsgroup [N]
comp.editors
groups.yahoo.com/group/vim "VIM" specific newsgroup
VIM Webring
VimTips PDF Version (PRINTABLE!)
Vimtips in Belarusian 
----------------------------------------
" : commands to neutralise < for HTML display and publish
" use yy@" to execute following commands
:w!|sav! vimtips.html|:/^__BEGIN__/,/^__END__/s#<#\<#g|:w!|:!vimtipsftp




01000011x10001000x000100000100x010000010010
ShellScript
https://www.shellscript.sh/

Acl
http://www.gsp.com/cgi-bin/mdroid.cgi?topic=extattrctl
http://www.onlamp.com/pub/a/bsd/2003/08/14/freebsd_acls.html
https://linux.die.net/man/1/setfacl
https://www.bing.com/search?q=ACLs+with+Samba+andWindows&src=IE-TopResult&FORM=IETR02&conversationid=
https://en.wikipedia.org/wiki/Chmod
See references https://en.wikipedia.org/wiki/Access_control_list
See see also https://en.wikipedia.org/wiki/Discretionary_access_control
https://security.stackexchange.com/questions/63518/mac-vs-dac-vs-rbac
Difference b/w mac and dac
With MAC, admins creates a set of levels and each user is linked with a specific access level. He can access all the resources that are not greater than his access level. In contrast, each resource in DAC has a list of users who can access it. DAC provides access by identity of the user and not by permission level.
Rbac

Canaries
http://antoniobarresi.com/security/exploitdev/2014/05/03/64bitexploitation/
https://stackoverflow.com/questions/24465014/gcc-generate-canary-or-not


Authentication and Access control in linux os
(Awesome)https://courses.cs.washington.edu/courses/cse484/11au/sections/section6.pdf
http://www.tenouk.com/linuxunixsecurityfeatures.html
https://link.springer.com/chapter/10.1007/978-3-642-23312-8_28
https://www.safaribooksonline.com/library/view/linux-server-hacks/0596100825/ch01.html
(Awesome)https://pdfs.semanticscholar.org/presentation/89f5/513e99544345cd86dfd7ef8ab386459cdd25.pdf
Book https://www.amazon.com/Foundations-Security-Every-Programmer-Experts/dp/1590597842
College 
https://courses.cs.washington.edu/courses/cse484/17au/schedule.html
https://courses.cs.washington.edu/courses/cse484/11au/sections/

In above college in different year course is totally different.


Buffer-overflow
http://www.cse.scu.edu/~tschwarz/coen152_05/
Howard and LeBlanc: Writing Secure Code, 2nd edition
https://web.archive.org/web/20050325202927/http://www.nextgenss.com/papers/advanced_sql_injection.pdf

Dangling pointer
https://developers.slashdot.org/story/10/04/13/1951246/how-to-exploit-null-pointers
https://security.stackexchange.com/questions/61948/how-do-i-make-a-working-example-of-a-dangling-pointers-exploit-or-where-do-i
https://blogs.oracle.com/linux/much-ado-about-null%3a-exploiting-a-kernel-null-dereference-v2
Causes of dangling pointer
1.when global variable points the some variable in function or local block.
2.initialize ptr=NULL immediate after block completion
Solution:
After deallocation of memory, immediate initialize pointer to NULL
http://codingstreet.com/what-is-dangling-pointer/
(Awesome)http://www.cs.virginia.edu/~ww6r/CS4630/syllabus.html

linux filesystem
http://www.tldp.org/LDP/intro-linux/html/index.html

Format String
http://www.cs.virginia.edu/~ww6r/CS4630/

tocttou
https://www.cl.cam.ac.uk/~rja14/Papers/SE-06.pdf
https://www.bing.com/search?q=tocttou&src=IE-TopResult&FORM=IETR02&conversationid=
https://github.com/tocttou
http://users.cis.fiu.edu/~weijp/Jinpeng_Homepage_files/toctou-fast05.pdf 
https://www.usenix.org/sites/default/files/conference/protected-files/michele_woot12_slides.pdf
http://www.sis.pitt.edu/jjoshi/courses/IS2620/Fall17/Lectures.html
http://www.sis.pitt.edu/jjoshi/courses/IS2620/Fall17/Lecture6.pdf
Ropfttw
http://shell-storm.org/talks/ROP_course_lecture_jonathan_salwan_2014.pdf
https://www.youtube.com/watch?v=5FJxC59hMRY
https://drive.google.com/file/d/0B3U0fxyeeTTdcDJhbm5DcU1OQU0/view
https://drive.google.com/file/d/0B3U0fxyeeTTdaGdQWGFvUFg5czQ/view
https://en.wikipedia.org/wiki/Address_space_layout_randomization

Bypassing sehop
https://repo.zenk-security.com/Reversing%20.%20cracking/Bypassing%20SEHOP.pdf

Heap_spray
https://en.wikipedia.org/wiki/Heap_spraying
(Awesome)http://security.cs.rpi.edu/courses/binexp-spring2015/

Integer overflow
https://phoenhex.re/2017-06-02/arrayspread

X86-architecture
https://stackoverflow.com/questions/18417849/difference-between-flat-memory-model-and-protected-memory-model
https://en.wikipedia.org/wiki/Flat_memory_model
Linux uses flat memory model.
http://www.cs.virginia.edu/~evans/cs216/guides/x86.html
https://gotocon.com/dl/goto-chicago-2014/slides/MattGodbolt_X86InternalsForFunAndProfit.pdf
http://asmtutor.com/#lesson1
https://software.intel.com/en-us/articles/intel-sdm
https://stackoverflow.com/questions/1023593/how-to-write-hello-world-in-assembler-under-windows#answer-20032763
https://software.intel.com/sites/default/files/m/d/4/1/d/8/Introduction_to_x64_Assembly.pdf
https://aaronbloomfield.github.io/pdr/book/x86-64bit-asm-chapter.pdf
http://aaronbloomfield.github.io/pdr/book/x86-64bit-ccc-chapter.pdf
http://asmtutor.com/#lesson1
https://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html
https://web.archive.org/web/20041010205615/http://docs.cs.up.ac.za/programming/asm/derick_tut#syscalls
https://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html
https://stackoverflow.com/questions/9601427/is-inline-assembly-language-slower-than-native-c-code
http://www.agner.org/optimize/

Elf format(Executable and linkable format)
https://www.linuxjournal.com/article/1060

Calling convention
https://en.wikipedia.org/wiki/Calling_convention
https://stackoverflow.com/questions/41231637/how-does-a-function-call-work
https://eli.thegreenplace.net/2011/02/04/where-the-top-of-the-stack-is-on-x86/
https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Specifications
http://www.agner.org/optimize/
Kernel and boot processes
http://duartes.org/gustavo/blog/post/
http://www.tldp.org/LDP/intro-linux/html/index.html
http://www.science.unitn.it/~fiorella/guidelinux/tlk/node5.html
http://en.wikipedia.org/wiki/Reset_vector
https://www.cs.cmu.edu/~410-s07/p4/p4-boot.pdf

Tmap,smap,smep, virtualisation and hypervisor
For smep http://j00ru.vexillium.org/?p=783
For smap https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention
For tpm https://en.wikipedia.org/wiki/Trusted_Platform_Module
https://en.wikipedia.org/wiki/Address_space_layout_randomization

Side channel attack
https://en.wikipedia.org/wiki/Side-channel_attack
https://www.peerlyst.com/posts/a-collection-of-links-to-pdfs-of-papers-on-micro-architectural-side-channel-attacks-sorted-by-date-paul-harvey
Cache attack
https://en.wikipedia.org/wiki/CPU_cache
https://www.youtube.com/watch?v=vpGI1ggKzC4
https://www.youtube.com/channel/UCG1HuJcwjA0Cp7a2-iGfWug
http://palms.ee.princeton.edu/system/files/SP_vfinal.pdf
https://github.com/defuse/flush-reload-attacks
https://gruss.cc/files/cache_and_rowhammer_ruhrsec.pdf
https://www.blackhat.com/docs/us-16/materials/us-16-Hornby-Side-Channel-Attacks-On-Everyday-Applications.pdf
https://www.youtube.com/watch?v=DkWqLDSqHm8&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=18
http://web.cse.ohio-state.edu/~zhang.834/slides/tutorial17.pdf
https://conference.hitb.org/hitbsecconf2016ams/materials/D2T1%20-%20Anders%20Fogh%20-%20Cache%20Side%20Channel%20Attacks.pdf
http://www.cryptofails.com/post/70097430253/crypto-noobs-2-side-channel-attacks
Timing attack
https://www.youtube.com/watch?v=3v5Von-oNUg
https://jochen-hoenicke.de/trezor-power-analysis/
Acoustic attack
https://www.cs.tau.ac.il/~tromer/acoustic/
Search for lev pachnov
Daniel gruss
iaik graz university of technology
https://www.youtube.com/user/BlackHatOfficialYT/playlists?disable_polymer=1
https://rd.springer.com/chapter/10.1007/978-1-4419-1530-6_8
https://www.usenix.org/node/184416
https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-yarom.pdf
https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-gruss.pdf
https://www.blackhat.com/docs/us-16/materials/us-16-Hornby-Side-Channel-Attacks-On-Everyday-Applications.pdf
https://www.cs.unc.edu/~reiter/papers/2014/CCS1.pdf
https://github.com/IAIK/rowhammerjs
https://www.blackhat.com/presentations/bh-usa-07/De_Haas/Presentation/bh-usa-07-de_haas.pdf
https://en.wikipedia.org/wiki/Shared_memory
Evict and time
https://www.youtube.com/watch?v=ewe3-mUku94
https://eprint.iacr.org/2005/271.pdf
RowHammer
https://www.blackhat.com/docs/us-15/materials/us-15-Seaborn-Exploiting-The-DRAM-Rowhammer-Bug-To-Gain-Kernel-Privileges-wp.pdf
https://www.youtube.com/watch?v=1iBpLhFN_OA
https://www.blackhat.com/docs/us-15/materials/us-15-Seaborn-Exploiting-The-DRAM-Rowhammer-Bug-To-Gain-Kernel-Privileges.pdf
https://www.blackhat.com/docs/eu-16/materials/eu-16-Lipp-ARMageddon-How-Your-Smartphone-CPU-Breaks-Software-Level-Security-And-Privacy-wp.pdf
(Awesome) https://www.vusec.net/projects/glitch/
Rowhammer on Armageddon
https://github.com/iaik/armageddon
https://mlq.me/
Moritz lipp
AES
http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
https://en.wikipedia.org/wiki/Rijndael_S-box
https://shanetully.com/2012/06/openssl-rsa-aes-and-c/
https://googleprojectzero.blogspot.co.uk/2015/03/exploiting-dram-rowhammer-bug-to-gain.html

Javascript Internals spidermonkey
http://www.phrack.org/issues/69/14.html#article

Computer organization 
http://pages.cs.wisc.edu/~arch/www/books.html
https://www.quora.com/What-is-a-good-book-to-learn-computer-architecture
http://williams.comp.ncat.edu/comp375/CacheSim.pdf
(Awesome )http://www.cs.uni.edu/~diesburg/courses/cs3430_sp14/sessions/s14/s14_caching_and_tlbs.pdf
(Awesome cache and tlb)http://inst.eecs.berkeley.edu/~cs162/sp11/sections/cs162-sp11-section6-answers.pdf
https://www.quora.com/What-is-the-difference-between-TLB-and-MMU-in-OS
http://www.agner.org/optimize/

Hardware reverse engineering
http://security.cs.rpi.edu/courses/hwre-spring2014/

Malware analysis
http://security.cs.rpi.edu/courses/malware-spring2013/
Misc
https://events.static.linuxfound.org/sites/events/files/slides/AFL%20filesystem%20fuzzing,%20Vault%202016_0.pdf
(Awesome list of links in last) https://dyjak.me/wp-content/uploads/2018/05/WarCon-2017-Interpreters-Under-Pressure.pdf
(Awesome)https://www.nds.rub.de/media/nds/arbeiten/2015/10/30/Tim_Guenther-EsPReSSO-BA.pdf
(Awesome book)https://download-mirror.savannah.gnu.org/releases/pgubook/ProgrammingGroundUp-1-0-booksize.pdf
https://archive.org/details/ToorconArchiveInfocon
https://techbeacon.com/best-security-conferences-2018
http://mirror.easyname.at/nongnu/pgubook/ProgrammingGroundUp-1-0-booksize.pdf
http://www.agner.org/optimize/
https://digteam.github.io/assets/tocttou.pdf (Don't know what that is)
https://www.youtube.com/user/SourcefireInc/playlists?disable_polymer=1
https://www.youtube.com/channel/UCSii2fuiLLlGqaR6sR_y0rA
https://www.youtube.com/channel/UCDNzNvZlYK8jZLsUbdiGrsQ
●[1] http://cseweb.ucsd.edu/~hovav/talks/blackhat08.html
● [2] http://cseweb.ucsd.edu/~hovav/dist/sparc.pdf
● [3] https://github.com/0vercl0k/rp
● [4] http://ropshell.com/ropeme/
● [5] https://github.com/pakt/ropc
● [6] https://github.com/awailly/nrop
● [7] http://shell-storm.org/project/ROPgadget/
● [8] https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf
● [9] https://www.lst.inf.ethz.ch/research/publications/PPREW_2013/PPREW_2013.pdf
● [10] http://www.scs.stanford.edu/brop/bittau-brop.pdf
● [11] https://labs.portcullis.co.uk/blog/ohm-2013-review-of-returning-signals-for-fun-and-profit/
● [12] http://shell-storm.org/repo/Notepad/ROP-chain-generation-via-backtracking-and-state-machine.txt
http://www.tenouk.com/cncplusplusbufferoverflow.html
https://www.sei.cmu.edu/research-capabilities/all-work/display.cfm?customel_datapageid_4050=21274
https://www.youtube.com/channel/UCkysTPyA_48174c80rcITmA
https://www.youtube.com/channel/UCMNvAtT4ak2azKNk6UlB1QQ
https://github.com/vitalysim/Awesome-Hacking-Resources#reverse-engineering-buffer-overflow-and-exploit-development
https://software.intel.com/en-us/articles/intel-sdm#combined
http://www.tenouk.com/Bufferoverflowc/stackbasedbufferoverflow.html
https://www.sei.cmu.edu/research-capabilities/all-work/display.cfm?customel_datapageid_4050=21274
https://www.youtube.com/channel/UCkysTPyA_48174c80rcITmA
https://www.youtube.com/channel/UCMNvAtT4ak2azKNk6UlB1QQ
https://github.com/vitalysim/Awesome-Hacking-Resources#reverse-engineering-buffer-overflow-and-exploit-development
https://software.intel.com/en-us/articles/intel-sdm#combined
http://www.tenouk.com/Bufferoverflowc/stackbasedbufferoverflow.html
(Awesome )http://www.cs.virginia.edu/~evans/cs216/
https://github.com/offensive-security
https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/
(primary) http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/1/01_lecture.pdf
https://kitctf.de/writeups/0ctf2015/freenote/
https://sploitfun.wordpress.com/2015/03/04/heap-overflowusing-malloc-maleficarum/
http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modernheap-overflow/
http://wapiflapi.github.io/2014/11/17/hacklu-oreo-withret2dl-resolve/
http://phrack.org/issues/66/10.html
http://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt
(Awesome)https://samsclass.info/127/127_F15.shtml
(Awesome codes)pip install -r requirements.txt --no-index --find-links file:///tmp/packages
Compiler intrinsics
https://www.linuxjournal.com/content/introduction-gcc-compiler-intrinsics-vector-processing
https://stackoverflow.com/questions/7156908/sse-intrinsic-functions-reference
https://msdn.microsoft.com/en-us/library/hh977022.aspx
(Awesome list of vulnerablilities) https://www.cvedetails.com/
Misc2
https://dzone.com/articles/how-to-check-linux-process-deeply-with-common-sens
https://doc.lagout.org/programmation/
(Triple awesome) https://renenyffenegger.ch/notes/development/languages/C-C-plus-plus/GCC/create-libraries/index
https://gms.tf/ld_library_path-considered-harmful.html
(Awesome book resources) https://www.linuxtopia.org/online_books/
https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Rants%26Writeups/Hacking%20Team%20Writeup.md
https://www.mwrinfosecurity.com/events/past-events/
(Awesome)https://www.cs.bgu.ac.il/~mahlert/TCPIP_Implementation/TCPIP_Implementation.pdf
(Awesome)https://www.wiley.com/en-gb/Efficient+Algorithms+for+MPEG+Video+Compression-p-9780471379423
(Awesome Alternatives of exploit db)https://security.stackexchange.com/questions/2715/exploit-db-like-websites-where-people-can-search-for-security-bugs
https://leotindall.com/tutorial/an-intro-to-x86_64-reverse-engineering/
http://resources.infosecinstitute.com/x86-assembly-reverse-engineering-part-2/
https://smtebooks.com/book/602/practical-reverse-engineering-x86-x64-pdf
http://overthewire.org/wargames/bandit/bandit0.html
https://github.com/RPISEC/MBE
https://jochen-hoenicke.de/trezor-power-analysis/
https://eprint.iacr.org/2017/1169.pdf
http://media.ntu.edu.sg/NewsReleases/Pages/newsdetail.aspx?news=e57faffc-24ea-4034-9181-f5fea9850690
https://github.com/mseaborn
https://github.com/HackathonHackers/groups
https://github.com/HackathonHackers/personal-sites
https://blog.feedspot.com/hacker_blogs/
https://github.com/FabioBaroni/awesome-chinese-infosec-websites
https://github.com/spacehackersclub/awesome-spacehackers
https://heimdalsecurity.com/blog/best-twitter-cybersec-accounts/#cybersec specialists
(makefile)https://gist.github.com/hallettj/29b8e7815b264c88a0a0ee9dcddb6210
(makefile awesome)http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
(MMDense LSTM)https://scirate.com/arxiv/1805.02410
https://github.com/pettarin/awesome-python-audio-research
https://github.com/ganny26/awesome-audioqr
https://github.com/ybayle/awesome-deep-learning-music
https://github.com/sbrugman/deep-learning-papers#visual
https://sisec.inria.fr/
http://www.brendangregg.com/perf.html
https://github.com/RRZE-HPC/likwid
(Awesome)https://sourceware.org/glibc/wiki/AgnerWishlist
(Awesome)https://wiki.osdev.org/Books
(Awesome os list)http://pages.cs.wisc.edu/~remzi/OSTEP/
(Awesome Aweome)https://wiki.osdev.org/Expanded_Main_Page
(Awesome Linux os)http://man7.org/tlpi/
(Awesome linux)http://people.ds.cam.ac.uk/pmb39/Linux/
https://totalhash.cymru.com/
(Awesome)http://thestarman.pcministry.com/asm/
http://thestarman.pcministry.com/asm/debug/Segments.html
https://web.archive.org/web/20130511233621/http://www.asmcommunity.net:80/book/
https://alicebob.cryptoland.net/understanding-the-montgomery-reduction-algorithm/
(Awesome) https://doc.lagout.org/security/
http://timetobleed.com/
(Awesome Awesome lots and lots of kernel video)https://www.youtube.com/user/hupstream/playlists
https://softwareengineering.stackexchange.com/questions/200214/cross-compile-arm-program-to-intel
(Elf format)https://www.youtube.com/watch?v=t09LFtfy4JU
OS security
https://github.com/maxking/linux-security-papers
http://namei.org/presentations/linux-kernel-security-kca09.pdf
http://namei.org/presentations/
http://kernsec.org/wiki/index.php/Main_Page
https://medium.com/@XiaohanZeng/i-interviewed-at-five-top-companies-in-silicon-valley-in-five-days-and-luckily-got-five-job-offers-25178cf74e0f
https://medium.com/@zainrehmani/how-i-got-interviews-and-job-offers-from-companies-like-facebook-google-microsoft-amazon-dd4080b218d4
Arm Security
https://github.com/IAIK
https://www.blackhat.com/docs/eu-16/materials/eu-16-Lipp-ARMageddon-How-Your-Smartphone-CPU-Breaks-Software-Level-Security-And-Privacy-wp.pdf
https://doc.lagout.org/security/XXXX_ARM_exploitation.pdf
http://mazsola.iit.uni-miskolc.hu/~drdani/docs_arm/
(Tells about gcc arm)http://thehackerworkshop.com/?p=391
https://www.youtube.com/watch?v=eM6TKcIwqI4
https://azeria-labs.com/
(Awesome Combining c and c++) https://stackoverflow.com/questions/3789340/combining-c-and-c-how-does-ifdef-cplusplus-work
https://blahcat.github.io/2017/06/25/qemu-images-to-play-with/
http://www.toves.org/books/arm/
Shared Memory
https://www.dfrws.org/sites/default/files/session-files/paper-monitoring_access_to_shared_memory-mapped_files.pdf

Android
https://www.dei.unipd.it/~fantozzi/esp1617/files/Android%20NDK.pdf
https://blog.xamarin.com/preparing-for-native-library-linking-changes-in-android-n/
https://link.springer.com/content/pdf/10.1007/978-1-4302-6131-5_7.pdf
https://rathodpratik.wordpress.com/2013/03/24/build-cc-executables-for-android-using-ndk/
https://groups.google.com/forum/#!topic/android-ndk/8oq_QcNtuOY
http://www.ikerhurtado.com/android-ndk-build-system
(Awesome) http://android.mk/
http://technologeeks.com/course.jl?course=AIRE
http://androiddoc.qiniudn.com/tools/help/shell.html
http://newandroidbook.com/code/android-6.0.0_r1/ndk/docs/Programmers_Guide/html/md_1__concepts__concepts.html#nstl
http://web.guohuiwang.com/technical-notes/nativelauncher
https://biblioteka.awf.katowice.pl/docs/lfi0d3o.php?cesy=android-run-adb-in-code
http://grokbase.com/t/gg/android-ndk/123tfxvqyb/how-can-i-run-c-binary-executable-file-in-android-from-android-shell
http://gimite.net/en/index.php?Run%20native%20executable%20in%20Android%20App
https://www.arc4dia.com/blog/building-and-debugging-command-line-programs-on-android/
https://source.android.com/devices/architecture/hidl/
https://developers.google.com/training/android/
https://www.anysoftwaretools.com/best-android-development-resources/
Best forums to discuss android
https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html
https://www.all-things-android.com/content/understanding-android-file-hierarchy
https://code.tutsplus.com/tutorials/advanced-android-getting-started-with-the-ndk--mobile-2152
(Awesome)http://betelco.blogspot.co.uk/2010/01/buildingdebugging-android-native-c.html
https://stackoverflow.com/questions/12995030/how-to-use-adb-pull-command
https://stackoverflow.com/questions/8650407/how-to-copy-selected-files-from-android-with-adb-pull
https://stackoverflow.com/questions/9868309/how-to-compile-c-into-an-executable-binary-file-and-run-it-in-android-from-andro
https://www.quora.com/What-is-the-best-book-for-understanding-the-Android-operating-system
https://stackoverflow.com/questions/48069141/android-shell-command-options-explained
(Awesome and Simple)ftp://ftp.wayne.edu/ldp/en/Linux-Android-HOWTO/
(Awesome)https://hub.packtpub.com/creating-compiling-and-deploying-native-projects-android-ndk/
https://stackoverflow.com/questions/1636901/can-linux-apps-be-run-in-android
http://wyatt8740.no-ip.org/android.html
https://stackoverflow.com/questions/4703131/is-it-possible-to-run-a-native-arm-binary-on-a-non-rooted-android-phone
https://www.slideshare.net/kost/android-porting-47896523
Good books
https://nostarch.com/tlpi
https://lwn.net/Kernel/Index/

TLB attacks
https://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf

Cache
https://www.linuxjournal.com/article/7105
https://en.wikipedia.org/wiki/Cache_(computing)
https://www.thomas-krenn.com/en/wiki/Linux_Page_Cache_Basics
https://www.thegeekstuff.com/2012/02/linux-memory-swap-cache-shared-vm/
https://www.google.co.uk/search?q=cache+management+in+linux&oq=cache+management+in+linux&aqs=chrome..69i57.7055j0j1&sourceid=chrome&ie=UTF-8
https://www.youtube.com/channel/UCzf_XjIoKSf4Ve2fH7xn-3A
https://www.youtube.com/watch?v=SfPlpvtZ53o
http://www.informit.com/articles/article.aspx?p=29961&seqNum=4
https://www.usenix.org/legacy/event/usenix01/freenix01/full_papers/riel/riel_html/
http://www.infradead.org/~mchehab/kernel_docs/unsorted/cachetlb.html
https://stackoverflow.com/questions/4812137/does-the-mmu-mediate-everything-between-the-operating-system-and-physical-memory
(Awesome)  https://pdfs.semanticscholar.org/presentation/afe5/e48e9a61a804dd39d3c2f69b834a4d14d9c3.pdf
(Awesome)http://www.stillhq.com/pdfdb/000446/data.pdf
https://www.tomshardware.com/reviews/Intel-i7-nehalem-cpu,2041-2.html
http://cseweb.ucsd.edu/classes/su09/cse120/lectures/Lecture7.pdf
(Awesome)https://www.youtube.com/user/NmeictEnggTechnology/playlists
(Application binary inteface)https://www.youtube.com/watch?v=g8A0Wa7REZI
(Awesome Awesome Awesome) https://stackoverflow.com/questions/2171177/what-is-an-application-binary-interface-abi
https://www.everything2.com/index.pl?node=iBCS
(cache Linux kernel awesome)https://www.kernel.org/doc/gorman/html/understand/understand006.html
(Umass os)https://www.youtube.com/user/UMassOS/playlists
http://www.rfwireless-world.com/Tutorials/ARM-tutorial.html
https://www.youtube.com/watch?v=c9rQmBcJpfk
http://events17.linuxfoundation.org/sites/events/files/slides/slides_10.pdf
https://en.wikipedia.org/wiki/Cache_coherence
(Awesome os notes)https://cseweb.ucsd.edu/classes/su09/cse120/schedule.html
(Awesome cache notes)https://courses.cs.washington.edu/courses/cse378/09wi/lectures/lec15.pdf
http://snir.cs.illinois.edu/PDF/Temporal%20and%20Spatial%20Locality.pdf
https://cmaurice.fr/pdf/raid15_maurice.pdf
(Awesome Cache) https://eprint.iacr.org/2015/905.pdf
https://wiki.debian.org/Hugepages

Linux system calls
https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/

Arm asm
http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0205j/Cihccdja.html
http://www.ic.unicamp.br/~celio/mc404-s2-2015/docs/ARM-GCC-Inline-Assembler-Cookbook.pdf
(Most Awesome inline)http://www.ethernut.de/en/documents/arm-inline-asm.html
http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.100748_0606_00_en/ddx1471430827125.html
(Most Awesome)http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0056d/BABIJCGF.html
(Awesome arm commands reference)http://www.keil.com/support/man/docs/armasm/armasm_dom1361289850039.htm
https://github.com/kevinhooke/learning-arm-asm
http://alanclements.org/ARMgradedExamples.pdf
https://github.com/Croydon/assembler-arm

Arm cache architecture
https://community.arm.com/processors/b/blog/posts/caches-and-self-modifying-code
http://infocenter.arm.com/help/topic/com.arm.doc.ddi0201d/DDI0201D_arm946es_r1p1_trm.pdf
http://events17.linuxfoundation.org/sites/events/files/slides/slides_10.pdf
http://www.ee.ncu.edu.tw/~jfli/soc/lecture/ARM9.pdf
https://www.nxp.com/files-static/training_pdf/WBT_27182_IMX31_CPU.pdf

Inline assembly
https://www.cs.virginia.edu/~clc5q/gcc-inline-asm.pdf
https://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Extended-Asm.html#Extended-Asm
https://sourceware.org/binutils/docs-2.18/as/index.html
(Most Awesome best)http://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html
(Short and concise, derived form other two)https://www.codeproject.com/Articles/15971/Using-Inline-Assembly-in-C-C
(Something something)https://www.codeproject.com/Articles/5318/Extended-Inline-Assembly-in-GCC
http://cholla.mmto.org/computers/gcc_inline.html
https://locklessinc.com/articles/gcc_asm/
https://forum.osdev.org/viewtopic.php?f=1&t=26751

Security
https://github.com/cryptax/confsec
https://copperhead.co/blog/2015/05/11/aslr-android-zygote
https://grsecurity.net/
http://www.blackhat.com/presentations/bh-usa-07/Maynor_and_Graham/Whitepaper/bh-usa-07-maynor_and_graham-WP.pdf
https://www.rapid7.com/db/search?utf8=%E2%9C%93&q=android&t=v
https://www.cvedetails.com/
http://www.securityfocus.com/bid/102976
https://twitter.com/mingjian_zhou?lang=en
http://c0reteam.org/2016/01/06/cve-20153865
https://source.android.com/security/overview/acknowledgements
https://www.youtube.com/user/mediacccde/playlists
https://defuse.ca/

Makefile
https://news.ycombinator.com/item?id=15041986
https://gist.github.com/isaacs/62a2d1825d04437c6f08

Bash shell
https://google.github.io/styleguide/shell.xml

Cmake
https://github.com/onqtam/awesome-cmake

Finding size of cache
https://stackoverflow.com/questions/794632/programmatically-get-the-cache-line-size
https://community.arm.com/processors/f/discussions/5807/how-get-armv7-cache-size

Android vulnerability
https://github.com/vusec/drammer
Searching in android vulnerability list, they give full twitter info of hacker then find them find their website find blogs etc.
https://www.slideshare.net/jiahongfang5/qualcomm2015-jfang-nforest
https://www.blackhat.com/docs/us-15/materials/us-15-Xu-Ah-Universal-Android-Rooting-Is-Back-wp.pdf
https://www.google.com/search?client=firefox-b-ab&ei=lc0PW4TXH4i4swG1zYZA&q=Find+your+own+Androidkernel+bug+pdf&oq=Find+your+own+Androidkernel+bug+pdf&gs_l=psy-ab.3...9041.12780.0.13195.8.7.1.0.0.0.358.1444.2-4j1.5.0....0...1c.1.64.psy-ab..3.1.264...33i160k1.0.sjMy_Nr7Qcw
https://www.blackhat.com/docs/eu-17/materials/eu-17-Corina-Difuzzing-Android-Kernel-Drivers.pdf
Mobile Application Penetration Testing
http://cloak-and-dagger.org/
http://events17.linuxfoundation.org/sites/events/files/slides/LSS%20-%20Treble%20%27n%27%20SELinux_0.pdf
https://alephsecurity.com/
https://github.com/dweinstein/android_notes/wiki/AndroidApplicationStartup
https://census-labs.com/media/shadow-infiltrate-2017.pdf
https://www.blackhat.com/docs/eu-16/materials/eu-16-Shen-Rooting-Every-Android-From-Extension-To-Exploitation.pdf
(Awesome)https://github.com/jacobsoo/AndroidSlides, http://www.droidsec.org/wiki/#miscellaneous, https://github.com/SecWiki/android-kernel-exploits
(Very Very awesome)https://www.sudo.ws/
(Awesome) https://reverseengineering.stackexchange.com/questions/206/where-can-i-as-an-individual-get-malware-samples-to-analyze
https://mobilesecuritywiki.com/
https://github.com/xtiankisutsa/awesome-mobile-CTF
https://github.com/ashishb/android-security-awesome
https://abuse.ch/
https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Exploit%20Development.md#expapers
https://github.com/ele7enxxh/android_vuln_poc-exp
https://ruxcon.org.au/
https://ruxcon.org.au/assets/2017/slides/A_Whole_New_Efficient_Fuzzing_Strategy_for_Stagefright_Porting_and_Optimisations.pptx
https://github.com/jiayy/android_vuln_poc-exp/
https://www.youtube.com/watch?v=q_HibdrbIxo&index=8&list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD
https://github.com/Screetsec/TheFatRat
https://gist.github.com/MattKetmo/96d703bc23ce432d4591
https://joshuawise.com/projects
https://github.com/linkedin/qark
https://blog.zimperium.com/the-latest-on-stagefright-cve-2015-1538-exploit-is-now-available-for-testing-purposes/
https://security.stackexchange.com/questions/40012/writing-android-exploits
http://www.xipiter.com/practical-android-exploitation.html
https://github.com/xairy/linux-kernel-exploitation
http://bits-please.blogspot.co.uk/2015/08/android-linux-kernel-privilege.html
https://www.securityfocus.com/news/11189
http://analysis.seclab.tuwien.ac.at/projects/vifuzz/docs/exploit.pdf
(Awesome Step by step) https://ionize.com.au/android-exploit-development-android-open-source-project-toolchain/
https://www.exploit-db.com/platform/?p=Android
https://github.com/SecWiki/android-kernel-exploits
http://analysis.seclab.tuwien.ac.at/projects/vifuzz/docs/exploit.pdf
key Search term = Writing exploits for device drivers
Key Search term = how to write exploit for android , Fuzzing drivers
https://www.vulnhub.com/
https://github.com/smeso/MTPwn
https://mobile-security.zeef.com/oguzhan.topgul
https://www.hackers-arise.com/single-post/2017/09/20/Exploiting-Nearly-Any-Windows-System-Using-CVE-2017-8759
https://github.com/FabioBaroni/awesome-exploit-development
writing security tools and exploits
https://conference.hitb.org/hitbsecconf2018ams/materials/D1T2%20-%20Yong%20Wang%20&%20Yang%20Song%20-%20Rooting%20Android%208%20with%20a%20Kernel%20Space%20Mirroring%20Attack.pdf
Android hacker's handbook 
learn pentesting on android
Android internals jonathan Levin
http://conference.hitb.org/hitbsecconf2017ams/materials/
https://www.blackhat.com/docs/us-16/materials/us-16-Zhang-Dangerous-Hare-Hanging-Attribute-References-Hazards-Due-To-Vendor-Customization.pdf
https://www.blackhat.com/us-17/briefings.html#avpass-leaking-and-bypassing-antivirus-detection-model-automatically
https://www.blackhat.com/us-17/briefings.html#broadpwn-remotely-compromising-android-and-ios-via-a-bug-in-broadcoms-wi-fi-chipsets
https://www.blackhat.com/us-17/briefings.html#cloak-and-dagger-from-two-permissions-to-complete-control-of-the-ui-feedback-loop
https://www.blackhat.com/us-17/briefings.html#defeating-samsung-knox-with-zero-privilege
https://www.blackhat.com/us-17/briefings.html#many-birds-one-stone-exploiting-a-single-sqlite-vulnerability-across-multiple-software
https://www.blackhat.com/docs/us-17/thursday/us-17-Jung-AVPASS-Leaking-And-Bypassing-Anitvirus-Detection-Model-Automatically.pdf
https://www.blackhat.com/docs/us-16/materials/us-16-Zhang-Dangerous-Hare-Hanging-Attribute-References-Hazards-Due-To-Vendor-Customization.pdf
https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/liu
https://www.rsaconference.com/writable/presentations/file_upload/mbs-f03-android-serialization-vulnerabilities-revisited.pdf
https://www.rsaconference.com/writable/presentations/file_upload/hta-r10-hey-android-where-is-my-car.pdf
https://www.rsaconference.com/writable/presentations/file_upload/mbs-r14-how-automated-vulnerability-analysis-discovered-hundreds-of-android-0-days.pdf
https://www.rsaconference.com/writable/presentations/file_upload/mbs-r14-how-automated-vulnerability-analysis-discovered-hundreds-of-android-0-days.pdf
https://www.ruhrsec.de/2018/#talks
https://www.slideshare.net/CanSecWest/csw2017-geshevmiller-logic-bug-hunting-in-chrome-on-android
(Awesome Might be on android as well) https://labs.mwrinfosecurity.com/assets/BlogFiles/apple-safari-wasm-section-vuln-write-up-2018-04-16.pdf
(It might help awesome)https://www.blackhat.com/us-17/training/schedule/index.html#android-application-hacking----penetration-and-reversing-mobile-apps-5628
https://github.com/hackedteam?tab=repositories

Deepfakes
https://github.com/goberoi/faceit
https://github.com/alew3/faceit_live
https://github.com/deepfakes/faceswap
https://medium.com/huia/live-deep-fakes-you-can-now-change-your-face-to-someone-elses-in-real-time-video-applications-a4727e06612f

Writing Cache friendly code
(Awesome search term)Writing cache friendly code

Linux MMu
https://events.static.linuxfound.org/sites/events/files/slides/elc_2016_mem.pdf

Chip
https://en.wikichip.org/wiki/mediatek/helio/mt6755
https://www.mediatek.com/products/smartphones/mt6755-helio-p10#

Virtual memory
https://blog.jeffli.me/blog/2014/11/08/pagemap-interface-of-linux-explained/
https://www.kernel.org/doc/Documentation/vm/pagemap.txt
https://www.youtube.com/watch?v=qcBIvnQt0Bw&list=PLiwt1iVUib9s2Uo5BeYmwkDFUh70fJPxX
https://events.static.linuxfound.org/sites/events/files/slides/elc_2016_mem.pdf
https://www.bottomupcs.com/virtual_addresses.xhtml
https://stackoverflow.com/questions/44520047/what-is-the-page-size-for-32-and-64-bit-versions-of-windows-os
https://stackoverflow.com/questions/33722205/how-many-page-tables-do-intel-x86-64-cpus-access-to-translate-virtual-memory
(Awesome)http://www.cirosantilli.com/x86-paging/
http://www.ic.unicamp.br/~celio/mc404-2013/arm-manuals/Paging%20Systems.pdf
http://lackingrhoticity.blogspot.co.uk/2015/05/how-physical-addresses-map-to-rows-and-banks.html

Awesome kali and exploit
https://github.com/secfigo/Awesome-Fuzzing
https://gist.github.com/natesubra/5117959c660296e12d3ac5df491da395
http://www.fuzzysecurity.com/links.html
https://github.com/FabioBaroni/awesome-exploit-development
https://www.corelan.be/
https://null-byte.wonderhowto.com/how-to/exploit-development-everything-you-need-know-0167801/
https://www.hackers-arise.com/single-post/2017/06/21/Exploit-Development-Part-3-Finding-Vulnerabilities-by-Fuzzing-with-Spike
https://uk.sans.org/course/advanced-exploit-development-penetration-testers
https://en.wikipedia.org/wiki/Fravia
http://www.ctyme.com/rbrown.htm
https://news.ycombinator.com/item?id=4121062
https://github.com/Hack-with-Github
https://github.com/yeyintminthuhtut/Awesome-Study-Resources-for-Kernel-Hacking
awesome exploit development
https://github.com/apsdehal/awesome-ctf
(Awesome)https://github.com/gregkh/kernel-development
(Awesome)https://github.com/fffaraz/kernel
https://github.com/aleksandar-todorovic/awesome-linux#learning-resources
https://github.com/aleksandar-todorovic/awesome-linux#useful-websites
A guide to kernel exploitation
https://securityonline.info/awesome-hacking-collection-awesome-lists-hackers-pentesters-security-researchers/
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0ahUKEwi5qNeKqpbbAhVPC-wKHQz9APQQFggnMAA&url=http%3A%2F%2Fwww.piotrbania.com%2Fall%2Farticles%2Fewdd.pdf&usg=AOvVaw3g5NjK-ghejApSApADwa65
https://www.blackhat.com/presentations/bh-usa-07/Bulygin/Presentation/bh-usa-07-bulygin.pdf

Awesome hardware
https://github.com/openmotics/hardware
Search high speed circuit design
vhdl
https://blog.hackster.io/student-creates-first-homebrew-dual-differential-amplifier-ic-8535af115d7e?gi=4334ecb2fcdd
https://blog.hackster.io/how-to-embed-nfc-chips-into-your-acrylic-fingernails-dor-unlocking-your-phone-and-much-more-51ea87d6a169
https://en.wikipedia.org/wiki/List_of_open-source_hardware_projects
https://en.wikipedia.org/wiki/Open-source_hardware
https://en.wikipedia.org/wiki/Open-Source_Lab_(book)
http://apt.cs.manchester.ac.uk/ftp/pub/apt/papers/LEMB_ToE09_O.pdf
Search term : Design system on chip
https://en.wikibooks.org/wiki/Chip_Design_Made_Easy
http://users.ece.utexas.edu/~gerstl/publications/TR-02-28.tutorial.pdf
http://www.cl.cam.ac.uk/teaching/1011/SysOnChip/socdam-notes1011.pdf
https://www.quora.com/Which-is-the-best-online-ARM-processor-course
https://github.com/monostable/awesome-electronics

Android terminal
ftp://ftp.wayne.edu/ldp/en/Linux-Android-HOWTO/Linux-Android-HOWTO-6.html

Processor know how
https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-823-computer-system-architecture-fall-2005/lecture-notes/

Iot sec
(Awesome)http://jcjc-dev.com/2016/06/08/reversing-huawei-4-dumping-flash/
https://security.electronicsforu.com/wp-content/uploads/2017/06/RISC_IoT_101.pdf
https://www.owasp.org/images/2/29/AppSecIL2016_HackingTheIoT-PenTestingRFDevices_ErezMetula.pdf
https://s3.us-east-2.amazonaws.com/attify-iot-hosting/Hacking+IoT+for+Bug+Bounties.pdf
https://sector.ca/wp-content/uploads/presentations17/Aditya-Gupta-Pwning-Smart-Homes-SecTor.pdf
http://www.cs.bham.ac.uk/~tpc/Edu/Pentesting/files/penEdu.pdf

Makefile
https://eigenstate.org/notes/makefiles
http://docs.yottabuild.org/tutorial/tutorial.html
https://www3.ntu.edu.sg/home/ehchua/programming/cpp/gcc_make.html
Managing large projects with make
http://doc.cat-v.org/bell_labs/mk/
https://github.com/oridb/mk
https://eli.thegreenplace.net/2013/07/09/library-order-in-static-linking

Good android books
Embedded Android: Porting, Extending
Android internals Jonathan Levin
Learning pentesting for android
http://www.opersys.com/training/embedded-android
https://stackoverflow.com/questions/11262817/learn-about-android-internalsdive-deep-into-the-system
Xda developers android hacker's toolkit

Embedded Linux
https://github.com/embedded-boston/awesome-embedded-systems
https://github.com/ysh329/awesome-embedded-ai
https://www.quora.com/What-are-the-best-lectures-for-learning-Embeded-systems-in-YouTube
https://hackr.io/tutorials/learn-android-development
https://github.com/JStumpp/awesome-android#resources

Compilers
https://insights.dice.com/2015/12/04/developing-in-cc-consider-clang/
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=15&ved=0ahUKEwjZvOfP7ZjbAhXC2aQKHSjcCxoQFgiaATAO&url=https%3A%2F%2Fraw.githubusercontent.com%2Fnamin%2Finc%2Fmaster%2Fdocs%2Ftutorial.pdf&usg=AOvVaw05R_CrVMx8P0t7nmVmnLwa
https://steveire.wordpress.com/
http://webpages.charter.net/ppluzhnikov/linker.html

Awesome Slam
https://github.com/kanster/awesome-slam#courses-lectures-and-workshops
https://github.com/liulinbo/slam
https://blog.csdn.net/renye_lpl/article/details/79225423

Gcc cross
http://preshing.com/20141119/how-to-build-a-gcc-cross-compiler/
https://github.com/landley/toybox
http://web.guohuiwang.com/technical-notes/androidndk2
http://www.linfo.org/main_index.html

Linux kernel
http://fxr.watson.org/

Write  an mp3 filter
http://book.realworldhaskell.org/read/
http://blog.bjrn.se/2008/10/lets-build-mp3-decoder.html
https://multimedia.cx/eggs/learn-multimedia-with-jpeg/
http://www.opennet.ru/docs/formats/jpeg.txt
http://parsingintro.sourceforge.net/
http://wiki.c2.com/?TipsForReadingCode

Programme and their memory
https://www.usna.edu/Users/cs/aviv/classes/ic221/s16/lec/11/lec.html
https://stackoverflow.com/questions/15638105/accessing-specific-memory-locations-in-c
https://www.kernel.org/doc/gorman/html/understand/understand007.html
https://www.google.com/search?q=how+memory+address+is+assigned+to+process&ie=utf-8&oe=utf-8&client=firefox-b-ab
http://www.informit.com/articles/article.aspx?p=29961&seqNum=2
https://www.google.com/search?q=how+os+gives+address+to+user+spce+prograzmme&ie=utf-8&oe=utf-8&client=firefox-b-ab
https://security.stackexchange.com/questions/18556/how-do-aslr-and-dep-work
https://www.blackhat.com/docs/eu-16/materials/eu-16-Schwarz-How-Your-DRAM-Becomes-A-Security-Problem-wp.pdf

dope links
https://fail0verflow.com/blog/
https://www.w3.org/TR/workers/
http://www.hotchips.org/archives/2010s/hc29/
http://linux-test-project.github.io/
https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Embedded%20Device%20%26%20Hardware%20Hacking%20-.md
https://www.google.com/search?client=firefox-b-ab&ei=1a4PW4z9FcaB6ATgy57oBw&q=awesome+hardware+hacking&oq=awesome+hardware+hacking&gs_l=psy-ab.3..33i160k1.5710.6089.0.6337.3.3.0.0.0.0.245.245.2-1.1.0....0...1c.1.64.psy-ab..2.1.244....0.OcRoyVos8Z0
Black Hat: Top 20 hack-attack tools
https://www.blackhat.com/us-17/training/applied-hardware-attacks-embedded-systems.html
https://www.google.com/search?client=firefox-b&ei=HLcPW6wnyImbBd6ekoAF&q=Dumping+Firmware+from+Software+pdf&oq=Dumping+Firmware+from+Software+pdf&gs_l=psy-ab.3...1367.2806.0.2965.4.4.0.0.0.0.265.265.2-1.1.0....0...1c.1.64.psy-ab..3.1.264...33i160k1.0.WHT9xo50-gU
https://www.google.com/search?client=firefox-b&ei=LrcPW6-GC8rN6QSAkpawBg&q=Manipulating+firmware+images+pdf&oq=Manipulating+firmware+images+pdf&gs_l=psy-ab.3..33i21k1.3130.4518.0.4688.4.4.0.0.0.0.262.508.2-2.2.0....0...1c.1.64.psy-ab..2.2.507...33i160k1.0.ZNykmY9pJT8
https://www.google.com/search?client=firefox-b&ei=Q7cPW-rRBsOF6ASL0Z_wDQ&q=Finding+software+bugs+in+firmware+pdf&oq=Finding+software+bugs+in+firmware+pdf&gs_l=psy-ab.3...6317.8320.0.8453.6.6.0.0.0.0.279.765.2-3.3.0....0...1c.1.64.psy-ab..3.3.764...33i160k1j33i21k1.0.H5R8teKf0as
http://hexblog.com/files/recon%202010%20Skochinsky.pdf
https://reverseengineering.stackexchange.com/questions/3526/how-do-i-extract-a-copy-of-an-unknown-firmware-from-a-hardware-device
https://reverseengineering.stackexchange.com/questions/2337/how-to-dump-flash-memory-with-spi
http://chdk.wikia.com/wiki/Obtaining_a_firmware_dump
https://www.blackhat.com/docs/us-16/materials/us-16-FitzPatrick-The-Tao-Of-Hardware-The-Te-Of-Implants.pdf
https://www.blackhat.com/us-16/training/applied-physical-attacks-on-x86-systems.html
http://www.nsaplayset.org/
https://en.wikipedia.org/wiki/NSA_ANT_catalog
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=4&ved=0ahUKEwjO2Jrl0K_bAhWjQJoKHV9kBWkQFghDMAM&url=http%3A%2F%2Fwww.jsums.edu%2Fnmeghanathan%2Ffiles%2F2015%2F05%2FCSC437-Fall2013-Module-5-Buffer-Overflow-Attacks.pdf%3Fx61976&usg=AOvVaw2lP003SqchXxcuGyhb4vFZ
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=3&ved=0ahUKEwjO2Jrl0K_bAhWjQJoKHV9kBWkQFgg2MAI&url=http%3A%2F%2Fforristal.com%2Fmaterial%2FForristal_Hardware_Involved_Software_Attacks.pdf&usg=AOvVaw3fiH_8AIm8RnTgqhBcfnlm
https://www.blackhat.com/presentations/bh-usa-04/bh-us-04-tsyrklevich.pdf
https://www.blackhat.com/docs/asia-18/asia-18-Ding-New-Compat-Vulnerabilities-In-Linux-Device-Drivers.pdf
https://security.stackexchange.com/questions/119712/methods-root-can-use-to-elevate-itself-to-kernel-mode
https://www.giac.org/paper/gsec/2235/quest-root-hacker-techniques-unix-security/103808
https://thehackernews.com/2017/05/linux-sudo-root-hack.html
https://hackmag.com/security/reach-the-root/
https://payatu.com/guide-linux-privilege-escalation/
https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Privilege%20Escalation%20%26%20Post-Exploitation.md
http://0x00sec.org/t/enumeration-for-linux-privilege-escalation/1959
https://thehackernews.com/2017/06/linux-root-privilege-escalation.html
https://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
https://uwnthesis.wordpress.com/2016/12/26/basics-of-making-a-rootkit-from-syscall-to-hook/
http://se7so.blogspot.com/2012/07/hijacking-linux-system-calls-rootkit.html
http://timetobleed.com/detailed-explanation-of-a-recent-privilege-escalation-bug-in-linux-cve-2010-3301/
https://www.google.com/search?client=firefox-b-ab&biw=1468&bih=937&ei=BMYPW8iaM8yusAGcvYm4CQ&q=privelege+escalation+using+syscalls&oq=privelege+escalation+using+syscalls&gs_l=psy-ab.3..33i21k1.252575.260038.0.260160.36.26.0.0.0.0.466.3636.2-3j4j3.11.0....0...1c.1.64.psy-ab..25.11.3924.6..0j35i39k1j0i131k1j0i10k1j0i13k1j0i22i30k1.296.3ay4O3XzcSI
http://bits-please.blogspot.com/2016/06/trustzone-kernel-privilege-escalation.html
https://www.exploit-db.com/exploits/44205/
https://perso.univ-st-etienne.fr/maf13892/Docs/Publications/JTAG.FIA.pdf
https://perso.univ-st-etienne.fr/maf13892/Docs/Presentations/TRUDEVICE2015_JTAGCombinedAttacks.pdf
https://hakin9.org/download/hacking-android-80-pages-of-experts-tutorials/
(Awesome hardware concise)https://media.blackhat.com/us-13/US-13-Zaddach-Workshop-on-Embedded-Devices-Security-and-Firmware-Reverse-Engineering-WP.pdf
https://www.google.com/search?client=firefox-b-ab&ei=O-YQW6OHJqKHmwXht5y4Bg&q=awesome+embeded+hacking+&oq=awesome+embeded+hacking+&gs_l=psy-ab.3...7740132.7748464.0.7748615.25.21.0.0.0.0.532.2820.3-4j2j1.8.0....0...1c.1.64.psy-ab..20.2.875.0..0j0i67k1.298.3F7kxDoweak
(Awesome)https://www.kb.cert.org/vuls/id/649219
https://en.wikipedia.org/wiki/DMA_attack
https://github.com/ufrisk/pcileech
https://www.blackhat.com/docs/us-17/wednesday/us-17-Trikalinou-Taking-DMA-Attacks-To-The-Next-Level-How-To-Do-Arbitrary-Memory-Reads-Writes-In-A-Live-And-Unmodified-System-Using-A-Rogue-Memory-Controller.pdf
https://github.com/torvalds/linux/blob/master/Documentation/DMA-API-HOWTO.txt
(Awesome resource hidden)https://cturt.github.io/ps4.html
https://fail0verflow.com/blog/2017/ps4-crashdump-dump/
https://www.psxhax.com/threads/dualshock-4-ds4-ps4-firmware-dump-reversing-tools-by-ds4user.1159/?utm_source=dlvr.it&utm_medium=facebook
https://www.reddit.com/r/ps4homebrew/comments/8amgmz/the_nor_chip/
https://www.3dbrew.org/wiki/Homebrew_Exploits
https://github.com/Cryptogenic/Exploit-Writeups/blob/master/FreeBSD/PS4%204.55%20BPF%20Race%20Condition%20Kernel%20Exploit%20Writeup.md
https://github.com/whnunlife/ps3publictools
http://www2.lauterbach.com/pdf/debugger_arm.pdf
https://news.ycombinator.com/item?id=7015082
https://comma.ai/
https://github.com/geohot/qira
https://pure.tue.nl/ws/files/46956556/770549-1.pdf
https://sharedmemorydump.net/building-a-mining-stack-of-raspberry-pis




Awesome kernel
https://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
http://www.vantagepoint.sg/blog/82-hooking-android-system-calls-for-pleasure-and-benefit
https://jvns.ca/blog/2014/09/18/you-can-be-a-kernel-hacker/
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0ahUKEwjz2tf216_bAhVDkywKHVwHCvsQFggsMAA&url=http%3A%2F%2Fevents17.linuxfoundation.org%2Fsites%2Fevents%2Ffiles%2Fslides%2Fnakamura_20170831_1.pdf&usg=AOvVaw1_1D1ZF-BJIF89_233pECT
Hacker playbook
http://delta-course.org/docs/delta4/day2/D4T2L5.pdf
http://www.cs.swan.ac.uk/~csmarkus/15_project/15_10_sample1_InitialDocument.pdf
http://wpage.unina.it/roberto.natella/papers/natella_androidfuzzing_issre2017.pdf
http://aitel.hist.no/fag/lan/lek02/dln02-en.pdf
https://www.usenix.org/legacy/events/hotsec11/tech/final_files/Cai.pdf
http://www.makelinux.net/kernel_map/#sd
http://chdk.wikia.com/wiki/Obtaining_a_firmware_dump
A guide to kernel exploitation
https://raw.githubusercontent.com/liulinbo/slam/master/Linux%E5%B0%B1%E8%AF%A5%E8%BF%99%E4%B9%88%E5%AD%A6.pdf
https://raw.githubusercontent.com/jacobsoo/AndroidSlides/master/%E5%8C%97%E4%BA%AC-GDG-Android-root-%E6%8A%80%E6%9C%AF%E6%B2%99%E9%BE%99-2014/Find%20your%20own%20Android%20kernel%20bug.pdf
http://www.xml.com/ldd/chapter/book/ch13.html
https://github.com/torvalds/linux/blob/master/Documentation/DMA-API-HOWTO.txt
https://www.linuxjournal.com/article/4378

Search for debug mode in processor
http://www.msn.com/en-gb/money/companies/google-used-to-ask-these-interview-questions-but-theyre-so-tricky-they-were-banned/ss-AAy3kE0?ocid=ientp#image=6

Fpga based security
https://github.com/ufrisk/pcileech
https://mirror.netcologne.de/CCC/congress/2017/slides-pdf/34c3-9111-public_fpga_based_dma_attacking.pdf
https://github.com/matthiasbock/JTAG-Sniffer
https://recon.cx/2013/trainingsynple.html
https://www.eetimes.com/document.asp?doc_id=1274593

PS#
https://www2.cs.arizona.edu/~collberg/Teaching/466-566/2012/Resources/presentations/2012/topic1-final/report.pdf
https://www2.cs.arizona.edu/~collberg/Teaching/466-566/2012/Resources/presentations/2012/topic1-final/slides.pdf
https://www.riscure.com/uploads/2017/09/Controlling-PC-on-ARM-using-Fault-Injection.pdf
https://events.ccc.de/congress/2010/Fahrplan/attachments/1780_27c3_console_hacking_2010.pdf
https://rdist.root.org/2010/01/27/how-the-ps3-hypervisor-was-hacked/
http://www.blackhat.com/docs/eu-15/materials/eu-15-Giller-Implementing-Electrical-Glitching-Attacks.pdf
http://mastersicurezza.di.uniroma1.it/mastersicurezza/images/materiali/Convegni/cbepas2012.pdf
http://ids.cs.columbia.edu/sites/default/files/ndss-2013.pdf
https://web.archive.org/web/20100409023327/http://geohotps3.blogspot.com/
https://web.archive.org/web/20100410060251/http://pastie.org:80/795944
https://web.archive.org/web/20100704075741/http://hackmii.com:80/2009/01/25c3-presentation/
https://web.archive.org/web/20100723083756/http://www.ibm.com:80/developerworks/power/library/pa-cellsecurity/
https://news.ycombinator.com/item?id=1079251
https://web.archive.org/web/20100404062009/http://rdist.root.org:80/2007/05/07/glitch-attacks-revealed/
https://web.archive.org/web/20100412055807/http://xorloser.com:80/?p=162#more-162
https://web.archive.org/web/20100220214115/http://ps3hvdoc.wikispaces.com:80/Hypervisor+RE
https://web.archive.org/web/20100410060005/http://pastie.org:80/795371
http://www.edepot.com/playstation3.html#PS3_Security
https://web.archive.org/web/20110110121139/http://wiki.ps2dev.org/

Ram dump
https://resources.infosecinstitute.com/obtaining-information-dumping-memory/#gref
https://rc2014.co.uk/modules/sd-memory-dump/
http://jcjc-dev.com/2016/12/14/reversing-huawei-5-reversing-firmware/
https://madiba.encs.concordia.ca/~x_decarn/papers/verifiable-build-acsac2014.pdf
Methods of capturing a memory dump
Mobile forensics
Capturing a live ram
https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=5&ved=0ahUKEwibyLjXrLLbAhXID8AKHbqCBjYQFghKMAQ&url=http%3A%2F%2Fwww.indjst.org%2Findex.php%2Findjst%2Farticle%2Fdownload%2F105851%2F77226&usg=AOvVaw1xksKEcSYyOXuHFbx_qeuw
https://www.sans.org/reading-room/whitepapers/forensics/techniques-tools-recovering-analyzing-data-volatile-memory-33049
Kernel panic
https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Burdach.pdf
https://www.forensicswiki.org/wiki/Memory_Imaging
(aWESOME)http://eh2008.koeln.ccc.de/fahrplan/attachments/1067_SEAT1394-svn-r432-paper.pdf
https://eprint.iacr.org/2011/221.pdf
http://www.stoned-vienna.com
https://privatecore.com/resources-overview/physical-memory-attacks/index.html
Attacks on physical memory
https://www.defcon.org/html/links/dc-archives/dc-20-archive.html
DIY electric car
File dump attack
Access ramd irectly
https://www.youtube.com/watch?v=Zp8dVq5ZvKY
https://cturt.github.io/ps4.html
https://opensourceforu.com/2011/02/debug-kernel-panics-with-crash/
https://cryptome.org/0003/RAMisKey.pdf



Security Awesome
https://www.sec.in.tum.de/i20/teaching
