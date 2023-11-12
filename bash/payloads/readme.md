## Bourne-Again SHell and Linux CLI

##
#
https://gist.github.com/connorjan/ec8e077775939b572172802caee74142
#
##

© 2013 [Martin Bruchanov](http://bruxy.regnet.cz/), bruxy@regnet.cz

Set interpreter: <tt>#!/bin/bash</tt>    Remarks: <tt># this is comment</tt>

### Interactive control

| Action | <tt>set -o vi</tt> | <tt>set -o emacs</tt> |
| --- | --- | --- |
| vi-command mode ( <span class="ss">C</span>) |  <span class="C"><span class="key">Esc</span></span> | — |
| Previous/next command in history |  <span class="CC">j<sub class="low">C</sub></span> / <span class="CC">k<sub class="low">C</sub></span> |  <span class="C"><span class="key">Ctrl</span>+p</span> / <span class="C"><span class="key">Ctrl</span>+n</span>
<span class="C"><span class="key">PageUp</span></span> / <span class="C"><span class="key">PageDown</span></span> |
| Automatic fill of file name |  <span class="C"><span class="key">Esc</span></span><span class="CC"><span class="key">Esc</span><sub class="low">C</sub></span> |  <span class="C"><span class="key">Tab</span></span> |
| List of all matches |  <span class="C"><span class="key">Esc</span></span><span class="C">=</span> |  <span class="C">Tab</span><span class="C">Tab</span> |
| Horizontal move in command line |  <span class="CC">h<sub class="low">C</sub></span> / <span class="CC">l<sub class="low">C</sub></span> |  <span class="C"><span class="key">Ctrl</span>+b</span> / <span class="C"><span class="key">Ctrl</span>+f</span>, <span class="C">_←_</span> / <span class="C">_→_</span> |
| Jump to line begin/end |  <span class="CC"><tt>^</tt><sub class="low">C</sub></span> / <span class="CC">$<sub class="low">C</sub></span> |  <span class="C"><span class="key">Ctrl</span>+a</span> / <span class="C"><span class="key">Ctrl</span>+e</span> |
| Backward/forward search in history |  <span class="CC">/<sub class="low">C</sub></span> / <span class="CC">?<sub class="low">C</sub></span> |  <span class="C"><span class="key">Ctrl</span>+r</span> / <span class="C"><span class="key">Ctrl</span>+s</span> |
| Delete word to the end/begin |  <span class="CC">dw<sub class="low">C</sub></span> / <span class="CC">db<sub class="low">C</sub></span> |  <span class="C"><span class="key">Esc</span> d</span> / <span class="C"><span class="key">Esc</span> h</span> |
| Delete text from cursor to the line end/begin |  <span class="CC">d<tt>$</tt><sub class="low">C</sub></span> / <span class="CC">d<tt>^</tt><sub class="low">C</sub></span> |  <span class="C"><span class="key">Ctrl</span>+k</span> / <span class="C"><span class="key">Ctrl</span>+u</span> |

#### Command line history

*   <tt>history</tt>, <tt>fc -l</tt> – display numbered history of commands
*   <tt>!<tt>_n_</tt></tt> – run command number <tt>_n_</tt>
*   <tt>!<tt>_p_</tt></tt> – run last command beginning by <tt>_p_</tt>
*   <tt>!!</tt> – repeat last entered command
*   <tt>!!:<tt>_n_</tt></tt> – expand <tt>_n_</tt>-th parameter of last command
*   <tt>!$</tt> – expand the last parameter of last command
*   <tt>fc</tt> – run defined <tt>$EDITOR</tt> wit last command
*   <tt>fc -e vim <tt>_z k_</tt></tt> – open <tt>vim</tt> editor with commands from _z_ to _k_
*   <tt>^old^new</tt> – substitute <tt>_old_</tt> with <tt>_new_</tt> in last command
*   <tt>_program_</tt> <tt>`!!`</tt> – use output of last command as input

#### Help and manuals

*   <tt>type -a <tt>_command_</tt></tt> – information about command
*   <tt>help <tt>_command_</tt></tt> – brief help on bash command
*   <tt>man <tt>_command_</tt></tt>, <tt>info <tt>_command_</tt></tt> – detailed help
*   <tt>man -k <tt>_key_</tt></tt>, <tt>apropos <tt>_key_</tt></tt>, <tt>whatis <tt>_key_</tt></tt> – find command

### Debugging

Run a script as: <tt>bash <tt>_option script and its parameters_</tt></tt>

*   <tt>bash -x</tt> – print commands before execution
*   <tt>bash -u</tt> – stop with error if undefined variable is used
*   <tt>bash -v</tt> – print script lines before execution
*   <tt>bash -n</tt> – do not execute commands

### Variables, arrays and hashes

*   <tt><tt>_NAME_</tt>=10</tt> – set value to variable <tt>$NAME</tt>, <tt>${NAME}</tt>
*   <tt>export NAME=10, typedef -x NAME</tt> – set as environment variable
*   <tt>D=$(date); D=<tt>`</tt>date<tt>`</tt></tt> – variable contains output of command <tt>date</tt>
*   <tt>env, printenv</tt> – list all environment variables
*   <tt>set</tt> – list env. variables, can set bash options and flags <tt>shopt</tt>
*   <tt>unset <tt>_name_</tt></tt> – destroy variable of function
*   <tt>typeset, declare</tt> – set type of variable
*   <tt>readonly <tt>_variable_</tt></tt> – set as read only
*   <tt>local <tt>_variable_</tt></tt> – set local variable inside function
*   <tt>${ !var}</tt>, <tt>eval \$var</tt> – indirect reference
*   <tt>${<tt>_parameter-word_</tt>}</tt> – if <tt>_parameter_</tt> has value, then it is used, else <tt>_word_</tt> is used
*   <tt>${<tt>_parameter=word_</tt>}</tt> – if <tt>_parameter_</tt> has no value assing <tt>_word_</tt>. Doesn't work with <tt>$1</tt>, <tt>$2</tt>, ets.
*   <tt>${<tt>_parameter:-word_</tt>}</tt> – works with <tt>$1</tt>, <tt>$2</tt>, etc.
*   <tt>${<tt>_parameter?word_</tt>}</tt> – if <tt>_parameter_</tt> has value, use it; if no display <tt>_word_</tt> and exit script.
*   <tt>${<tt>_parameter+word_</tt>}</tt> – if <tt>_parameter_</tt> has value, use <tt>_word_</tt>, else use empty string
*   <tt>array=(a b c); echo ${array[1]}</tt> – print „b“
*   <tt>array+=(d e f)</tt> – append new item/array at the end
*   <tt>${<tt>array[*]</tt>}</tt>, <tt>${<tt>array[@]</tt>}</tt> – all items of array
*   <tt>${<tt>#array[*]</tt>}</tt>, <tt>${<tt>#array[@]</tt>}</tt> – number of array items
*   <tt>declare -A hash</tt> – create associative array (from version)
*   <tt>hash=([key1]=value ["other key2"]="other value")</tt> – store items
*   <tt>${<tt>hash["other key2"]</tt>}</tt>, <tt>${<tt>hash[other key2]</tt>}</tt> – access
*   <tt>${<tt>hash[@]</tt>}</tt>, <tt>${<tt>hash[*]</tt>}</tt> – all items
*   <tt>${<tt>!hash[@]</tt>}</tt>, <tt>${<tt>!hash[*]</tt>}</tt> – all keys

#### Strings

*   <tt>STRING="Hello"</tt> – indexing: H<sub>0</sub> e<sub>1</sub> l<sub>2</sub> l<sub>3</sub> o<sub>4</sub>
*   <tt>STRING+=" world!"</tt> – concatenate strings
*   <tt>${<tt>#string</tt>}</tt>, <tt>expr length $string</tt> – string length
*   <tt>${<tt>string:position</tt>}</tt> – extract substring from position
*   <tt>${<tt>string:position:length</tt>}</tt> – extract substr. of length from position
*   <tt>${<tt>string/substring/substitution</tt>}</tt> – substitute first occurrence
*   <tt>${<tt>string//substring/substitution</tt>}</tt> – substitute all
*   <tt>${<tt>string/%substring/substitution</tt>}</tt> – substitute last occurrence
*   <tt>${<tt>string#substring</tt>}</tt> – erase shortest substring
*   <tt>${<tt>string##substring</tt>}</tt> – erase longest substring

#### Embedded variables

*   <tt>~</tt>, <tt>$HOME</tt> – home directory of current user
*   <tt>$PS1</tt>, <tt>$PS2</tt> – primary, secundary user prompt
*   <tt>$PWD</tt>, <tt>~+</tt> / <tt>$OLDPWD</tt>, <tt>~-</tt> – actual/previous directory
*   <tt>$RANDOM</tt> – random number generator, 0 – 32,767
*   <tt>$?</tt> – return value of last command
*   <tt>$</tt> – process id. of current process
*   <tt>$!</tt> – process id. of last background command
*   <tt>$PPID</tt> – process id. of parent process
*   <tt>$-</tt> – display of bash flags
*   <tt>$LINENO</tt> – current line number in executed script
*   <tt>$PATH</tt> – list of paths to executable commands
*   <tt>$IFS</tt> – Internal field separator. List of chars, that delimiter words from input, usually space, tabulator <tt>/tt>\t'</tt> and new line <tt>/tt>\n'</tt>.

### Script command line parameters

*   <tt>$0</tt>, <tt>${0}</tt> – name of script
*   <tt>$1</tt> to <tt>$</tt>9, <tt>${1}</tt> to <tt>${255}</tt> – positional command line parameters
*   <tt>$</tt><tt>#</tt> – number of command line parameters (argc)
*   <tt>$*</tt> – expand all parameters, <tt>"$*"</tt> = <tt>"$1 $2 $3…"</tt>
*   <tt>$</tt><tt>@</tt> – expand all parameters, <tt>"$</tt><tt>@"</tt> = <tt>"$1" "$2" "$3"…</tt>
*   <tt>$_</tt> – last parameter of previous command
*   <tt>shift</tt> – rename arguments, <tt>$2</tt> to <tt>$1</tt>, <tt>$3</tt> to <tt>$2</tt>, etc.; lower counter <tt>$</tt><tt>#</tt>
*   <tt>xargs <tt>_command_</tt></tt> – read stdin and put it as parameters of <tt>_command_</tt>

#### Read options from command line

<pre> while getopts "a:b" opt; do case $opt in
  	a) echo a = $OPTARG ;;
  	b) echo b ;;
  	\?) echo "Unknown parameter!" ;;
esac; done
shift $(($OPTIND - 1)); echo "Last: $1" 
</pre>

### Control expressions

*   <tt>(<tt>_commands_</tt>)</tt>, <tt>$(<tt>_commands_</tt>)</tt>, <tt>`</tt><tt>_commands_</tt><tt>`</tt>, <tt>{<tt>_commands;_</tt>}</tt> – run in subshell
*   <tt>$(<tt>_program_</tt>)</tt>, <tt>`</tt><tt>_program_</tt><tt>`</tt> – output of program replaces command
*   <tt>test</tt>, <tt>[ ]</tt> – condition evaluation:
*   numeric comparison: <tt><tt>_a_</tt> -eq <tt>_b_</tt></tt> … _a=b_, <tt><tt>_a_</tt> -ge <tt>_b_</tt></tt> … _a≥b_, <tt><tt>_a_</tt> -gt <tt>_b_</tt></tt> … _a>b_, <tt><tt>_a_</tt> -le <tt>_b_</tt></tt> … _a≤b_, <tt><tt>_a_</tt> -lt <tt>_b_</tt></tt> … _a<b_
*   file system: <tt>-d <tt>_file_</tt></tt> is directory, <tt>-f <tt>_file_</tt></tt> exists and is not dir., <tt>-r <tt>_file_</tt></tt> exists and is readable, <tt>-w <tt>_file_</tt></tt> exists and is writable, <tt>-s <tt>_file_</tt></tt> is non-zero size, <tt>-a <tt>_file_</tt></tt> exists
*   logical: <tt>-a</tt> and, <tt>-o</tt> or, <tt>!</tt> negation
*   <tt>[[ ]]</tt> – comparison of strings, equal <tt>=</tt>, non-equal <tt>!=</tt>, <tt>-z \sl string</tt> is zero sized, <tt>-n \sl string</tt> is non-zero sized, <tt><</tt>, <tt>></tt> lexical comparison
*   <tt>[</tt> <tt>_condition_</tt> <tt>] && [</tt> <tt>_condition_</tt> <tt>]</tt>
*   <tt>true</tt> – returns 0 value
*   <tt>false</tt> – returns 1 value
*   <tt>break</tt> – terminates executed cycle
*   <tt>continue</tt> – starts new iteration of cycle
*   <tt>eval <tt>_parameters_</tt></tt> – executes parameters as command
*   <tt>exit <tt>_value_</tt></tt> – terminates script with return value
*   <tt>. <tt>_script_</tt></tt>, <tt>source <tt>_script_</tt></tt> – reads and interprets another script
*   <tt>: <tt>_argument_</tt></tt> – just expand argument or do redirect
*   <tt>alias <tt>_name='commands'_</tt></tt> – expand <tt>_name_</tt> to commands
*   <tt>unalias <tt>_name_</tt></tt> – cancel alias
*   <tt>if [ <tt>_condition_</tt> ]; then <tt>_commands_</tt>;
    elif [ <tt>_condition_</tt> ]; then <tt>_commands_</tt>;
    else <tt>_commands_</tt>; fi</tt>
*   <tt>for <tt>_variable_</tt> in <tt>_arguments_</tt>; do <tt>_commands;_ </tt>done</tt>
*   <tt>{a..z</tt> – expands to <tt>a b c … z</tt>
*   <tt>{<tt>_i..n..s_</tt>}</tt> – sequence from <tt>_i_</tt> to <tt>_n_</tt> with step <tt>_s_</tt>
*   <tt><tt>\"</tt>{a,b,c}<tt>\"</tt></tt> – expands to <tt>"a" "b" "c"</tt>
*   <tt>{1,2}{a,b}</tt> – expands to <tt>1a 1b 2a 2b</tt>
*   <tt>seq <tt>_start step end_</tt></tt> – number sequence
*   <tt>for((i=1; i<10; i++)); do <tt>_commands;_ </tt>done</tt>
*   <tt>while <tt>_returns true_</tt>; do <tt>_commands;_</tt> done</tt>
*   <tt>until [ <tt>_test returns true_</tt> ]; do <tt>_commands;_</tt> done</tt>
*   <tt>case $prom</tt> in value__1_) commands ;;
    value__2_) commands ;; *) implicit. commands ;;
    esac
*   Function definition: <tt>function <tt>_name ()_</tt> { <tt>_commands_</tt>; }</tt>
*   <tt>return <tt>_value_</tt></tt> – return value of the function
*   <tt>declare -f <tt>_function_</tt></tt> – print function declaration

### Redirections

*   <tt>0</tt> stdin/input, <tt>1</tt> stdout/output, <tt>2</tt> stderr/error output
*   <tt>></tt> <tt>_file_</tt> – redirection, create new file or truncate it to zero size
*   <tt>>></tt> <tt>_file_</tt> – append new data at the end of file
*   <tt>_command<sub>1</sub>_</tt><tt><<<</tt><tt>_command<sub>2</sub>_</tt> – ouput from 2<sup>nd</sup> to stdin of 1<sup>st</sup>
*   <tt>_command_ </tt><tt><</tt> <tt>_file_</tt> – read stdin from file
*   <tt>tee</tt> <tt>_file_</tt> – read stdin, writes to file and to stdout
*   <tt>_command_</tt> <tt>2></tt> <tt>_file_</tt> – redirect error messages to file
*   <tt>exec 1> >(tee -a log.txt)</tt> – redirect stdout also to file
*   <tt>2>&1</tt> – merge stderr and stdout
*   <tt>exec 3<>/dev/tcp/</tt><tt>_addr/port_</tt> – create descriptor for network read/write
*   <tt>exec 3>&-</tt> – close descriptor
*   <tt>_command_</tt> <tt>> /dev/null 2>&1</tt> – suppress all output
*   <tt>n> n></tt><tt>> n>&m</tt> – operation redirect for descriptors <tt>_n, m_</tt>
*   <tt>mkfifo <tt>_name_</tt></tt> – make a named pipe, that can be written and read as file
*   <tt>_command_</tt><sub>1</sub> <tt>|</tt> <tt>_command_</tt><sub>2</sub> – pipe, connection between processes
*   <tt>read <tt>_parameters_</tt></tt> – read input line and separate it into parameters

#### Input for interactive programs (here documents)

<pre>./program <<  EOF      ./program <<-'EOF' # suppress tabulators
Input1                      Input1
Input2                      Input2
EOF                         EOF
</pre>

#### Process file line by line

<tt>cat file.txt | (while read L; do echo "$L"; done)</tt>

### Evaluating mathematical expressions

*   <tt>let <tt>_expression_</tt></tt>, <tt>expr <tt>_expression_</tt></tt>, <tt>$((</tt>_expression_<tt>))</tt>, <tt>$((</tt>_expression1, expression2_<tt>))</tt>, <tt>$[</tt>_expression_<tt>]</tt>
*   Numeric systems: _base_<tt>#</tt>_number_; hexa <tt>0xABC</tt>, octal <tt>0253</tt>, binary <tt>2#10101011</tt>
*   Operators: <tt>i++</tt>, <tt>++i</tt>, <tt>i–</tt>, <tt>–i</tt>, <tt>+</tt>, <tt>-</tt>; <tt>**</tt> power, <tt>*</tt>, <tt>/</tt>, <tt>%</tt> remainder; logical: <tt>!</tt> neg., <tt>&&</tt> and, <tt>||</tt> or; binary: <tt>~</tt>, <tt>&</tt>, <tt>|</tt>; <tt><<</tt>, <tt>>></tt> shifts; assignment: <tt>= *= /=</tt> <tt>%</tt><tt>= += -= <>= &= ^= |=</tt> <tt>>>= <<=</tt>; relations: <tt>< <= > >=</tt>
*   <tt>factor <tt>_n_</tt></tt> – factorize _n_ into primes
*   Floating point operations: <tt>echo "scale=10; 22/7" <tt>|</tt> bc</tt>

### Screen output

*   <tt>echo "text"</tt> – print text, <tt>echo *</tt> print all files in current dir
*   <tt>echo -e "text"</tt> – interpret escape-sequences (<tt>\t</tt> tab., <tt>\a</tt> beep, <tt>\f</tt> new page, <tt>\n</tt> new line), <tt>-n, <tt>\c</tt></tt> suppressing <tt>\n</tt>, <tt>\x</tt><tt>_HH_</tt> hex-byte, <tt>\<tt>_nnn_</tt></tt> oct. byte, <tt>\u03B1</tt> „α“ (U+03B1) in UTF-8
*   <tt>stty</tt> – change and print terminal line settings
*   <tt>tty</tt> – print name of terminal connected to stdout
*   <tt>printf <tt>_format values_</tt></tt> – format output
*   <tt>printf -v <tt>_variable form. val._</tt></tt> – form. output into variable

*   % [flags][width][.precision][length]specifier
*   Specifier: <tt>%u</tt>, <tt>%d</tt>, <tt>%i</tt> decimal; <tt>%E</tt>, <tt>%f</tt> float, <tt>%x</tt>, <tt>%X</tt> hex; <tt>%o</tt> octal, <tt>%s</tt> string, <tt>%%</tt> char %
*   Width: _n_ prints at least _n_ chars, spaces from right, _0n_ print at least _n_ chars, zeros from left, <tt>*</tt> width specified in preceding parameter
*   Precision: min. number of digits, digits after decimal point, number of printed chars, <tt>*</tt> number of chars given by preceding parameter
*   Flags: <tt>-</tt> left-justify, <tt>+</tt> prints number with sign <tt>+/-</tt>

*   <tt>printf "%d" \'A</tt> – display ASCII code of char “A” (65)
*   <tt>printf \\$(printf '%03o' 65)</tt> – print char given by ASCII code
*   <tt>tput <tt>_action_</tt></tt> – terminal dependent action
*   <tt>reset</tt>, <tt>tput sgr0</tt>, <tt>tset</tt> – reset terminal, cancel attributes
*   <tt>clear</tt>, <tt>tput clear</tt> – clear screen

### Process management

*   <tt>_command_</tt> <tt>&</tt> – run <tt>_command_</tt> in background
*   <tt>prog<sub>1</sub> <tt>&&</tt> prog<sub>2</sub></tt> – run prog<sub>2</sub>, if prog<sub>1</sub> ends with success
*   <tt>prog<sub>1</sub> <tt>||</tt> prog<sub>2</sub></tt> – rub prog<sub>2</sub>, if prog<sub>1</sub> ends with error
*   <span class="C"><span class="key">Ctrl</span>+z</span> – stop process (SIGSTOP)
*   <tt>bg</tt> / <tt>fg</tt> – run last stopped process in background/foreground
*   <tt>jobs</tt> – list processes running in background
*   <tt>exec <tt>_command_</tt></tt> – shell is replaced by <tt>_command_</tt>
*   <tt>wait</tt> – wait for end of background tasks
*   <tt>top</tt> – watch CPU, memory, system utilization
*   <tt>ps -xau</tt> – list processes and users, <tt>ps -xaf, pstree</tt> tree listing
*   <tt>pgrep <tt>_process_</tt></tt>, <tt>pidof <tt>_process_</tt></tt> – get PID by name of process
*   <tt>nice -n <tt>_p_</tt> <tt>_command_</tt></tt> – priority _p_ od _-_20 (max.) to 19 (min.)
*   <tt>renice -n <tt>_p_</tt> -p <tt>_pid_</tt></tt> – change priority of running process
*   <tt>kill -s <tt>_k n_</tt></tt> – send signal _k_ to proces id. _n_, 0, 1 SIGHUP; 2 SIGINT <span class="C"><span class="key">Ctrl</span>+c</span>; 3 SIGQUIT; 9 SIGKILL; 15 SIGTERM; 24 SIGSTOP
*   <tt>trap '<tt>_command_</tt>' signals</tt> – run command when signal received
*   <tt>killall <tt>_name_</tt></tt> – send signals to process by name
*   <tt>nohup <tt>_command_</tt></tt> <tt>&</tt> – command will continue after logout
*   <tt>time <tt>_command_</tt></tt> – print time of process execution
*   <tt>times</tt> – print user and system time utilization in current shell
*   <tt>watch -n <tt>_s command_</tt></tt> – every <tt>_s_</tt> seconds run command

### Time and process planning

*   <tt>date</tt> – print date, <tt>date –date=@\sl unix_time</tt>
*   <tt>date +"%Y%m%d</tt> <tt>%H:%M:%S</tt> <tt>%Z"</tt> – format to <tt>20130610 13:39:02 CEST</tt>
*   <tt>cal</tt> – display calendar
*   <tt>crontab -e</tt> – edit crontab, <tt>-l</tt> list, format <tt>_min hour date month day command_</tt>, <tt>* * * * * command</tt> run every minute, <tt>1 * * * * command</tt> 1<sup>st</sup> min of every hour
*   <tt>at, batch, atq, atrm</tt> – queue, examine or delete jobs for later execution

### File operations

File name wildchars: <tt>?</tt> a char; <tt>*</tt> zero or more chars; <tt>[</tt><tt>_set_</tt><tt>]</tt> one or more given chars, interval <tt>[0-9]</tt> <tt>[a-z]</tt>, <tt>[A-Z]</tt>; <tt>[!</tt><tt>_set_</tt><tt>]</tt>, <tt>[^</tt><tt>_set_</tt><tt>]</tt> none of chars.

*   <tt>ls</tt> – list directory, <tt>ls -la</tt>, <tt>vdir</tt> all files with info
*   <tt>tree</tt> – display hierarchy tree of directories
*   <tt>file <tt>_file_</tt></tt> – determine file by its magic number
*   <tt>lsattr, chattr</tt> – list and change file attributes for ext2,3
*   <tt>umask</tt> – define permission mask for new file
*   <tt>pwd (-P)</tt> – logical (physical) path to current directory
*   <tt>cd directory</tt> – change directory, <tt>cd</tt> jump to <tt>$HOME</tt>, <tt>cd -</tt> to <tt>$OLDPWD</tt>
*   <tt>dirs</tt> – list stack of directories
*   <tt>pushd <tt>_directory_</tt></tt> – store <tt>_directory_</tt> to stack
*   <tt>popd</tt> – set top stack directory as actual directory
*   <tt>cp <tt>_source target_</tt></tt> – copy file
*   <tt>ln -s <tt>_source link_</tt></tt> – create a symbolic link
*   <tt>mkdir</tt>, <tt>rmdir</tt> – create, remove directory
*   <tt>rm <tt>_file_</tt></tt>, <tt>rm -r -f <tt>_directory_</tt></tt>, <tt>unlink</tt> – delete
*   <tt>touch <tt>_file_</tt></tt> – create file, set actual time to existing file
*   <tt>du -h</tt> – display space usage of directories
*   <tt>stat <tt>_file_</tt></tt> – file statistics, <tt>stat –format=%s</tt> size
*   <tt>basename <tt>_name suffix_</tt></tt> – remove path or suffix
*   <tt>dirname <tt>_/path/to/file_</tt></tt> – print only path
*   <tt>repquota</tt> – summarize quotas for a filesystem
*   <tt>mktemp</tt> – create file with unique name in <tt>/tmp</tt>

### Work with file content

*   <tt>cat</tt> – concatenate files and print them to stdout
*   <tt>cat > file</tt> – create file, end with <span class="C"><span class="key">Ctrl</span>+d</span>
*   <tt>tac</tt> – like <tt>cat</tt>, but from bottom to top line
*   <tt>more</tt>, <tt>less</tt> – print by pages, scrollable
*   <tt>od</tt>, <tt>hexdump -C</tt>, <tt>xxd</tt> – print in octal, hex dump
*   <tt>wc</tt> – get number of lines <tt>-l</tt>, chars <tt>-n</tt>, bytes <tt>-c</tt>, words <tt>-w</tt>
*   <tt>head</tt>/<tt>tail</tt> – print begin/end, <tt>tailf, tail -f</tt> wait for new lines
*   <tt>split</tt>, <tt>csplit</tt> – split file by size, content
*   <tt>sort</tt> – <tt>-n</tt> numerical, <tt>-r</tt> reverse, <tt>-f</tt> ignore case
*   <tt>uniq</tt> – omit repeated lines, <tt>-d</tt> show only duplicates
*   <tt>sed -e '<tt>_script_</tt>'</tt> – stream editor, script <tt>y/ABC/abc/</tt> replaces A, B, C for a, b, c; <tt>s/regexp/substitution/</tt>
*   <tt>tr <tt>_a b_</tt></tt> – replace char <tt>_a_</tt> for <tt>_b_</tt>
*   <tt>tr '[a-z]' '[A-Z]' < file.txt</tt> – change lowercase to uppercase
*   <tt>awk '/pattern/ { action }' <tt>_file_</tt></tt> – process lines containing pattern
*   <tt>cut -d <tt>_delimiter_</tt> -f <tt>_field_</tt></tt> – print column(s)
*   <tt>cmp <tt>_file1_</tt> <tt>_file2_</tt></tt> – compare files and print first difference
*   <tt>diff, diff3, sdiff, vimdiff</tt> – compare whole files
*   <tt>dd if=<tt>_in_</tt> of=<tt>_out_</tt> bs=<tt>_k_</tt></tt> count=<tt>_n_</tt> – read _n_ blocks of _k_ bytes
*   <tt>strings</tt> – show printable strings in binary file
*   <tt>paste <tt>_file<sub>1</sub> file<sub>2</sub>_</tt></tt> – merge lines of files
*   <tt>rev</tt> – reverse every line

### Search

*   <tt>whereis, which</tt> – find path to command
*   <tt>grep</tt> – <tt>-i</tt> ignore case, <tt>-n</tt> print line number, <tt>-v</tt> display everything except pattern, <tt>-E</tt> extended regexp
*   <tt>locate <tt>_file_</tt></tt> – find file
*   <tt>find <tt>_path_</tt> -name 'file*'</tt> – search for <tt>_file*_</tt>
*   <tt>find <tt>_path_</tt> -exec grep <tt>_text_</tt> -H {} \;</tt> – find file containing <tt>_text_</tt>

### Users and permissions

*   <tt>whoami, who am i</tt> – tell who I am :)
*   <tt>w, who, users, finger</tt> – list connected users
*   <tt>last / lastb</tt> – history successful / unsuccessful logins
*   <tt>logout</tt>, <span class="C"><span class="key">Ctrl</span>+d</span> – exit shell
*   <tt>su <tt>_login_</tt></tt> – change user to <tt>_login_</tt>
*   <tt>sudo</tt> – run command as other user
*   <tt>id <tt>_login_</tt></tt>, <tt>groups <tt>_login_</tt></tt> – show user details
*   <tt>useradd, userdel, usermod</tt> – create, delete, edit user
*   <tt>groupadd, groupdel, groupmod</tt> – create, delete, edit group
*   <tt>passwd</tt> – change password
*   <tt>pwck</tt> – check integrity of <tt>/etc/passwd</tt>
*   <tt>chown <tt>_user:group file_</tt></tt> – change owner, <tt>-R</tt> recursion
*   <tt>chgrp <tt>_group file_</tt></tt> – change group of file
*   <tt>chmod <tt>_permissions file_</tt></tt> – change permissions in octal of user, group, others; <tt>444=-r–r–r–</tt>, <tt>700=-rwx——</tt>, <tt>550=-r-xr-x—</tt>
*   <tt>runuser <tt>_login_</tt> -c <tt>_"command"_</tt></tt> – run command as user

### System utilities

*   <tt>uname -a</tt> – name and version of operating system
*   <tt>uptime</tt> – how long the system has been running
*   <tt>fuser</tt> – identify processes using files or sockets
*   <tt>lsof</tt> – list open files
*   <tt>sync</tt> – flush file system buffers
*   <tt>chroot <tt>_dir command_</tt></tt> – run command with special root directory
*   <tt>strace,ltrace <tt>_program_</tt></tt> – show used system/library calls
*   <tt>ldd <tt>_binary_</tt></tt> – show library dependencies

#### Disk partitions

*   <tt>df</tt> – display free space
*   <tt>mount</tt> – print mounted partitions
*   <tt>mount -o remount -r -n /</tt> – change mount read only
*   <tt>mount -o remount -w -n /</tt> – change mount writeable
*   <tt>mount -t iso9660 cdrom.iso /mnt/dir -o loop</tt> – mount image
*   <tt>mount -t cifs \\\\server\\ftp /mnt/adr -o user=a,passwd=b</tt>
*   <tt>umount <tt>_partition_</tt></tt> – unmount partition
*   <tt>fdisk -l</tt> – list disk devices and partitions
*   <tt>blkid</tt> – display attributes of block devices
*   <tt>tune2fs</tt> – change ext2/3/4 filesystem parameters
*   <tt>mkfs.ext2</tt>, <tt>mkfs.ext3</tt> – build file-system
*   <tt>hdparm</tt> – set/read parameters of SATA/IDE devices

#### System utilization

*   <tt>ulimit -l</tt> – print limits of system resources
*   <tt>free</tt>, <tt>vmstat</tt> – display usage of physical, virt. memory
*   <tt>lspci</tt>, <tt>lsusb</tt> – list PCI, USB devices
*   <tt>dmesg</tt> – display messages from kernel
*   <tt>sysctl</tt> – configure kernel parameters at runtime
*   <tt>dmidecode</tt> – decoder for BIOS data (DMI table)
*   <tt>init</tt>, <tt>telinit</tt> – command <tt>init</tt> to change runlevel
*   <tt>runlevel</tt>, <tt>who -r</tt> – display current runlevel

### Networking

*   <tt>hostname</tt> – display computer hostname
*   <tt>ping <tt>_host_</tt></tt> – send ICMP ECHO_REQUEST
*   <tt>dhclient eth0</tt> – dynamically set <tt>eth0</tt> configuration
*   <tt>host, nslookup <tt>_host/adr_</tt></tt> – DNS query
*   <tt>dig</tt> – get record from DNS
*   <tt>whois <tt>_domain_</tt></tt> – finds owner of domain or network range
*   <tt>ethtool eth0</tt> – change HW parameters of network interface <tt>eth0</tt>
*   <tt>ifconfig</tt> – display network devices, device configuration
*   <tt>ifconfig eth0 add 10.0.0.1 netmask 255.255.255.0</tt>
*   <tt>ifconfig eth0 hw ether 01:02:03:04:05:06</tt> – change MAC address
*   <tt>route add default gw 10.0.0.138</tt> – set network gateway
*   <tt>route -n</tt>, <tt>netstat -rn</tt> – display route table
*   <tt>netstat -tlnp</tt> – display processes listening on ports
*   <tt>arp</tt> – display ARP table
*   <tt>iptables -L</tt> – display firewall rules
*   <tt>tcpdump -i eth0 'tcp port 80'</tt> – display HTTP communication
*   <tt>tcpdump -i eth0 'not port ssh'</tt> – all communication except SSH
*   <tt>ssh user@hostname <tt>_command_</tt></tt> – run command remotely
*   <tt>mail -s "subject" address</tt> – send email to address
*   <tt>wget -e robots=off -r -L http://<tt>_path_</tt></tt> – mirror given page

This text was mirrored from http://bruxy.regnet.cz/linux/bash_cheatsheet/bash_cheatsheet.html
