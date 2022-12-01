One-liner introduction
This chapter will give an overview of perl syntax for command line usage and some examples to show what kind of problems are typically suited for one-liners.

Why use Perl for one-liners?
I assume you are already familiar with use cases where command line is more productive compared to GUI. See also this series of articles titled Unix as IDE.

A shell utility like bash provides built-in commands and scripting features to easily solve and automate various tasks. External *nix commands like grep, sed, awk, sort, find, parallel, etc can be combined to work with each other. Depending upon your familiarity with those tools, you can either use perl as a single replacement or complement them for specific use cases.

Here's some one-liners (options will be explained later):

perl -pe 's/(?:\x27;\x27|";")(*SKIP)(*F)|;/#/g' — change ; to # but don't change ; within single or double quotes
perl -MList::Util=uniq -e 'print uniq <>' — retain only first copy of duplicated lines, uses built-in module List::Util
perl -MRegexp::Common=net -nE 'say $& while /$RE{net}{IPv4}/g' — extract only IPv4 addresses, using a third-party Regexp::Common module
Some stackoverflow Q&A that I've answered over the years with simpler perl solution compared to other cli tools
replace string with incrementing value
sort rows in csv file without header & first column
reverse matched pattern
append zeros to list
arithmetic replacement in a text file
reverse complement DNA sequence for a specific field
The selling point of perl over tools like grep, sed and awk includes feature rich regular expression engine and standard/third-party modules. If you don't already know the syntax and idioms for sed and awk, learning command line options for perl would be the easier option. Another advantage is that perl is more portable, given the many differences between GNU, BSD, Mac and other such implementations. The main disadvantage is that perl is likely to be verbose and slower for features that are supported out of the box by those tools.

info See also unix.stackexchange: when to use grep, sed, awk, perl, etc

Installation and Documentation
If you are on a Unix like system, you are most likely to already have some version of Perl installed. See cpan: Perl Source for instructions to install the latest perl version from source. perl v5.32.0 is used for all the examples shown in this book.

You can use perldoc command to access documentation from the command line. You can visit https://perldoc.perl.org/ if you wish to read it online, which also has a handy search feature. Here's some useful links to get started:

perldoc: overview
perldoc: perlintro
perldoc: faqs
Command line options
perl -h gives the list of all command line options, along with a brief description. See perldoc: perlrun for documentation on these command switches.

Option	Description
-0[octal]	specify record separator (\0, if no argument)
-a	autosplit mode with -n or -p (splits $_ into @F)
-C[number/list]	enables the listed Unicode features
-c	check syntax only (runs BEGIN and CHECK blocks)
-d[:debugger]	run program under debugger
-D[number/list]	set debugging flags (argument is a bit mask or alphabets)
-e program	one line of program (several -e's allowed, omit programfile)
-E program	like -e, but enables all optional features
-f	don't do $sitelib/sitecustomize.pl at startup
-F/pattern/	split() pattern for -a switch (//'s are optional)
-i[extension]	edit <> files in place (makes backup if extension supplied)
-Idirectory	specify @INC/#include directory (several -I's allowed)
-l[octal]	enable line ending processing, specifies line terminator
-[mM][-]module	execute use/no module... before executing program
-n	assume while (<>) { ... } loop around program
-p	assume loop like -n but print line also, like sed
-s	enable rudimentary parsing for switches after programfile
-S	look for programfile using PATH environment variable
-t	enable tainting warnings
-T	enable tainting checks
-u	dump core after parsing program
-U	allow unsafe operations
-v	print version, patchlevel and license
-V[:variable]	print configuration summary (or a single Config.pm variable)
-w	enable many useful warnings
-W	enable all warnings
-x[directory]	ignore text before #!perl line (optionally cd to directory)
-X	disable all warnings
This chapter will show examples with -e, -l, -n, -p and -a options. Some more options will be covered in later chapters, but not all of them are discussed in this book.

Executing Perl code
If you want to execute a perl program file, one way is to pass the filename as argument to the perl command.


$ echo 'print "Hello Perl\n"' > hello.pl
$ perl hello.pl
Hello Perl
For short programs, you can also directly pass the code as an argument to the -e or -E options. See perldoc: feature for details about the features enabled by the -E option.


$ perl -e 'print "Hello Perl\n"'
Hello Perl

$ # multiple statements can be issued separated by ;
$ # -l option will be covered in detail later, appends \n to 'print' here
$ perl -le '$x=25; $y=12; print $x**$y'
59604644775390625
$ # or, use -E and 'say' instead of -l and 'print'
$ perl -E '$x=25; $y=12; say $x**$y'
59604644775390625
Filtering
perl one-liners can be used for filtering lines matched by a regexp, similar to grep, sed and awk. And similar to many command line utilities, perl can accept input from both stdin and file arguments.


$ # sample stdin data
$ printf 'gate\napple\nwhat\nkite\n'
gate
apple
what
kite

$ # print all lines containing 'at'
$ # same as: grep 'at' and sed -n '/at/p' and awk '/at/'
$ printf 'gate\napple\nwhat\nkite\n' | perl -ne 'print if /at/'
gate
what

$ # print all lines NOT containing 'e'
$ # same as: grep -v 'e' and sed -n '/e/!p' and awk '!/e/'
$ printf 'gate\napple\nwhat\nkite\n' | perl -ne 'print if !/e/'
what
By default, grep, sed and awk will automatically loop over input content line by line (with \n as the line distinguishing character). The -n or -p option will enable this feature for perl. O module section shows the code Perl runs with these options.

As seen before, the -e option accepts code as command line argument. Many shortcuts are available to reduce the amount of typing needed. In the above examples, a regular expression (defined by the pattern between a pair of forward slashes) has been used to filter the input. When the input string isn't specified, the test is performed against special variable $_, which has the contents of the current input line here (the correct term would be input record, see Record separators chapter). $_ is also the default argument for many functions like print and say. To summarize:

/REGEXP/FLAGS is a shortcut for $_ =~ m/REGEXP/FLAGS
!/REGEXP/FLAGS is a shortcut for $_ !~ m/REGEXP/FLAGS
info See perldoc: match for help on m operator. See perldoc: special variables for documentation on $_, $&, etc.

Here's an example with file input instead of stdin.


$ cat table.txt
brown bread mat hair 42
blue cake mug shirt -7
yellow banana window shoes 3.14

$ perl -nE 'say $& if /(?<!-)\d+$/' table.txt
42
14

$ # if the condition isn't required, capture groups can be used
$ perl -nE 'say /(\d+)$/' table.txt
42
7
14
info The learn_perl_oneliners repo has all the files used in examples (like table.txt in the above example).

Substitution
Use s operator for search and replace requirements. By default, this operates on $_ when the input string isn't provided. For these examples, -p option is used instead of -n option, so that the value of $_ is automatically printed after processing each input line. See perldoc: search and replace for documentation and examples.


$ # for each input line, change only first ':' to '-'
$ # same as: sed 's/:/-/' and awk '{sub(/:/, "-")} 1'
$ printf '1:2:3:4\na:b:c:d\n' | perl -pe 's/:/-/'
1-2:3:4
a-b:c:d

$ # for each input line, change all ':' to '-'
$ # same as: sed 's/:/-/g' and awk '{gsub(/:/, "-")} 1'
$ printf '1:2:3:4\na:b:c:d\n' | perl -pe 's/:/-/g'
1-2-3-4
a-b-c-d
info The s operator modifies the input string it is acting upon if the pattern matches. In addition, it will return number of substitutions made if successful, otherwise returns a false value (empty string or 0). You can use r flag to return string after substitution instead of in-place modification. As mentioned before, this book assumes you are already familiar with perl regular expressions. If not, see perldoc: perlretut to get started.

Field processing
Consider the sample input file shown below with fields separated by a single space character.


$ cat table.txt
brown bread mat hair 42
blue cake mug shirt -7
yellow banana window shoes 3.14
Here's some examples that is based on specific field rather than the entire line. The -a option will cause the input line to be split based on whitespaces and the field contents can be accessed using @F special array variable. Leading and trailing whitespaces will be suppressed, so there's no possibility of empty fields. More details is discussed in Default field separation section.


$ # print the second field of each input line
$ # same as: awk '{print $2}' table.txt
$ perl -lane 'print $F[1]' table.txt
bread
cake
banana

$ # print lines only if the last field is a negative number
$ # same as: awk '$NF<0' table.txt
$ perl -lane 'print if $F[-1] < 0' table.txt
blue cake mug shirt -7

$ # change 'b' to 'B' only for the first field
$ # same as: awk '{gsub(/b/, "B", $1)} 1' table.txt
$ perl -lane '$F[0] =~ s/b/B/g; print "@F"' table.txt
Brown bread mat hair 42
Blue cake mug shirt -7
yellow banana window shoes 3.14
See Output field separator section for details on using array variable inside double quotes.

BEGIN and END
You can use a BEGIN{} block when you need to execute something before input is read and a END{} block to execute something after all of the input has been processed.


$ # same as: awk 'BEGIN{print "---"} 1; END{print "%%%"}'
$ seq 4 | perl -pE 'BEGIN{say "---"} END{say "%%%"}'
---
1
2
3
4
%%%
ENV hash
When it comes to automation and scripting, you'd often need to construct commands that can accept input from user, file, output of a shell command, etc. As mentioned before, this book assumes bash as the shell being used. To access environment variables of the shell, you can use the special hash variable %ENV with the name of the environment variable as a string key.

info Quotes won't be used around hash keys in this book. See stackoverflow: are quotes around hash keys a good practice in Perl? on possible issues if you don't quote the hash keys.


$ # existing environment variable
$ # output shown here is for my machine, would differ for you
$ perl -E 'say $ENV{HOME}'
/home/learnbyexample
$ perl -E 'say $ENV{SHELL}'
/bin/bash

$ # defined along with perl command
$ # note that the variable definition is placed before the shell command
$ word='hello' perl -E 'say $ENV{word}'
hello
$ # the characters are preserved as is
$ ip='hi\nbye' perl -E 'say $ENV{ip}'
hi\nbye
Here's another example when a regexp is passed as an environment variable content.


$ cat word_anchors.txt
sub par
spar
apparent effort
two spare computers
cart part tart mart

$ # assume 'r' is a shell variable that has to be passed to the perl command
$ r='\Bpar\B'
$ rgx="$r" perl -ne 'print if /$ENV{rgx}/' word_anchors.txt
apparent effort
two spare computers
You can also make use of the -s option to assign a perl variable.


$ r='\Bpar\B'
$ perl -sne 'print if /$rgx/' -- -rgx="$r" word_anchors.txt
apparent effort
two spare computers
info As an example, see my repo ch: command help for a practical shell script, where commands are constructed dynamically.

Executing external commands
You can execute external commands using the system function. See perldoc: system for documentation and details like how string/list argument is processed before it is executed.


$ perl -e 'system("echo Hello World")'
Hello World

$ perl -e 'system("wc -w <word_anchors.txt")'
12

$ perl -e 'system("seq -s, 10 > out.txt")'
$ cat out.txt
1,2,3,4,5,6,7,8,9,10
Return value of system or special variable $? can be used to act upon exit status of command issued. As per documentation:

info The return value is the exit status of the program as returned by the wait call. To get the actual exit value, shift right by eight


$ perl -E '$es=system("ls word_anchors.txt"); say $es'
word_anchors.txt
0
$ perl -E 'system("ls word_anchors.txt"); say $?'
word_anchors.txt
0

$ perl -E 'system("ls xyz.txt"); say $?'
ls: cannot access 'xyz.txt': No such file or directory
512
To save the result of an external command, use backticks or qx operator. See perldoc: qx for documentation and details like separating out STDOUT and STDERR.


$ perl -e '$words = `wc -w <word_anchors.txt`; print $words'
12

$ perl -e '$nums = qx/seq 3/; print $nums'
1
2
3
info See also stackoverflow: difference between backticks, system, and exec

Summary
This chapter introduced some of the common options for perl cli usage, along with typical cli text processing examples. While specific purpose cli tools like grep, sed and awk are usually faster, perl has a much more extensive standard library and ecosystem. And you do not have to learn a lot if you are already comfortable with perl but not familiar with those cli tools. The next section has a few exercises for you to practice the cli options and text processing use cases.

Exercises
info Exercise related files are available from exercises folder of learn_perl_oneliners repo.

info All the exercises are also collated together in one place at Exercises.md. To see the solutions, visit Exercise_solutions.md.

a) For the input file ip.txt, display all lines containing is.


$ cat ip.txt
Hello World
How are you
This game is good
Today is sunny
12345
You are funny

##### add your solution here
This game is good
Today is sunny
b) For the input file ip.txt, display first field of lines not containing y. Consider space as the field separator for this file.


##### add your solution here
Hello
This
12345
c) For the input file ip.txt, display all lines containing no more than 2 fields.


##### add your solution here
Hello World
12345
d) For the input file ip.txt, display all lines containing is in the second field.


##### add your solution here
Today is sunny
e) For each line of the input file ip.txt, replace first occurrence of o with 0.


##### add your solution here
Hell0 World
H0w are you
This game is g0od
T0day is sunny
12345
Y0u are funny
f) For the input file table.txt, calculate and display the product of numbers in the last field of each line. Consider space as the field separator for this file.


$ cat table.txt
brown bread mat hair 42
blue cake mug shirt -7
yellow banana window shoes 3.14

##### add your solution here
-923.16
g) Append . to all the input lines for the given stdin data.


$ printf 'last\nappend\nstop\n' | ##### add your solution here
last.
append.
stop.
h) Use contents of s variable to display all matching lines from the input file ip.txt. Assume that s doesn't have any regexp metacharacters. Construct the solution such that there's at least one word character immediately preceding the contents of s variable.


$ s='is'

##### add your solution here
This game is good
i) Use system to display contents of filename present in second field (space separated) of the given input line.


$ s='report.log ip.txt sorted.txt'
$ echo "$s" | ##### add your solution here
Hello World
How are you
This game is good
Today is sunny
12345
You are funny

$ s='power.txt table.txt'
$ echo "$s" | ##### add your solution here
brown bread mat hair 42
blue cake mug shirt -7
yellow banana window shoes 3.14
