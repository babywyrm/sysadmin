https://learnbyexample.github.io/learn_gnugrep_ripgrep/ripgrep.html

##
##
##
##

ripgrep

ripgrep is definitely becoming a popular alternative (if not the most popular) to the grep command. Editors like Visual Studio Code and Atom are using ripgrep to power their search offerings. The major selling point is its default behavior for recursive search and speed. The project doesn't aim to be compatible with POSIX and behavior varies with respect to GNU grep in terms of features, option names, output style, regular expressions, etc.

Project links

github: ripgrep
issue manager
User guide
FAQ
Benchmark with other grep implementations — published in 2016
info See Feature comparison of ack, ag, git-grep, GNU grep and ripgrep for quick overview between different grep implementations. See also issues as the chart might be pending updates.

Installation
See ripgrep: installation for details on various methods and platforms. Instructions shown below is for Debian-like distributions.


$ # link shown here on two lines as it is too long
$ # visit using the first part to get latest version
$ link='https://github.com/BurntSushi/ripgrep/releases/'
$ link="$link"'download/12.1.1/ripgrep_12.1.1_amd64.deb'
$ wget "$link"
$ sudo gdebi ripgrep_12.1.1_amd64.deb 

$ # note that the installed command name is rg, not ripgrep
$ rg --version
ripgrep 12.1.1 (rev 7cb211378a)
-SIMD -AVX (compiled)
+SIMD -AVX (runtime)
Default behavior
Compared to GNU grep, the following is a list of default rg behavior (there could be more such differences):

recursive search, if any input path is a directory (CWD if source is not specified) and
ignores files and directories that match rules specified by ignore files like .gitignore
ignores hidden files and directories
ignores binary files (files containing ASCII NUL character) — but displays the match if found before encountering NUL character along with a warning
blank line between matches from different files
filename is added as a prefix line above matching lines instead of prefix for each matching line
line number prefix
color option is enabled by default
info Files used in examples are available chapter wise from learn_gnugrep_ripgrep repo. This chapter will reuse directories used for GNU grep. The recursive_matching directory was created in Recursive search chapter.


$ # assumes 'recursive_matching' as CWD
$ # by default line numbers are shown on terminal
$ rg 'repo' nested_group.txt
10:prepossesses
13:repossesses

$ # recursive search example
$ rg 'a' scripts
scripts/pi.py
1:import math
3:print(math.pi)

scripts/decode.sh
1:tr 'a-z0-9' 'n-za-m5-90-4' < .key
Options overview
It is always a good idea to know where to find the documentation. From command line, you can use man rg for manual and rg -h for list of all the options. See also ripgrep: User guide.


$ man rg
NAME
       rg - recursively search current directory for lines matching a pattern

SYNOPSIS
       rg [OPTIONS] PATTERN [PATH...]
       rg [OPTIONS] -e PATTERN... [PATH...]
       rg [OPTIONS] -f PATTERNFILE... [PATH...]
       rg [OPTIONS] --files [PATH...]
       rg [OPTIONS] --type-list
       command | rg [OPTIONS] PATTERN
       rg [OPTIONS] --help
       rg [OPTIONS] --version

DESCRIPTION
       ripgrep (rg) recursively searches your current directory for a regex
       pattern. By default, ripgrep will respect your .gitignore and
       automatically skip hidden files/directories and binary files.

       ripgrep’s default regex engine uses finite automata and guarantees
       linear time searching. Because of this, features like backreferences
       and arbitrary look-around are not supported. However, if ripgrep is
       built with PCRE2, then the --pcre2 flag can be used to enable
       backreferences and look-around.

       ripgrep supports configuration files. Set RIPGREP_CONFIG_PATH to a
       configuration file. The file can specify one shell argument per line.
       Lines starting with # are ignored. For more details, see the man page
       or the README.

       ripgrep will automatically detect if stdin exists and search stdin for
       a regex pattern, e.g. ls | rg foo. In some environments, stdin may
       exist when it shouldn’t. To turn off stdin detection explicitly specify
       the directory to search, e.g. rg foo ./.

       Tip: to disable all smart filtering and make ripgrep behave a bit more
       like classical grep, use rg -uuu.
This section will cover some of the options provided by ripgrep with examples. These are adapted from examples presented for GNU grep and explanations will be kept to a minimum. Regular expressions will be covered in separate sections later on.

Literal search

$ # assumes 'freq_options' as CWD
$ rg -F 'twice' programming_quotes.txt
1:Debugging is twice as hard as writing the code in the first place.

$ echo 'int a[5]' | rg -F 'a[5]'
int a[5]
Case insensitive search

$ rg -i 'jam' programming_quotes.txt
6:use regular expressions. Now they have two problems by Jamie Zawinski

$ printf 'Cat\ncOnCaT\nscatter\ncut' | rg -i 'cat'
Cat
cOnCaT
scatter
Invert matching lines

$ seq 5 | rg -v '3'
1
2
4
5

$ printf 'goal\nrate\neat\npit' | rg -v 'at'
goal
pit
Line number and count
Default settings like line number and color depend upon context. If output is terminal, these are on, but if output is redirected to file, another command, etc then they are turned off. Also, if stdin is the only source of input, line number option won't turn on.


$ # -n will ensure line numbers are available for further processing
$ rg -n 'twice' programming_quotes.txt
1:Debugging is twice as hard as writing the code in the first place.
$ # -N to turn off default line number prefix on terminal
$ rg -N 'twice' programming_quotes.txt
Debugging is twice as hard as writing the code in the first place.

$ # count of matching/non-matching lines
$ rg -c 'in' programming_quotes.txt
8
$ printf 'goal\nrate\neat\npit' | rg -vc 'g'
3

$ # multiple file input
$ seq 15 | rg -c '1' programming_quotes.txt -
<stdin>:7
programming_quotes.txt:1
$ cat <(seq 15) programming_quotes.txt | rg -c '1'
8
If any input file doesn't have a match, -c will not display that file in output. You can use --include-zero to display files without matches as well.


$ rg -c '1' *
search_strings.txt:1
programming_quotes.txt:1

$ # same as: grep -c '1' *
$ rg -c --include-zero '1' *
search_strings.txt:1
programming_quotes.txt:1
colors_1:0
colors_2:0
Limiting output lines

$ # limit no. of matching lines displayed for each input file
$ rg -m3 'in' programming_quotes.txt
1:Debugging is twice as hard as writing the code in the first place.
3:by definition, not smart enough to debug it by Brian W. Kernighan
5:Some people, when confronted with a problem, think - I know, I will

$ seq 1000 | rg -m4 '2'
2
12
20
21
Multiple search strings

$ # search for '1' or 'two', similar to conditional OR boolean logic
$ rg -e '1' -e 'two' programming_quotes.txt
6:use regular expressions. Now they have two problems by Jamie Zawinski
12:naming things, and off-by-1 errors by Leon Bambrick

$ # specify a file as source of search strings
$ printf 'two\n1\n' > search_strings.txt
$ rg -f search_strings.txt programming_quotes.txt
6:use regular expressions. Now they have two problems by Jamie Zawinski
12:naming things, and off-by-1 errors by Leon Bambrick

$ # -f and -e can be combined and used multiple times
$ rg -f search_strings.txt -e 'twice' programming_quotes.txt
1:Debugging is twice as hard as writing the code in the first place.
6:use regular expressions. Now they have two problems by Jamie Zawinski
12:naming things, and off-by-1 errors by Leon Bambrick

$ # match lines containing both 'in' and 'not' in any order
$ # similar to conditional AND boolean logic
$ rg 'in' programming_quotes.txt | rg 'not'
by definition, not smart enough to debug it by Brian W. Kernighan
A language that does not affect the way you think about programming,
is not worth knowing by Alan Perlis
Get filename instead of matching lines

$ # list filename if it contains 'are' anywhere in the file
$ rg -l 'are' programming_quotes.txt search_strings.txt
programming_quotes.txt
$ rg -l 'xyz' programming_quotes.txt search_strings.txt
$ rg -l '1' programming_quotes.txt search_strings.txt
search_strings.txt
programming_quotes.txt

$ # list filename if it does NOT contain 'xyz' anywhere in the file
$ rg --files-without-match 'xyz' programming_quotes.txt search_strings.txt
search_strings.txt
programming_quotes.txt
$ rg --files-without-match 'are' programming_quotes.txt search_strings.txt
search_strings.txt
Filename prefix for matching lines

$ # by default, filename isn't printed for single input
$ rg '1' programming_quotes.txt
12:naming things, and off-by-1 errors by Leon Bambrick
$ # use -I to suppress filename prefix for multiple input
$ seq 1000 | rg -I -m3 '1' - programming_quotes.txt
1:1
10:10
11:11

12:naming things, and off-by-1 errors by Leon Bambrick

$ # default behavior for multiple file input
$ seq 1000 | rg -m3 '1' - programming_quotes.txt
programming_quotes.txt
12:naming things, and off-by-1 errors by Leon Bambrick

<stdin>
1:1
10:10
11:11
$ # use -H to always show filename prefix
$ rg -H '1' programming_quotes.txt
programming_quotes.txt
12:naming things, and off-by-1 errors by Leon Bambrick
To get output format same as GNU grep


$ # use --no-heading to get same style as GNU grep
$ rg --no-heading -H '1' programming_quotes.txt
programming_quotes.txt:12:naming things, and off-by-1 errors by Leon Bambrick

$ # --no-heading is automatically assumed when output is redirected
$ rg -Hn '1' *.txt | cat -
search_strings.txt:2:1
programming_quotes.txt:12:naming things, and off-by-1 errors by Leon Bambrick
The vim editor has an option -q that allows to easily edit the matching lines from rg output if it has both line number and filename prefixes. Use --vimgrep option instead of -Hn to allow vim to place cursor from start of match instead of start of line.


$ rg --vimgrep '1' *.txt
search_strings.txt:2:1:1
programming_quotes.txt:12:27:naming things, and off-by-1 errors by Leon Bambrick

$ # use :cn and :cp to navigate to next/previous occurrences
$ # the status line at bottom will have additional info
$ vim -q <(rg --vimgrep '1' *.txt)
Colored output
By default, --color=auto setting is used to distinguish matching portions, line numbers, filenames, etc. Use never to disable color and always to carry forward color information for further processing.

rg color output

Below image shows difference between auto and always. In the first case, in is highlighted even after piping, while in the second case, in is not highlighted. In practice, always is rarely used (for example: piping results to less -R) as it has extra information added to matching lines and could cause undesirable results when processing such lines. You can also use -p option, which is a shortcut to enable --color=always --heading --line-number options.

rg auto vs always

The --colors (note the plural form) option is useful to customize colors and style used for matching text, line numbers, etc. A common usage is to highlight multiple terms in different colors. See manual for complete details.

rg colors customize

Match whole word or line
warning The -w option behaves a bit differently than word boundaries in regular expressions. See Word boundary differences section for details.


$ # this matches 'par' anywhere in the line
$ printf 'par value\nheir apparent\n' | rg 'par'
par value
heir apparent

$ # this matches 'par' only as a whole word
$ # word character means any alphabet, digit or underscore characters
$ printf 'par value\nheir apparent\n' | rg -w 'par'
par value
Use -x to display a line only if entire line satisfies the given pattern.


$ # this matches 'my book' anywhere in the line
$ printf 'see my book list\nmy book\n' | rg 'my book'
see my book list
my book
$ # this matches 'my book' only if no other characters are present
$ printf 'see my book list\nmy book\n' | rg -x 'my book'
my book

$ # counting empty lines
$ rg -cx '' programming_quotes.txt
3
The -f and -x options can be combined to get common lines between two files or the difference when -v is used as well. Add -F as well depending on whether literal or regular expressions matching is needed.


$ # common lines between two files
$ rg -Fxf colors_1 colors_2
4:yellow

$ # lines present in colors_2 but not in colors_1
$ rg -Fvxf colors_1 colors_2
1:blue
2:black
3:dark green

$ # lines present in colors_1 but not in colors_2
$ rg -Fvxf colors_2 colors_1
1:teal
2:light blue
3:brown
Extract only matching portion

$ rg -o -e 'twice' -e 'hard' programming_quotes.txt
1:twice
1:hard
11:hard

$ # -c only gives count of matching lines
$ rg -c 'in' programming_quotes.txt
8
$ # add -o to get total count of matches (differs from GNU grep)
$ # can also use --count-matches option instead of -co
$ rg -co 'in' programming_quotes.txt
13
Context matching
Use -A and -B to display lines after and before matching lines.


$ # assumes 'context_matching' as CWD
$ # show lines containing 'blue' and two lines after such lines
$ # for multiple matches, -- is added between the results
$ # prefix is : for matching lines and - for relative lines
$ rg -A2 'blue' context.txt
5:blue
6-    toy
7-    flower
--
9:light blue
10-    flower
11-    sky

$ # show lines containing 'bread' and two lines before such lines
$ rg -B2 'bread' context.txt
1-wheat
2-    roti
3:    bread
Use -C to display lines around the matching ones.


$ # same as: rg -A1 -B1 'sky' context.txt
$ rg -C1 'sky' context.txt
10-    flower
11:    sky
12-    water
--
15-    blood
16:    evening sky
17-    rose

$ rg -A1 -B2 'sky' context.txt
9-light blue
10-    flower
11:    sky
12-    water
--
14-    ruby
15-    blood
16:    evening sky
17-    rose
The separator -- won't be added if two or more groups of matching lines have overlapping lines or are next to each other in input file.


$ # the two groups are next to each other here
$ rg -C1 'flower' context.txt
6-    toy
7:    flower
8-    sand stone
9-light blue
10:    flower
11-    sky

$ # example for overlapping case
$ # last line of 1st group overlaps with matching line of 2nd group
$ rg -A4 'blue' context.txt
5:blue
6-    toy
7-    flower
8-    sand stone
9:light blue
10-    flower
11-    sky
12-    water
13-dark red
Use --context-separator to change the default separator -- to something else. You can also use escape sequences like \t, \n, etc as part of the separator.


$ seq 29 | rg --context-separator='*****' -A1 '3'
3
4
*****
13
14
*****
23
24
You cannot use --context-separator='' to display only the matches without any separator as a newline is always added in addition to the given string. Use --no-context-separator for such cases.


$ seq 29 | rg --no-context-separator -A1 '3'
3
4
13
14
23
24
Scripting options
While writing scripts, sometimes you just need to know if a file contains the pattern and act based on exit status of the command. Instead of usual workarounds like redirecting output to /dev/null you can use the -q option. This will avoid printing anything on stdout and also provides speed benefit as rg would stop processing as soon as the given condition is satisfied.


$ # assumes 'miscellaneous' as CWD
$ rg -q 'the the' find.md
$ echo $?
0
$ rg -q 'xyz' find.md
$ echo $?
1

$ rg -q 'the the' find.md && echo 'Repeated word found!'
Repeated word found!
The --no-messages option will suppress error messages that are intended for stderr.


$ # when file doesn't exist
$ rg 'in' xyz.txt
xyz.txt: No such file or directory (os error 2)
$ rg --no-messages 'in' xyz.txt
$ echo $?
2

$ # when sufficient permission is not available
$ rg 'rose' foo.txt
foo.txt: Permission denied (os error 13)
$ rg --no-messages 'rose' foo.txt
$ echo $?
2
Errors regarding regular expressions and invalid options will be on stderr even when the --no-messages option is used.


$ rg --no-messages 'a(' find.md
regex parse error:
    a(
     ^
error: unclosed group

$ rg --no-messages 'a(' find.md 2> /dev/null
$ echo $?
2
Byte offset

$ # zero-based offset for starting line of each match
$ # if line number prefix is also active, it will be before byte offset
$ rg -Nb 'is' find.md
0:The find command is more versatile than recursive options and
125:has provisions to match based on the the file characteristics

$ # offset for start of matching portion instead of line
$ rg -Nob 'is' find.md
17:is
133:is
180:is
Rust Regex
This section will cover regular expressions syntax and features of Rust regex crate — the engine that powers the default regex offered by rg. From the docs:

Its syntax is similar to Perl-style regular expressions, but lacks a few features like look around and backreferences. In exchange, all searches execute in linear time with respect to the size of the regular expression and search text.

By default, rg treats the search pattern as a regex

-F option will cause the search patterns to be treated literally
-P option will enable Perl Compatible Regular Expression 2 (PCRE2) instead of Rust regex
--engine=auto option will dynamically use PCRE2 if needed
Content for this section is adapted from BRE/ERE Regular Expressions and Perl Compatible Regular Expressions chapters, with reduced description and examples.

info rg allows to replace matching portions as well (sed 's/search/replace/g' will be similar to rg -N --passthru 'search' -r 'replace') for both Rust regex and PCRE2 (substitution is the major feature-wise difference compared to PCRE).

Line Anchors

$ # lines starting with 'pa'
$ printf 'spared no one\npar\nspar\ndare' | rg '^pa'
par

$ # lines ending with 'ar'
$ printf 'spared no one\npar\nspar\ndare' | rg 'ar$'
par
spar

$ # lines containing only 'par', same as: rg -x 'par'
$ printf 'spared no one\npar\nspar\ndare' | rg '^par$'
par
Word Anchors
A word character is any alphabet (irrespective of case), digit and the underscore character. The regex engine implementation is Unicode by default, but consider examples and descriptions as intended for ASCII characters unless otherwise specified.

warning Word boundaries behave a bit differently than -w option. See Word boundary differences section for details.


$ # assumes 'bre_ere' as CWD
$ # match words starting with 'par'
$ rg '\bpar' word_anchors.txt
1:sub par
5:cart part tart mart

$ # match words ending with 'par'
$ rg 'par\b' word_anchors.txt
1:sub par
2:spar

$ # match only whole word 'par', same as: rg -w 'par'
$ rg '\bpar\b' word_anchors.txt
1:sub par
The word boundary has an opposite anchor too. \B matches wherever \b doesn't match. This duality will be seen with some other escape sequences too.


$ # replace 'par' with 'PAR' if it is surrounded by word characters
$ rg '\Bpar\B' -r 'PAR' word_anchors.txt
3:apPARent effort
4:two sPARe computers

$ # match 'par' but not as start of word
$ rg '\Bpar' word_anchors.txt
2:spar
3:apparent effort
4:two spare computers

$ # match 'par' but not as end of word
$ rg 'par\B' word_anchors.txt
3:apparent effort
4:two spare computers
5:cart part tart mart

$ printf 'copper' | rg '\b' -r ':'
:copper:
$ printf 'copper' | rg '\B' -r ':'
c:o:p:p:e:r
String anchors
\A restricts the match to start of string and \z restricts the match to end of string. This makes a difference if you are working with input data containing more than one line (based on newline character).


$ # -U enables multiline matching
$ # regex multiline modifier m (covered later) is also enabled by default
$ # note that output will contain only matching line(s), not entire input
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U '\Ahi'
hi-hello;top
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U '\Afoo'
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U '^foo'
foo-spot

$ # note that you need to mention \n (if present) for \z
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U 'pot\n\z'
foo-spot
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U 'pot$'
foo-spot
$ printf 'hi-hello;top\nfoo-spot\n' | rg -U 'top$'
hi-hello;top
info See my blog post Multiline fixed string search and replace with cli tools for more examples with -U option.

Alternation
Alternation is similar to using multiple -e option, but provides more flexibility when combined with grouping.


$ # match either 'cat' or 'dog', same as: rg -e 'cat' -e 'dog'
$ printf 'I like cats\nI like parrots\nI like dogs' | rg 'cat|dog'
I like cats
I like dogs

$ # match either 'cat' or 'dog' or 'fox' case insensitively
$ echo 'CATs dog bee parrot FoX' | rg -io 'cat|dog|fox'
CAT
dog
FoX
$ echo 'CATs dog bee parrot FoX' | rg -i 'cat|dog|fox' -r 'mammal'
mammals mammal bee parrot mammal

$ # match lines starting with 'a' or a line containing a word ending with 'e'
$ rg '^a|e\b' word_anchors.txt
3:apparent effort
4:two spare computers
A cool use case of alternation is combining line anchors to display entire input file but highlight only required search patterns. This effect can also be achieved using --passthru option instead of using standalone anchors as part of alternation.

rg highlighting patterns in whole input

There's some tricky situations when using alternation. If it is used to get matching line, there is no ambiguity. However, for matching portion extraction with -o option, it depends on a few factors. Say, you want to get either are or spared — which one should get precedence? The bigger word spared or the substring are inside it or based on something else?


$ # alternative which matches earliest in the input gets precedence
$ # left to right precedence if alternatives match on same index
$ printf 'spared PARTY PaReNt' | rg -io 'par|pare|spare'
spare
PAR
PaR
$ # workaround is to sort alternations based on length, longest first
$ printf 'spared PARTY PaReNt' | rg -io 'spare|pare|par'
spare
PAR
PaRe

$ echo 'best years' | rg 'year|years' -r 'X'
best Xs
$ echo 'best years' | rg 'years|year' -r 'X'
best X
Grouping
Similar to a(b+c)d = abd+acd in maths, you get a(b|c)d = abd|acd in regular expressions.


$ # same as: rg 'reform|rest'
$ printf 'red\nreform\nread\narrest' | rg 're(form|st)'
reform
arrest

$ # same as: '\bpar\b|\bpart\b'
$ # you'll later learn a better technique using quantifiers
$ printf 'sub par\nspare\npart time' | rg '\b(par|part)\b'
sub par
part time
Escaping metacharacters
You have seen a few metacharacters and escape sequences that help to compose a regular expression. To match the metacharacters literally, i.e. to remove their special meaning, prefix those characters with a \ character. To indicate a literal \ character, use \\. If there are many metacharacters to be escaped, try to work out if the command can be simplified by using -F (paired with options such as -e, -f, -i, -w, -x, etc).


$ # same as: rg -F 'b^2'
$ echo 'a^2 + b^2 - C*3' | rg 'b\^2'
a^2 + b^2 - C*3

$ # cannot use -F here as line anchor is needed
$ printf '(a/b) + c\n3 + (a/b) - c' | rg '^\(a/b\)'
(a/b) + c
The dot meta character
The dot metacharacter serves as a placeholder to match any character except newline.


# extract 'c', followed by any character and then 't'
$ echo 'tac tin cot abc:tuv excite' | rg -o 'c.t'
c t
cot
c:t
cit

# '2', followed by any character and then '3'
$ printf '42\t33\n' | rg '2.3' -r '8'
483

$ # 5 character lines starting with 'c' and ending with 'ty' or 'ly'
$ rg -Nx 'c..(t|l)y' words.txt
catty
coyly
curly
Greedy Quantifiers
The ? metacharacter quantifies a character or group to match 0 or 1 times.


$ # same as: rg '\b(par|part)\b' or rg -w 'par|part'
$ printf 'sub par\nspare\npart time' | rg -w 'part?'
sub par
part time

$ # same as: rg 'part|parrot' -r 'X'
$ echo 'par part parrot parent' | rg 'par(ro)?t' -r 'X'
par X X parent
$ # same as: rg -o 'part|parrot|parent'
$ echo 'par part parrot parent' | rg -o 'par(en|ro)?t'
part
parrot
parent
The * metacharacter quantifies a character or group to match 0 or more times.


$ # extract 'f' followed by zero or more of 'e' followed by 'd'
$ echo 'fd fed fod fe:d feeeeder' | rg -o 'fe*d'
fd
fed
feeeed
$ # replace zero or more of '1' followed by '2' with 'X'
$ echo '3111111111125111142' | rg '1*2' -r 'X'
3X511114X
The + metacharacter quantifies a character or group to match 1 or more times.


$ # extract 'f' followed by at least one of 'e' or 'o' or ':' followed by 'd'
$ echo 'fd fed fod fe:d feeeeder' | rg -o 'f(e|o|:)+d'
fed
fod
fe:d
feeeed

$ # extract one or more of '1' followed by '2'
$ echo '3111111111125111142' | rg -o '1+2'
11111111112
$ # replace one or more of '1' followed by optional '4' and then '2' with 'X'
$ echo '3111111111125111142' | rg '1+4?2' -r 'X'
3X5X
You can specify a range of integer numbers, both bounded and unbounded, using {} metacharacters. There are three ways to use this quantifier as listed below:

Pattern	Description
{m,n}	match m to n times
{m,}	match at least m times
{n}	match exactly n times

$ # note that whitespace is allowed within {} but not recommended
$ echo 'abc ac adc abbc xabbbcz bbb bc abbbbbc' | rg -o 'ab{1,4}c'
abc
abbc
abbbc

$ echo 'abc ac adc abbc xabbbcz bbb bc abbbbbc' | rg -o 'ab{3,}c'
abbbc
abbbbbc

$ echo 'abc ac adc abbc xabbbcz bbb bc abbbbbc' | rg -o 'ab{3}c'
abbbc

$ echo 'abc ac adc abbc xabbbcz bbb bc abbbbbc' | rg -o 'ab{0,2}c'
abc
ac
abbc
info The {} metacharacters have to be escaped to match them literally. However, unlike () metacharacters, escaping { alone is enough.

Next up, how to construct AND conditional using dot metacharacter and quantifiers. To allow matching in any order, you'll have to bring in alternation as well. That is somewhat manageable for 2 or 3 patterns. With PCRE2, you can use lookarounds for a comparatively easier approach.


$ # match 'Error' followed by zero or more characters followed by 'valid'
$ echo 'Error: not a valid input' | rg -o 'Error.*valid'
Error: not a valid

$ echo 'a cat and a dog' | rg 'cat.*dog|dog.*cat'
a cat and a dog
$ echo 'dog and cat' | rg 'cat.*dog|dog.*cat'
dog and cat
Why are these called greedy quantifiers? If multiple quantities can satisfy the pattern, the longest match wins.


$ # longest match among 'foo' and 'fo' wins here
$ echo 'foot' | rg 'f.?o' -r 'X'
Xt

$ # everything will match here
$ echo 'car bat cod map scat dot abacus' | rg -o '.*'
car bat cod map scat dot abacus
But wait, how did Error.*valid example work? Shouldn't .* consume all the characters after Error? Good question. Depending on the implementation of regular expression engine, longest match will be selected from all valid matches generated with varying number of characters for .* or the engine would backtrack character by character from end of string until the pattern can be satisfied or fails.


$ # extract from start of line to last 'm' in the line
$ echo 'car bat cod map scat dot abacus' | rg -o '.*m'
car bat cod m

$ # extract from first 'c' to last 't' in the line
$ echo 'car bat cod map scat dot abacus' | rg -o 'c.*t'
car bat cod map scat dot

$ # extract from first 'c' to last 'at' in the line
$ echo 'car bat cod map scat dot abacus' | rg -o 'c.*at'
car bat cod map scat
Precedence for quantifiers is left to right, even if it ends in matching less number of characters.


$ # (1|2|3)+ matches as much as possible here, which is '123312'
$ # which results in (12baz)? matching 0 times
$ echo 'foo123312baz' | rg -o 'o(1|2|3)+(12baz)?'
o123312

$ # (1|2|3)+ here matches '1233' to allow overall regex to pass
$ echo 'foo123312baz' | rg -o 'o(1|2|3)+12baz'
o123312baz
Non-greedy quantifiers
As the name implies, these quantifiers will try to match as minimally as possible. Also known as lazy or reluctant quantifiers. Appending a ? to greedy quantifiers makes them non-greedy.


$ # smallest match among 'foo' and 'fo' wins here
$ echo 'foot' | rg 'f.??o' -r 'X'
Xot
$ # overall regex has to be satisfied as minimally as possible
$ echo 'frost' | rg 'f.??o' -r 'X'
Xst

$ echo 'foo 314' | rg -o '\d{2,5}?'
31

$ echo 'that is quite a fabricated tale' | rg -o 't.*?a'
tha
t is quite a
ted ta
Character classes
To create a custom placeholder for limited set of characters, enclose them inside [] metacharacters. It is similar to using single character alternations inside a grouping, but with added flexibility and features. Character classes have their own versions of metacharacters and provide special predefined sets for common use cases. Quantifiers are also applicable to character classes.


$ # same as: rg '(a|e|o)+t'
$ printf 'meeting\ncute\nboat\nsite\nfoot' | rg '[aeo]+t'
meeting
boat
foot

$ echo 'so in to no on' | rg -w '[sot][on]' -r 'X'
X in X no X

$ # lines of length at least 2 and made up of letters 'o' and 'n'
$ rg -Nx '[on]{2,}' words.txt
no
non
noon
on
Character classes have their own metacharacters to help define the sets succinctly. First up, the - metacharacter that helps to define a range of characters instead of having to specify them all individually.


$ # same as: rg -o '[0123456789]+'
$ echo 'Sample123string42with777numbers' | rg -o '[0-9]+'
123
42
777

$ # whole words made up of lowercase alphabets and digits only
$ echo 'coat Bin food tar12 best' | rg -w '[a-z0-9]+' -r 'X'
X Bin X X X
$ # whole words made up of lowercase alphabets, starting with 'p' to 'z'
$ echo 'road i post grip read eat pit' | rg -w '[p-z][a-z]*' -r 'X'
X i X grip X eat X

$ # numbers between 10 to 29
$ echo '23 154 12 26 34' | rg -ow '[12][0-9]'
23
12
26
$ # numbers >= 100 with optional leading zeros
$ echo '0501 035 154 12 26 98234' | rg -ow '0*[1-9][0-9]{2,}'
0501
154
98234
Next metacharacter is ^ which has to specified as the first character of the character class. It negates the set of characters, so all characters other than those specified will be matched.


$ # replace all non-digits
$ echo 'Sample123string42with777numbers' | rg '[^0-9]+' -r 'X'
X123X42X777X

$ # extract last two columns based on a delimiter
$ echo 'foo:123:bar:baz' | rg -o '(:[^:]+){2}$'
:bar:baz

$ # get all sequence of characters surrounded by unique character
$ echo 'I like "mango" and "guava"' | rg -o '"[^"]+"'
"mango"
"guava"

$ # use -v option if it is simpler than negated set: rg -x '[^aeiou]*'
$ printf 'tryst\nfun\nglyph\npity\nwhy' | rg -v '[aeiou]'
tryst
glyph
why
Some commonly used character sets have predefined escape sequences:

\d matches all digit characters [0-9]
\D matches all non-digit characters
\w matches all word characters [a-zA-Z0-9_]
\W matches all non-word characters
\s matches all whitespace characters: tab, newline, vertical tab, form feed, carriage return and space
\S matches all non-whitespace characters

$ echo 'Sample123string42with777numbers' | rg '\d+' -r ':'
Sample:string:with:numbers
$ echo 'Sample123string42with777numbers' | rg '\D+' -r ':'
:123:42:777:

$ printf 'lo2ad.;.err_msg--\nant,;.' | rg -o '\w+'
lo2ad
err_msg
ant

$ echo 'tea sea-pit sit-lean bean' | rg -o '[\w\s]+'
tea sea
pit sit
lean bean
A named character set is defined by a name enclosed between [: and :] and has to be used within a character class [], along with any other characters as needed. Using [:^ instead of [: will negate the named character set. See BRE/ERE Character classes section for full list.


$ # all alphabets and digits
$ printf 'errMsg\nant2\nm_2\n' | rg -x '[[:alnum:]]+'
errMsg
ant2

$ # other than punctuation characters
$ echo 'pie tie#ink-eat_42;' | rg -o '[[:^punct:]]+'
pie tie
ink
eat
42
Set operations can be applied inside character class between sets. Mostly used to get intersection or difference between two sets, where one/both of them is a character range or predefined character set. To aid in such definitions, you can use [] in nested fashion.


$ # intersection of lowercase alphabets and other than vowel characters
$ # can also use set difference: rg -ow '[a-z--aeiou]+'
$ echo 'tryst glyph pity why' | rg -ow '[a-z&&[^aeiou]]+'
tryst
glyph
why

$ # symmetric difference, [[a-l]~~[g-z]] is same as [a-fm-z]
$ echo 'gets eat top sigh' | rg -ow '[[a-l]~~[g-z]]+'
eat
top

$ # remove all punctuation characters except . ! and ?
$ para='"Hi", there! How *are* you? All fine here.'
$ echo "$para" | rg '[[:punct:]--[.!?]]+' -r ''
Hi there! How are you? All fine here.
Character class metacharacters can be matched literally by specific placement or using \ to escape them.


$ # - should be first or last character within []
$ echo 'ab-cd gh-c 12-423' | rg -ow '[a-z-]{2,}'
ab-cd
gh-c

$ # ] should be first character within []
$ printf 'int a[5]\nfoo\n1+1=2\n' | rg '[]=]'
int a[5]
1+1=2
$ # [ has to be escaped with \
$ echo 'int a[5]' | rg '[x\[.y]'
int a[5]

$ # ^ should be other than first character within []
$ echo 'f*(a^b) - 3*(a+b)/(a-b)' | rg -o 'a[+^]b'
a^b
a+b
Backreferences
The grouping metacharacters () are also known as capture groups. Similar to variables in programming languages, the string captured by () can be referred later using backreference $N where N is the capture group you want. Leftmost ( in the regular expression is $1, next one is $2 and so on. By default, $0 will give entire matched portion. Use ${N} to avoid ambiguity between backreference and other characters.


# remove square brackets that surround digit characters
$ echo '[52] apples [and] [31] mangoes' | rg '\[(\d+)]' -r '$1'
52 apples [and] 31 mangoes

# add something around the matched strings
$ echo '52 apples and 31 mangoes' | rg '\d+' -r '(${0}4)'
(524) apples and (314) mangoes

# replace __ with _ and delete _ if it is alone
$ echo '_foo_ __123__ _baz_' | rg '(_)?_' -r '$1'
foo _123_ baz

# swap words that are separated by a comma
$ echo 'good,bad 42,24' | rg '(\w+),(\w+)' -r '$2,$1'
bad,good 24,42
You can use a non-capturing group to avoid keeping a track of groups not needed for backreferencing. The syntax is (?:pattern) to define a non-capturing group.


$ # with normal grouping, need to keep track of all the groups
$ echo '1,2,3,4,5,6,7' | rg '^(([^,]+,){3})([^,]+)' -r '$1($3)'
1,2,3,(4),5,6,7

$ # using non-capturing groups, only relevant groups have to be tracked
$ echo '1,2,3,4,5,6,7' | rg '^((?:[^,]+,){3})([^,]+)' -r '$1($2)'
1,2,3,(4),5,6,7
Regular expressions can get cryptic and difficult to maintain, even for seasoned programmers. There are a few constructs to help add clarity. One such is named capture groups and using that name for backreferencing instead of plain numbers.


$ echo 'a,b 42,24' | rg '(?P<fw>\w+),(?P<sw>\w+)' -r '$sw,$fw'
b,a 24,42

$ row='today,2008-24-03,food,2012-12-08,nice,5632'
$ echo "$row" | rg '(?P<dd>-\d{2})(?P<mm>-\d{2})' -r '$mm$dd'
today,2008-03-24,food,2012-08-12,nice,5632
Using backreference along with -o and -r options will allow to extract matches that should also satisfy some surrounding conditions. This is a workaround for some of the cases where lookarounds are needed.


$ # extract digits that follow =
$ echo 'foo=42, bar=314, baz:512' | rg -o '=(\d+)' -r '$1'
42
314

$ # extract digits only if it is preceded by - and followed by ; or :
$ echo '42 foo-5, baz3; x-83, y-20: f12' | rg -o '\-(\d+)[:;]' -r '$1'
20

$ # extract 3rd occurrence of 'cat' followed by optional lowercase letters
$ s='scatter cat cater scat concatenate abdicate'
$ echo "$s" | rg -o '^(?:.*?cat.*?){2}(cat[a-z]*)' -r '$1'
cater
As $ is special in replacement section, you'll need $$ to represent it literally.


$ echo 'a b a' | rg 'a' -r '$${a}'
${a} b ${a}
Modifiers
Modifiers are like command line options to change the default behavior of the pattern. The -i option is an example for modifier. However, unlike -i, these modifiers can be applied selectively to portions of a pattern. In regular expression parlance, modifiers are also known as flags.

Modifier	Description
i	case sensitivity
m	multiline for line anchors
s	matching newline with . metacharacter
x	readable pattern with whitespace and comments
u	unicode
To apply modifiers to selectively, specify them inside a special grouping syntax. This will override the modifiers applied to entire pattern, if any. The syntax variations are:

(?modifiers:pattern) will apply modifiers only for this portion
(?-modifiers:pattern) will negate modifiers only for this portion
(?modifiers-modifiers:pattern) will apply and negate particular modifiers only for this portion
(?modifiers) when pattern is not given, modifiers (including negation) will be applied from this point onwards

$ # same as: rg -i 'cat' -r 'X'
$ echo 'Cat cOnCaT scatter cut' | rg '(?i)cat' -r 'X'
X cOnX sXter cut
$ # override -i option
$ printf 'Cat\ncOnCaT\nscatter\ncut' | rg -i '(?-i)cat'
scatter
$ # same as: rg -i '(?-i:Cat)[a-z]*\b' -r 'X' or rg 'Cat(?i)[a-z]*\b' -r 'X'
$ echo 'Cat SCatTeR CATER cAts' | rg 'Cat(?i:[a-z]*)\b' -r 'X'
X SX CATER cAts

$ # allow . metacharacter to match newline character as well
$ printf 'Hi there\nHave a Nice Day' | rg -U '(?s)the.*ice' -r ''
Hi  Day

$ # multiple modifiers can be used together
$ printf 'Hi there\nHave a Nice Day' | rg -Uo '(?is)the.*day'
there
Have a Nice Day

$ # assumes 'pcre' as CWD
$ # whole word 'python3' in 1st line and a line starting with 'import'
$ # note the use of string anchor and that m modifier is enabled by default
$ rg -Ul '\A.*\bpython3\b(?s).*^import'
script
$ # no output if m is disabled
$ rg -Ul '(?-m)\A.*\bpython3\b(?s).*^import'
The x modifier allows to use literal unescaped whitespaces for readability purposes and add comments after unescaped # character. This modifier has limited usage for cli applications as multiline pattern cannot be specified.


$ echo 'fox,cat,dog,parrot' | rg -o '(?x) ( ,[^,]+ ){2}$ #last 2 columns'
,dog,parrot

$ # need to escape whitespaces or use them inside [] to match literally
$ echo 'a cat and a dog' | rg '(?x)t a'
$ echo 'a cat and a dog' | rg '(?x)t\ a'
a cat and a dog
$ echo 'foo a#b 123' | rg -o '(?x)a#.'
a
$ echo 'foo a#b 123' | rg -o '(?x)a\#.'
a#b
Unicode
Similar to named character classes and escape sequences, the \p{} construct offers various predefined sets to work with Unicode strings. See regular-expressions: Unicode for details. See also -E option regarding other encoding support.


$ # all consecutive letters
$ # note that {} is not necessary here as L is single character
$ echo 'fox:αλεπού,eagle:αετός' | rg '\p{L}+' -r '($0)'
(fox):(αλεπού),(eagle):(αετός)

$ # extract all consecutive Greek letters
$ echo 'fox:αλεπού,eagle:αετός' | rg -o '\p{Greek}+'
αλεπού
αετός

$ # \d, \w, etc are unicode aware
$ echo 'φοο12,βτ_4,foo' | rg '\w+' -r '[$0]'
[φοο12],[βτ_4],[foo]
$ # can be changed by using u modifier
$ echo 'φοο12,βτ_4,foo' | rg '(?-u)\w+' -r '[$0]'
φοο[12],βτ[_4],[foo]

$ # extract all characters other than letters, \PL can also be used
$ echo 'φοο12,βτ_4,foo' | rg -o '\P{L}+'
12,
_4,
Characters can be specified using hexadecimal \x{} codepoints as well.


$ # {} are optional if only two hex characters are needed
$ echo 'a cat and a dog' | rg 't\x20a'
a cat and a dog

$ echo 'fox:αλεπού,eagle:αετός' | rg -o '[\x61-\x7a]+'
fox
eagle

$ echo 'fox:αλεπού,eagle:αετός' | rg -o '[\x{3b1}-\x{3bb}]+'
αλε
αε
PCRE2
Use -P option to enable Perl Compatible Regular Expressions 2 (PCRE2) instead of default Rust regex. PCRE2 is mostly similar, but not exactly same as regular expressions present in Perl programming language. The main feature difference between PCRE and PCRE2 is substitution. Most of the features covered in Perl Compatible Regular Expressions chapter will work exactly the same with rg -P as well. There could be differences with regards to how certain things are handled between GNU grep and ripgrep — for example, -f and -e options, empty matches, etc.


$ # empty match handling
$ echo '1a42z' | grep -oP '[a-z]*'
a
z
$ echo '1a42z' | rg -oP '[a-z]*'

a

z

$ # assumes 'pcre' as CWD
$ printf 'sub\nbit' | grep -P -f- five_words.txt
grep: the -P option only supports a single pattern
$ printf 'sub\nbit' | rg -P -f- five_words.txt
2:subtle
4:exhibit
This section will only show a few examples. For complete documentation and other information, see pcre: current doc.


$ # lookarounds is major feature not present in Rust regex
$ rg -P '(?=.*a)(?=.*e)(?=.*i)(?=.*o).*u' five_words.txt
1:sequoia
3:questionable
5:equation
$ echo 'hey food! foo42 foot5 foofoo' | rg -P 'foo(?!\d)' -r 'X'
hey Xd! foo42 Xt5 XX
$ # same as: rg -o '^(?:.*?cat.*?){2}(cat[a-z]*)' -r '$1'
$ s='scatter cat cater scat concatenate abdicate'
$ echo "$s" | rg -oP '^(.*?cat.*?){2}\Kcat[a-z]*'
cater
$ # match if 'go' is not there between 'at' and 'par'
$ echo 'fox,cat,dog,parrot' | rg -qP 'at((?!go).)*par' && echo 'Match'
Match

$ # backreference within regex definition
$ # remove any number of consecutive duplicate words separated by space
$ echo 'aa a a a 42 f_1 f_1 f_13.14' | rg -P '\b(\w+)( \1)+\b' -r '$1'
aa a 42 f_1 f_13.14

$ # mixing regex and literal matching
$ expr='(a^b)'
$ echo 'f*(2-a/b) - 3*(a^b)-42' | rg -oP '\S*\Q'"$expr"'\E\S*'
3*(a^b)-42
If you wish to use Rust regex normally and switch to PCRE2 when needed, use the --engine=auto option.


$ # using a feature not present normally
$ echo 'car bat cod map' | rg -o '\b(bat|map)\b(*SKIP)(*F)|\w+'
regex parse error:
    \b(bat|map)\b(*SKIP)(*F)|\w+
                  ^
error: repetition operator missing expression

$ # automatically switch to PCRE2
$ echo 'car bat cod map' | rg -o --engine=auto '\b(bat|map)\b(*SKIP)(*F)|\w+'
car
cod
info See my blog post Search and replace tricks with ripgrep for more examples.

Recursive options
This section reuses recursive_matching directory that was created in an earlier chapter. To avoid any issues, you can delete the existing directory and recreate it again using the following commands.


$ # assumes 'example_files' as CWD
$ # create directory for this section and cd into it
$ mkdir recursive_matching && cd $_

$ # create some files
$ printf 'hide\nobscure\nconceal\ncover\nblot\nshield' > patterns.txt
$ grep -Ff patterns.txt ../bre_ere/words.txt > .hidden
$ grep -E '([as]([b-g]|po)[r-t]){2}' ../bre_ere/words.txt > nested_group.txt
$ echo 'how are you?' > normal.txt
$ echo 'how dare you!' > 'filename with spaces.txt'

$ # create sub-directory, two scripts and another hidden file
$ mkdir scripts
$ echo 'yrneaolrknzcyr 86960' > scripts/.key
$ echo "tr 'a-z0-9' 'n-za-m5-90-4' < .key" > scripts/decode.sh
$ printf "import math\n\nprint(math.pi)\n" > scripts/pi.py

$ # create link to a directory
$ ln -s ../context_matching/

$ tree -al
.
├── context_matching -> ../context_matching/
│   └── context.txt
├── filename with spaces.txt
├── .hidden
├── nested_group.txt
├── normal.txt
├── patterns.txt
└── scripts
    ├── decode.sh
    ├── .key
    └── pi.py

2 directories, 9 files
This section will cover the feature most attractive for users — the default recursive behavior and options to customize it. For beginners to recursive search using rg, the --files option to get list of files being searched can be useful. The --debug and --trace options could be used for further analysis, especially to know why a file is ignored. The --files option is also handy if you want to use features of rg in pruning filenames for further processing instead of glob match, find command, etc.


$ # assumes 'recursive_matching' as CWD
$ rg --files
patterns.txt
scripts/pi.py
scripts/decode.sh
nested_group.txt
normal.txt
filename with spaces.txt
As seen from the example above, some of the files seem missing. That is because rg performs recursive search with certain pre-set conditions:

ignore files and directories that match rules specified by ignore files like .gitignore
ignore hidden files and directories
ignore binary files (files containing ASCII NUL character) — but displays the match if found before encountering NUL character along with a warning
ignore symbolic links (same as grep -r)
Here's an example to show .gitignore in action. The presence of .git directory (either in current directory or in parent directories) would mark .gitignore to be used for ignoring. Recently, --no-require-git flag was added to avoid the need for empty .git directory. For illustration purposes, empty .git would be created here instead of using an actual git project. In addition to .gitignore, the rg command also uses filenames like .ignore and .rgignore for determining files to ignore. For complete details and various ignore options, refer to manual as well as ripgrep: user guide.

info See stackoverflow: .gitignore pattern format to learn about the various rules.


$ mkdir .git
$ echo 'patterns.txt' > .gitignore
$ rg -wl 'obscure|are'
normal.txt

$ # --no-ignore option will disable pruning based on ignore files
$ rg --no-ignore -wl 'obscure|are'
patterns.txt
normal.txt
Use the --hidden option to search hidden files and directories as well.


$ # create normal file in a hidden directory
$ cp patterns.txt .git/pat.txt
$ # no output, and patterns.txt isn't matched because of .gitignore
$ rg -l 'obscure|ne'

$ rg --hidden -l 'obscure|ne'
scripts/.key
.git/pat.txt
.hidden
As a shortcut, you can use

-u to indicate --no-ignore
-uu to indicate --no-ignore --hidden
-uuu to indicate --no-ignore --hidden --binary
Use -L option to follow symbolic links.


$ rg 'red'
$ rg -Ll 'red'
context_matching/context.txt
The -t option provides a handy way to search files based on their extension. Use rg --type-list to see all available types and their glob patterns. Use -T to invert the selection.


$ rg --type-list | rg 'markdown'
markdown: *.markdown, *.md, *.mdown, *.mkdn
md: *.markdown, *.md, *.mdown, *.mkdn

$ # use rg --type-list | rg '^sh:' to see glob pattern for 'sh'
$ rg -t=py -t=sh --files
scripts/pi.py
scripts/decode.sh

$ # note that .gitignore is active
$ rg -t=txt --files
nested_group.txt
normal.txt
filename with spaces.txt

$ rg -T=txt --files
scripts/pi.py
scripts/decode.sh
Use -g option to search only files matching the given glob pattern. Prefix ! to exclude the matches. If / is not used, the glob will be matched against basename of all the files found recursively.


$ rg -g='*.{sh,py}' --files
scripts/pi.py
scripts/decode.sh

$ rg -g='*gr*' --files
nested_group.txt

$ # exclude filenames ending with py
$ rg -g='!*.py' --files
scripts/decode.sh
nested_group.txt
normal.txt
filename with spaces.txt
$ # exclude scripts directory
$ rg -g='!scripts' --files
nested_group.txt
normal.txt
filename with spaces.txt
You can use ** while constructing the glob pattern as a placeholder for zero or more levels of directories. See git documentation: gitignore pattern format for more details.


$ # create files/directories
$ mkdir double_star && cd $_
$ mkdir -p one/two/{x,y,z}/four
$ touch one/1.txt one/two/y/why.txt one/two/x/ex.txt one/two/y/four/4.txt

$ # all files
$ rg --files
one/1.txt
one/two/x/ex.txt
one/two/y/four/4.txt
one/two/y/why.txt

$ # file paths starting with 'one/two/'
$ rg -g='one/two/**' --files
one/two/x/ex.txt
one/two/y/four/4.txt
one/two/y/why.txt

$ # file paths having the directory 'y' anywhere in the path
$ rg -g='**/y/**' --files
one/two/y/four/4.txt
one/two/y/why.txt

$ # clean up temporary directory
$ cd .. && rm -r double_star
info There are many more options to customize the search experience (for ex: defining your own type using --type-add option, --max-depth to control depth of traversal, etc). See ripgrep user guide: configuration for examples and details on how to maintain them in a file.

Speed comparison
See Parallel execution section for sample directory used for comparison shown below.


$ # assumes 'linux-4.19' as CWD
$ # note that my machine has two cores with two threads per core
$ # rg automatically makes the best use of available resources
$ # GNU grep would need external tools like parallel to do so

$ time grep -rw 'user' > ../f1
real    0m0.815s
$ time rg -uuu -w 'user' > ../f2
real    0m0.248s

$ diff -sq <(sort ../f1) <(sort ../f2)
Files /dev/fd/63 and /dev/fd/62 are identical
Lot of factors like file size, file encoding, line size, sparse or dense matches, hardware features, etc will affect performance. rg has options like -j, --dfa-size-limit and --mmap to tweak performance for some cases.

info See Benchmark with other grep implementations by the author of ripgrep command for a methodological detailed analysis and insights.

info See Speed comparison section from an earlier version of this book for some more examples. It also compares features like PCRE, rg -r vs GNU sed, etc.

ripgrep-all
From GitHub repo:

rga is a line-oriented search tool that allows you to look for a regex in a multitude of file types. rga wraps the awesome ripgrep and enables it to search in pdf, docx, sqlite, jpg, movie subtitles (mkv, mp4), etc.

The main usp is pairing file types and relevant tools to enable text searching. rga also has a handy caching feature that speeds up the search for subsequent usages on the same input.

Summary
ripgrep is an excellent alternative to GNU grep. If you are working with large code bases, I'd definitely recommend ripgrep for its performance and customization options. Recently, the author added github: discussions to the repository, which is very handy too. There are interesting features in the pipeline, for example ngram indexing support.

Exercises
Would be a good idea to first redo all the exercises using rg from all the previous chapters. Some exercises will require reading the manual, as those options aren't covered in the chapter.

a) Go through the manual and find an option that will change the line separator from \n to \r\n. See Frequently used options: Exercises section for details about the input file used here.


$ # assumes 'exercises/freq_options' as CWD

$ # no output
$ rg -cx '' dracula.txt

$ rg ##### add your solution here
2559
b) Commands like sed and perl require special care if you need to search and replace a text literally. rg provides an easier alternative, which can be seen with these exercises.


$ # replace [4]* with 2
$ printf '2.3/[4]*6\nfoo\n5.3-[4]*9\n' | rg ##### add your solution here
2.3/26
foo
5.3-29

$ # replace '3$a with &
$ printf "a'3\$a\nb'3\$a6\nc\n" | rg ##### add your solution here
a&
b&6
c
c) Create exercises/ripgrep directory and then save this file from learn_gnugrep_ripgrep repo as sample.md. For this input file, match all lines containing ruby irrespective of case, but not if it is part of code blocks that are bounded by triple backticks.


$ # assumes 'exercises' as CWD
$ mkdir ripgrep && cd $_

$ rg ##### add your solution here
3:REPL is a good way to learn RUBY for beginners.
16:ruby comes loaded with awesome methods. Enjoy learning RuBy.
d) Sum all integer numbers (floating-point numbers should be ignored) if the file also contains the string is


$ # assumes 'exercises/ripgrep' as CWD
$ # which already has one file named 'sample.md'

$ # create two more files with these commands
$ echo 'hi,31,3.14,bye' > 'space in filename.txt'
$ echo 'This is 2 good' > $'weird \n symbols'

$ # all three files should be considered as input
$ # use awk '{s+=$1} END{print s}' if datamash is not available
$ rg ##### add your solution here | datamash sum 1
61
e) Default behavior changes depending upon output is intended for terminal or not. Use appropriate option(s) to get the output as shown below. Search for good way or bye in all the files in the given directory and save the output in out.txt file.


$ # assumes 'exercises/ripgrep' as CWD

$ rg ##### add your solution here
$ cat out.txt
space in filename.txt
1:hi,31,3.14,bye

sample.md
3:REPL is a good way to learn RUBY for beginners.
f) Which option will show both line number and 1-based byte offset of first matching portion for matching lines?


$ # assumes 'exercises/ripgrep' as CWD

$ # normal output
$ rg 'good' sample.md
3:REPL is a good way to learn RUBY for beginners.

$ # expected output
$ rg ##### add your solution here
3:11:REPL is a good way to learn RUBY for beginners.
g) By default, ripgrep uses \n as the line separator. Use appropriate option to change the separator to NUL and display all lines containing red for the given input.


$ printf 'dark red\nteal\n\0brown\n\0spared' | rg ##### add your solution here
dark red
teal
spared
h) Use appropriate options to replace all NUL characters with --- and a newline character as shown below.


$ printf 'dark red\nteal\n\0brown\n\0spared' | rg ##### add your solution here
dark red
teal
---
brown
---
spared
