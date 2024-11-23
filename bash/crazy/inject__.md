##
#
https://yossarian.net/til/post/some-surprising-code-execution-sources-in-bash/
#
##


Some surprising code execution sources in bash
2024-11-15
security shell
I ran across two surprising sources of code execution in bash (and probably other shells) recently.

In a historic context these probably weren't too serious of a problem, but in the context of CI systems where everything is a rats' nest of shell and YAML they could be useful execution primitives.

Edit 2024-11-22: the Bash Pitfalls page in the Wooledge Bash Guide contains examples of these, among other sources of surprising evaluations.

Source 1: arithmetic expressions (a.k.a. "white-collar eval")
Leading question aside, do you think this snippet of bash1 can run arbitrary code?
```
function guess() {
  num="${1}"
  if [[ "${num}" -eq 42 ]]
  then
    echo "Correct"
  else
    echo "Wrong"
  fi
}
```
Most people (including experienced shell programmers2) say "no": they recognize that there could have been a splatting bug if it was $num instead of "${num}", but the double quoting should firmly prevent any evaluation of the num variable itself.

But nope: because of -eq, num is treated with bash's arithmetic evaluation rules, meaning that this works:
```
$ guess 'a[$(cat /etc/passwd > /tmp/pwned)] + 42'
Correct
$ cat /tmp/pwned
```
Note the single quotes: $(cat /etc/passwd > ~/pwned) is not executed eagerly as a parameter to guess, but as part of the evaluation of -eq within [[.

Unlike the case below, this doesn't appear to work with [ or test.

Source 2: test -v
The same surprising code execution source exists with test -v var, under the same conditions as arithmetic expressions (needs to use the builtin, not the standard binary):
```
$ [[ -v 'x[$(cat /etc/passwd > /tmp/pwned)]' ]]
$ cat /tmp/pwned
```
This also works with [ and test, so long as their builtin variants are used instead of their external binary variants. /usr/bin/[ and /usr/bin/test will of course not work, since they have no access to the context of the shell that spawned them.

I'm not 100% sure why this is the case, since -v var is documented as testing whether var is set and it shouldn't be necessary to evaluate a subscript to determine that.

Edit 2024-11-22: Multiple people have pointed out that -v var[...] checks for the subscript's presence, hence the "need" to evaluate expressions. This is not well documented anywhere, as far as I can tell.

Minimized and tweaked from Vidar Holen's blog, where I learned about this! ↩

I polled my coworkers: of 17 respondents, 16 through this snippet was fine and 1 thought it contained a potential vulnerability. ↩
