

Hi, I recently found a .git folder exposed on a public bug bounty program and used it to reconstruct the Web app’s source code. I can’t disclose specific details yet, but wanted to share with you this tutorial on how to find and exploit this kind of bugs.

.git exposure can pay well or not, depending on the assets found. But it is interesting anyway because:

    It is very easy to detect
    Analyzing the source code can reveal other vulnerabilities that are even more critical and interesting

The process is the same whether you have a list of targets during a penetration test, or a broad scope (like *.example.com) when bug hunting.
If the scope is limited to a set of Web applications, skip to step2. Otherwise, use recon to make a list of Web apps:
Make a list of Web apps

Start with enumerating domains. Jason Haddix’s bug hunters methodology is a very good start.

Check acquisitions in particular. Let’s say the program’s acquisition rules say that acquisitions are in scope only after 6 months. Then if you test a new acquisition at month 7, you may have more chances to find bugs than on a one or two-year old acquisition. The new one is probably less tested than the main domain too.

Then enumerate subdomains using tools like Amass, Sublist3r or Massdns.

After that, identify web applications, by port scanning all ips found and manually browsing all HTTP/HTTPS services. Note that the same subdomain can host multiple Web applications, for example on different ports or URL paths.
Detect .git exposure using forced browsing

Once you have a solid list of Web applications, use forced browsing to see if a .git folder is accessible on them.

If file & directory bruteforce tools are allowed, you can use dirsearch or dirb (with common.txt dictionary). They both check for .git/.

But if automated tools are not allowed (happens even on pentests!), simply go to <web-app>/.git (e.g. https://example.com/.git or https://example.com/git/) on a browser.

If you get a 404 error, then .git/ doesn’t exist on the server. But if you get a 403 forbidden error, it does! The folder’s root just won’t be directly accessible if directory listing is disabled on the server:

If you’re lucky and directory listing is enabled, then you could directly browse the .git folder’s contents:

Confirm the bug by manually browsing the .git folder

If you “git clone” any Git project from Github and look at .git/ in its root you’ll notice that some file are always present: .git/config, .git/HEAD, .git/logs/HEAD, .git/index…

You can confirm that the .git folder’s contents are accessible (even if .git/ itself isn’t) by trying to open these different common file names, for example:

    https://example.com/.git/config
    https://example.com/.git/HEAD
    https://example.com/.git/logs/HEAD
    https://example.com/.git/index

Automatically extract contents of .git

This is the fun part! Browsing .git/ manually is good for proof of concept, but tedious. If you want to retrieve as many files as possible, even with directory listing disabled, the tool to use is GitTools.

It’s really good! Just 4 lines and you’ll have all or parts of the remote Git repository on your computer:

./gitdumper.sh https://example.com/.git/ /output-directory/
git status 			# Returns that the files were deleted because folders are empty
git checkout -- . 	# To restore the files & download the directory
git log				# See what other commits are there

Finally, you have to analyze the local repository manually. Try to detect other vulnerabilities using static code analysis, or credentials, authentication tokens, new endpoints, etc.

And don’t forget, if you find a vulnerable domain, to check its development and staging subdomains too. They would probably be vulnerable, even if the bug was fixed on the main domain/subdomain.
Potential impact

    Finding new vulnerabilities by analyzing the source code
    Finding files containing sensitive information like credentials, tokens, new endpoints, etc

Examples of bug bounty reports

    Git repository found on Grabtaxi Holdings Pte Ltd ($1,000)
    Git available containing passwords. on Boozt Fashion AB ($400)
    [staging-engineering.gnip.com] Publicly accessible GIT directory on Twitter ($280)
    GIT Detected on Nextcloud ($0)
    
    



thing.sh

```
.bashrc, .bash_profile, .zshrc
alias status='git status'
alias logdiff='git log -p'
alias log='git log --decorate'
alias pull='git pull'
alias push='git push'
alias commit='git commit'
alias add='git add'
alias checkout='git checkout'
alias branch='git branch'
alias stash='git stash'
alias diff='git diff'

.rvmrc
alias hack='../scripts/hack'
alias commits='../scripts/commit'
alias sink='../scripts/sink'
alias ship='../scripts/ship'

----- hack ----
#!/bin/sh -x
FEATURE=$1
CURRENT=`git branch | grep "*" | awk '{print $2}'`
USER=`git config user.login`

git checkout $CURRENT
git pull --rebase origin $CURRENT
git checkout -b $1 $CURRENT

URL="https://api.github.com/repos/rodrigomaia/sorteando/issues/${FEATURE}"
curl -v -X PATCH -H "Accept: application/json" -H "Content-type: application/json" -u "${USER}" -d "{\"assignee\":\"${USER}\"}" $URL


---- commit ----
#!/bin/sh -x
CURRENT=`git branch | grep "*" | awk '{print $2}'`
git commit -a -m "[$2 #${CURRENT}] $1"


---- sink ----
#!/bin/sh -x
CURRENT=`git branch | grep "*" | awk '{print $2}'`
BRANCH=$1
git checkout ${BRANCH}
git pull --rebase origin ${BRANCH}
git checkout ${CURRENT}
git rebase ${BRANCH} ${CURRENT}


---- ship ----
#!/bin/sh -x
CURRENT=`git branch | grep "*" | awk '{print $2}'`
BRANCH=$1
git checkout ${BRANCH}
git merge ${CURRENT} 
git commit -a -v
git push origin ${BRANCH}
```

##
##

# Git Tips

## Properly Configure your `~/.gitconfig`

- Properly configure your user information
GitHub tracks your changes by using the information provided by your `~/.gitconfig`. If you work on more than one machine and your `~/.gitconfig` is not properly configured, you will probably end up with duplicated commits and disorganized history. Here are the lines you will have to modify according to your GitHub credentials.

```
[user]
	name = Guilherme M. Trein
	email = valid@email.com
```

- Properly configure your difftool and mergetool.
The difftool and mergetool are the software Git will execute during diff or conflict resolution operations respectively.
```
[difftool "opendiff"]
	cmd = /usr/bin/opendiff \"$LOCAL\" \"$REMOTE\" -merge \"$MERGED\" | cat
[diff]
	tool = opendiff
[merge]
	tool = opendiff
```

- Create aliases for the most common used commands. You will noticed that you will end up issuing the same Git command several times a day. Creating aliases to the most common used commands can save precious minutes every day.
```
[alias]
	st = status
	ci = commit
	br = branch
	co = checkout
	ds = diff --staged
	changes = log -n1 -p --format=fuller
	amend = commit --amend -C HEAD
	undo = clean -f -d
	undoci = reset HEAD~1
	unstage = reset HEAD --
	lg = log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit
	ls = log --pretty=format:\"%C(yellow)%h %C(blue)%ad%C(red)%d %C(reset)%s%C(green) [%cn]\" --decorate --date=short
	lg-full = log --name-status --pretty=fuller
```

## Cheat Sheet

### Create


| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| Clone an existing repository  | `$ git clone ssh://user@domain.com/repo.git`|
| Create a new local repository | `$ git init`                                |

### Local Changes

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| Changed files in your working directory | `$ git status` |
| Changes to tracked files | `$ git diff` |
| Add all current changes to the next commit | `$ git add .` |
| Add some changes in <file> to the next commit | `$ git add -p <file>` |
| Commit all local changes in tracked files | `$ git commit -a` |
| Commit previously staged changes | `$ git commit` |
| Change the last commit (__Don‘t amend published commits!__) | `$ git commit --amend` |

### Commit History

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| Show all commits, starting with newest | `$ git log` |
| Show changes over time for a specific file | `$ git log -p <file>` |
| Who changed what and when in <file> | `$ git blame <file>` |

### Branches and Tags

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| List all existing branches | `$ git branch` |
| Switch HEAD branch | `$ git checkout <branch>` |
| Create a new branch based on your current HEAD | `$ git branch <new-branch>` |
| Create a new tracking branch based on a remote branch | `$ git checkout --track <remote/branch>` |
| Delete a local branch | `$ git branch -d <branch>` |
| Mark the current commit with a tag | `$ git tag <tag-name>` |

### Update and Publish

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| List all currently configured remotes | `$ git remote -v` |
| Show information about a remote | `$ git remote show <remote>` |
| Add new remote repository, named <remote> | `$ git remote add <remote> <url>` |
| Download all changes from <remote>, but don‘t integrate into HEAD | `$ git fetch <remote>` |
| Download changes and directly merge/ integrate into HEAD | `$ git pull <remote> <branch>` |
| Publish local changes on a remote | `$ git push <remote> <branch>` |
| Delete a branch on the remote | `$ git branch -dr <remote/branch>` |
| Publish your tags | `$ git push --tags` |

### Merge and Rebase

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| Merge <branch> into your current HEAD | `$ git merge <branch>` |
| Rebase your current HEAD onto <branch> (__Don‘t rebase published commits!__) | `$ git rebase <branch>` |
| Abort a rebase | `$ git rebase --abort` |
| Continue a rebase after resolving conflicts | `$ git rebase --continue` |
| Use your configured merge tool to solve conflicts | `$ git mergetool` |
| Use your editor to manually solve con- flicts and (after resolving) mark file as resolved | `$ git add <resolved-file> $ git rm <resolved-file>` |

### Undo

| Operation                                      | Command                    |
|------------------------------------------------|----------------------------|
| Discard all local changes in your working directory | `$ git reset --hard HEAD` |
| Discard local changes in a specific file | `$ git checkout HEAD <file>` |
| Revert a commit (by producing a new commit with contrary changes) | `$ git revert <commit>` |
| Reset your HEAD pointer to a previous commit and discard all changes since then | `$ git reset --hard <commit>` |
| Reset your HEAD pointer to a previous commit and preserve all changes as unstaged changes | `$ git reset <commit>` |
| Reset your HEAD pointer to a previous commit and preserve uncommitted local changes | `$ git reset --keep <commit>` |

##
##
