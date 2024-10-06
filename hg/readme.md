Mercurial Commands

Commands | Description
-------- | -----------
hg pull | get latest changes like git pull use flags like -u IDK why yet
hg add | only for new files
hg commit | add changes to commit with -m for message just like git
hg addremove | adds new files and removes file not in your file system
hg incoming | see changes commited by others
hg outgoing | see local commits
hg commit --amend | same as ```git commit --amend```
hg record filename | shows history of changes to file uses extension
hg merge | like a ```git merge``` http://hgbook.red-bean.com/read/a-tour-of-mercurial-merging-work.html
hg log -r tip | tip changelog
hg log -l 5 | last 5 changelog statuses
hg status -m | show modified files only
hg status -r | show removed files only
hg status -a | show added files only
hg strip "0000" | remove commit from history and delete changes before push, if pushed you are fucked
hg log -u email@accout.com | see all account commits &#124; type -v for a verbose version
hg diff -r 0000:0000 /dir/location/path | Diff versions of same file from different CHANGESET
hg diff &#124; less; hg commit | show changes committed
hg out | See what is not pushed to remote branch
hg update 0000 | CHANGESET = 0000 or branchname
hg checkout branch | works like a ```git checkout branch```
hg record | shows record of pending changes
hg update -C | resets your head and removes commits not pushed like ```git reset --hard```
hg backout 0000 | CHANGESET = 0000 like a ```git revert tag/hash```
hg blame or hg annotate | same as a git blame
hg bisect | lets you test inbetween commits to find bugs http://mercurial.selenic.com/wiki/BisectExtension
hg shelve | like a ```git stash``` (Requires the ShelveExtension or the AtticExtension.)
hg graft --edit 0000 | lets you pick what changes to push to default or commit CHANGESET = 0000 ```git cherry-pick <commit>``` http://selenic.com/hg/help/graft
hg graft --edit 0000::0005 | add a series of commits from 0000 to 0005 as a batch
hg heads | shows changes in child and parent branches
hg identify --num | current changeset
hg branch feature | go to default branch and use this command to create a new branch namded "feature" based off of it
hg commit --close-branch -m 'closing this branch' | Inside branch you want to close commit this and push so branch disapears and keeps your coworkers happy
note | Hg .hgignore, syntax: glob is the same behaviour as git's .gitignore.

## Branching
http://stevelosh.com/blog/2009/08/a-guide-to-branching-in-mercurial/



# Git

Fetch single branch (trunk): `git fetch origin trunk:trunk` (add `-u` flag when already on that branch)

Make a new worktree (similar to hg share): `git worktree add --no-checkout --detach ../mynewfolder`


Converting Hg repo to Git:
```
; get https://github.com/frej/fast-export somewhere
; clone hg repo
hg clone repourl clonedirhg
; convert Hg largefiles to regular files
hg lfconvert --to-normal clonedirhg clonedirhg-nolf
; init git repo and convert
mkdir clonedirgit
cd clonedirgit
git init .
../path/to/fast-export.sh -r ../clonedirhg-nolf
; convert files to Git LFS
git lfs migrate import --everything --verbose --include="*.png,*.jpg,*.tga"
```


# Hg

Graph of total commits by month, over last year:
```
hg churn -f "%Y-%m" -s -c -d "-365"
```
List of my commits over last year:
```
hg log -k aras -d "2018-01-01 to 2018-12-31" --template "{short(node)} {user(author)} {firstline(desc)}\n" >mycommits.txt
``` 
My lines changed count over last year (takes ages):
```
hg churn -r "user(aras)" -d "2018-01-01 to 2018-12-31" --diffstat
```   
Commits over last 30 days by authors:
```
hg churn -d "-30" -c
```
Git commits since date by authords:
```
git shortlog -sne --since="01 Jan 2020"
```

Figuring out size of branch merge (see size of `tmp.hg` after the command):
```
hg bundle -v -r my/branch/name --base trunk tmp.hg
```

# Ono

Ono list of PRs for an author (https://ono.unity3d.com/_admin/graphql):
```
{
  repository(name: "unity/unity") {
    pullRequests(user: {username: "aras"}, includeClosed: true) {
      nodes {
        id
        created
        origin { name }
        title
        iterations { id }
      }
    }
  }
}
```
```
