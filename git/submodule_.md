# Recipes

##
#
https://git-scm.com/book/en/v2/Git-Tools-Submodules
#
https://www.cyberdemon.org/2024/03/20/submodules.html
#
##



Dmitry Mazin
"cyberdemon.org is a cool domain"

home / email me / mastodon / RSS feed / Telegram channel
Demystifying git submodules

Mar 20, 2024

Throughout my career, I have found git submodules to be a pain. Because I did not understand them, I kept getting myself into frustrating situations.

So, I finally sat down and learned how git tracks submodules. Turns out, it’s not complex at all. It’s just different from how git tracks regular files. It’s just one more thing you have to learn.

In this article, I’ll explain exactly what I needed to know in order to work with submodules without inflicting self-damage.

(This article doesn’t discuss whether submodules are good/bad, or if you should use them or not – a valid discussion, but out of scope.)
The lay of the land

This article will make more sense if we use concrete examples.

Allow me to describe a toy webapp we’re building. Call this repo webapp. Here are the contents of the repo.

$ [/webapp] ls

.git/
README.md
tests/

Say you want to import some library. It lives in its own repo, library.

$ [/library] ls

.git/
README.md
my_cool_functions.py

Shortly, I’ll explain how submodules work. But, first, let me dramatically re-enact something that has happened to me multiple times. This is what it looks like to use submodules without understanding them.
A day in the life of someone who doesn’t understand submodules

Ah, 2012. What a time to be a “full-stack engineer”! I wonder what contributions await me on the main branch!

(For the sake of readability, in this article, instead of using real commit SHAs, I’m going to use fake descriptive ones.)

Let’s pull to make sure I’m up-to-date with the remote.
```
$ [/webapp] git pull

remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (1/1), done.
remote: Total 2 (delta 1), reused 2 (delta 1), pack-reused 0
Unpacking objects: 100% (2/2), 237 bytes | 118.00 KiB/s, done.
From https://github.com/dmazin/webapp
   webapp_old_commit_sha..webapp_new_commit_sha  main -> origin/main
Updating webapp_old_commit_sha..webapp_new_commit_sha
Fast-forward
 library | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

After I pull, I like to confirm that my working tree is clean.

$ [/webapp] git st

## main...origin/main
 M library

What’s this? I’ve made modifications to library? I never touch that directory.

It’s weird that I’ve modified a directory. Usually git just says I’ve modified a specific file.

Well, what does git diff have to say?

$ [/webapp] git diff

diff --git a/library b/library
index library_old_commit_sha..library_new_commit_sha 160000
--- a/library
+++ b/library
@@ -1 +1 @@
-Subproject commit library_new_commit_sha
+Subproject commit library_old_commit_sha
```
Apparently, I deleted Subproject commit library_new_commit_sha and added Subproject commit library_old_commit_sha.

Surely I didn’t do that. That’s weird, let me do a hard reset.

$ [/webapp] git reset --hard origin/main

HEAD is now at webapp_new_commit_sha point submodule to newest commit

Did it make the git diff go away?

$ [/webapp] git st

## main...origin/main
 M library

It did not! I am really confused now!

Well, the usual way I make local modifications go away is git reset --hard, and that didn’t work. The other way is to commit the changes.

(Sometimes, people don’t even notice the diff above, and accidentally do this.)

My future self: Don’t do it! If you git add that change, you’ll be rolling back a change someone else made!

What’s going on, of course, is that library is a submodule, and you have to do special stuff to deal with them.

Let’s dive into submodules.
What’s a submodule?

A git submodule is a full repo that’s been nested inside another repo. Any repo can be a submodule of another.

So, library is a full repo that has been nested inside webapp as a submodule.

That doesn’t seem so confusing, does it? However, there are two important, and tricky, facts about submodules. These facts are why so many people trip up on submodules.
1. A submodule is always pinned to a specific commit

You know how package managers let you be fuzzy when specifying a package version (“get me any version of requests so long as it’s 2.x.x”), or to pin an exact version (“use requests 2.31.0 exactly”)?

Submodules can only be pinned to a specific commit. This is because a submodule isn’t a package; it’s code that you have embedded in another repo, and git wants you to be precise.

We’ll see exactly how this pinning works shortly.
2. git does not automatically download or update submodules

If you clone webapp afresh, git will not automatically download library for you (unless you clone using git clone --recursive)

Similarly, if a collaborator pins webapp to a new commit of library, and you git pull webapp, git will not automatically update library for you.

This is actually what’s happening in the dramatic re-enactment above. Let me rewind a little bit to show what happened.
What happens when someone updates a submodule?

In the beginning, webapp pointed to webapp_old_commit_sha, which pinned library to library_old_commit_sha.

Hand-drawn diagram of two git repositories, webapp and library. It shows that the old_sha commit of the webapp repo points to the old_sha commit of the library repo. The old_sha commit of the webapp repo has a purple border around it, saying 'HEAD'. The old_sha commit of the library repo also has a purple border around it, saying 'HEAD'.

(Think of HEAD as “current commit”.)

Then, my collaborator made changes to library. Remember, library is a full repo, so after they did their work, they did what you always do after you make changes: they committed and pushed the new commit, library_new_commit_sha.

They weren’t done, though. webapp must point to a specific commit of library, so in order to use library_new_commit_sha, my collaborator then pushed a new commit to webpapp, webapp_new_commit_sha, which points to library_new_commit_sha.

Here’s the thing, though! git does not automatically update submodules, so library still points to library_old_commit_sha.

Hand-drawn diagram of two git repositories, webapp and library. It shows that the old_sha commit of the webapp repo points to the old_sha commit of the library repo. The new_sha commit of the webapp repo points to the new_sha of the library repo. The new_sha commit of the webapp repo has a purple border around it, saying 'HEAD'. The old_sha commit of the library repo has a purple border around it, saying 'HEAD'. A red arrow points to the purple border around old_sha in the library repo. The red arrow is linked to a speech bubble which says, 'library still points at old_sha!'

I think this will be a lot less confusing if we look at exactly how git tracks submodules.
Commercial interruption

If you’re enjoying yourself, may I ask if you’d like to follow me via RSS feed, Mastodon, or Telegram channel? Thanks!
How git tracks submodules
How does git pin a submodule to a specific commit?

The latest commit of webapp is webapp_new_commit_sha. Let’s inspect that commit.

A commit is just a file on disk. However, it’s optimized/compressed, so we use a built-in utility to view it. Here’s what the commit stores.

$ [/webapp] git cat-file -p `webapp_new_commit_sha`

tree 92018fc6ac6e71ea3dfb57e2fab9d3fe23b6fdf4
parent webapp_old_commit_sha
author Dmitry Mazin <dm@cyberdemon.org> 1708717288 +0000
committer Dmitry Mazin <dm@cyberdemon.org> 1708717288 +0000

point submodule to newest commit

What we care about is tree 92018fc6ac6e71ea3dfb57e2fab9d3fe23b6fdf4. The tree object represents the directory listing of your repo. When you think trees, think directories.

Let’s inspect the tree object.
```
$ [/webapp] git cat-file -p 92018fc6ac6e71ea3dfb57e2fab9d3fe23b6fdf4

100644 blob     6feaf03c7a9c805ff734a90a245a417e6a6c099b    .gitmodules
100644 blob     a72832b303c4d4f1833da79fc8a566e8a0eb37af    README.md
040000 tree     a425c23ded8892f901dee7fbc8d4c5714bdcc40d    tests
160000 commit   library_new_commit_sha                      library
```
Note how tests is a tree (just like directories can hold directories, trees can point to trees).

But library is a… commit?!

160000 commit   library_new_commit_sha                      library

That weirdness, right there, is precisely how git knows library points to library_new_commit_sha.

In other words, the way git implements submodules is by doing a weird trick where a tree points to a commit.

Hand-drawn diagram showing the text 'webapp_new_commit_sha' connected, via arrow, to 'tree a425' which is itself connected, via arrow, to 'library_new_commit_sha'

Let’s use this knowledge to understand the git diff from earlier.
Understanding git diff

Here’s the diff again.
```
$ [/webapp] git diff

diff --git a/library b/library
index library_old_commit_sha..library_new_commit_sha 160000
--- a/library
+++ b/library
@@ -1 +1 @@
-Subproject commit library_new_commit_sha
+Subproject commit library_old_commit_sha
```
It’s confusing that it’s saying that I modified library. I didn’t modify it, someone else did!

Usually, I think of git diff as “here are the changes I have made”. But this isn’t exactly correct.

When you invoke git diff, you’re asking git to tell you the difference between your working tree (that is, your unstaged, uncommitted local changes) and the most recent commit of your branch (webapp_new_commit_sha).

When you look at it that way, the above git diff starts to make sense. In webapp_new_commit_sha, library points to library_new_commit_sha, but in our working tree, library still points to library_old_commit_sha.

git has no idea which change happened first. It only knows that your working tree is different from the commit. And, so it tells you: library_new_commit_sha is saying that library should point to library_new_commit_sha, but it doesn’t.

Understanding the above took the pain out of submodules for me. However, I still haven’t told you how to update a submodule.
How to update a submodule

We now understand that we need to point library to library_new_commit_sha. How?

Because library is a full repo, I could just cd into it and literally check out that commit:

$ [/webapp] cd library

$ [/library] git checkout library_new_commit_sha

Previous HEAD position was library_old_commit_sha README
HEAD is now at library_new_commit_sha add some cool functions

If we go back into webapp, we’ll see that git st/git diff finally look clean.

$ [/webapp] git st

## main...origin/main
# (no output)

$ [/webapp] git diff

# (no output)

However, you don’t actually need to do the above.
How to really update a submodule

From webapp, we can invoke git submodule update. This updates all of a repo’s submodules.

People often use certain flags with git submodule update, so let’s understand them.
Initialize a submodule: git submodule update --init

Remember how I said that if you git clone webapp, git won’t actually download the contents of library?

What you’re supposed to do is, after cloning webapp:

    Run git submodule init to initialize the submodules. This doesn’t actually download them, though 🙃️.
    Run git submodule update to actually pull the submodules.

This is kind of a silly dance, so git lets you just do git submodule update --init. This initializes any submodules and updates them in one step. I always pass --init because there is no harm in doing so.

You can skip --init by cloning with --recursive: that is, you could have done git clone webapp --recursive. I never remember to do this, though. Plus, you end up having to do git update submodule anyway.
Update submodules of submodules: git submodule update --recursive

Submodules can nest other submodules. Yeah.

So, to take care of updating submodules all the way down, pretty much just always pass --recursive to git submodule update.

So, the command I always end up using is git submodule update --init --recursive.
Make git automatically update submodules: git config submodule.recurse true

submodule.recurse true makes submodules automatically update when you git pull, git checkout, etc. In other words, it makes submodules automatically point to whatever they are supposed to point to. It’s only available in git 2.14 and newer.

That makes running git submodule update unnecessary.

I don’t use this setting, because I’m not sure if there are drawbacks or not. Plus, I work on submodules enough that I think it could cause conflicts. Let me know if you’re aware of shortcomings, or if you’ve been using this setting forever without issue!

This setting definitely does not apply to git clone. So you still need to do git clone --recursive or init/update submodules using the commands above.
Recap

I think I can summarize submodules pretty simply.

It’s possible to embed a repo within another repo. This is called a submodule.

Each commit of the outer repo always specifies an exact commit that submodule. This is done by the outer commit -> tree -> submodule commit link.

When you check out commits, git doesn’t automatically update submodules for you. You have to do that using git submodule update.

And there we have it!
Further topics in submodules

The above is enough to hopefully take the confusion out of submodules. However, there are more common commands and configs that I’d like to explain.
How to add a submodule: git submodule add

Let’s say that I start webapp fresh, and I have not added library to it yet.

To add library, I’d do git submodule add https://github.com/dmazin/library.git library.

This will add (or update) the .gitmodules file of webapp, download library, and point webapp at the latest commit of library.

Remember, this actually modifies webapp, so you need to commit after that. But you thankfully don’t need to do git submodule update after doing git submodule add or anything.
What do I do after I’ve modified a submodule?

Remember that library is a full repo, so if you want to make changes to it, you can. Just make changes and commit them to the main branch.

But how do you make webapp point at the new commit? There are a couple ways.
Without a command

You can go into webapp, then cd library, and just do git pull in there. When you cd back into webapp, if you git diff you’ll see that webapp points to the newest branch of library. You can commit that.
Using git submodule update --remote -- library

This tells git “make the submodule point to the latest remote commit”. Since you have pushed the latest commit of library to library’s remote, this will make webapp point to that commit.

But note that git submodule update --remote will do this to all your submodules. You likely do not want that.

For that reason, you have to do git submodule update --remote -- library to limit this to library only. (If you’re thrown off by the fact that you have to do -- library – yeah, it’s kind of weird.)

Because --remote might accidentally update all the submodules, honestly I usually do the “without a command” method.
The .gitmodules file

How does git know where to download library from? git uses a file called .gitmodules to track the basic facts of a submodule, like the repo URL.

```
$ [/webapp] cat .gitmodules

[submodule "library"]
        path = library
        url = https://github.com/dmazin/library.git

```
The nice thing about .gitmodules is that it’s a regular file, tracked the regular way in git. That makes it not confusing.

(What I don’t understand is, why git didn’t just put the submodule commit right in .gitmodules? The commits of webapp would still be able to specify exact commits of library to use. What am I missing?)
Making submodules use branches other than main

If you want to, you can make library track whatever branch you want. Otherwise, it defaults to whatever the “main” branch is.
```
[submodule "library"]
        path = library
        url = https://github.com/dmazin/library.git
        branch = staging
```
Thanks for reading!


##
##

Note: the [main]$ bits on each line represents your bash prompt. You should only type the stuff after the $.

    Set up the submodule for the first time:

    [~]$  cd ~/main/
    [main]$  git submodule add git://github.com/my/submodule.git ./subm
    [main]$  git submodule update --init
    [main]$  git commit .gitmodules -m "Added submodule as ./subm"

    Fetch submodules after cloning a repository:

    [~]$  git clone git://github.com/my/main.git ~/main
    [~]$  cd ~/main/
    [main]$  git submodule update --init

      To get submodules automatically, you can use “git clone –recursive “

    Pull upstream main repo changes and update submodule contents:

    [main]$  git pull origin/master
    [main]$  git submodule update

    Pull upstream changes to the submodule:

    [main]$  cd ./subm
    [subm]$  git pull origin/master   # or fetch then merge
    [subm]$  cd ..
    [main]$  git commit ./subm -m "Updated submodule reference"

    Edit and commit files in your submodule:

    [main]$  cd ./subm
    [subm]$  edit whatever.rb
    [subm]$  git commit whatever.rb -m "Updated whatever.rb"
    [subm]$  cd ..
    [main]$  git commit ./subm -m "Updated submodule reference"

    Push your submodule changes to the submodule upstream:

    [main]$  cd ./subm
    [subm]$  git push origin master
    
    
##
##

##
##


Git submodules
Git submodules allow you to keep a Git repository as a subdirectory of another Git repository. Git submodules are simply a reference to another repository at a particular snapshot in time. Git submodules enable a Git repository to incorporate and track version history of external code.

What is a Git submodule?
Often a code repository will depend upon external code. This external code can be incorporated in a few different ways. The external code can be directly copied and pasted into the main repository. This method has the downside of losing any upstream changes to the external repository. Another method of incorporating external code is through the use of a language's package management system like Ruby Gems or NPM. This method has the downside of requiring installation and version management at all places the origin code is deployed. Both of these suggested incorporation methods do not enable tracking edits and changes to the external repository.

A Git submodule is a record within a host Git repository that points to a specific commit in another external repository. Submodules are very static and only track specific commits. Submodules do not track Git refs or branches and are not automatically updated when the host repository is updated. When adding a submodule to a repository a new .gitmodules file will be created. The .gitmodules file contains meta data about the mapping between the submodule project's URL and local directory. If the host repository has multiple submodules, the .gitmodules file will have an entry  for each submodule.

When should you use a Git submodule?
If you need to maintain a strict version management over your external dependencies,  it can make sense to use Git submodules. The following are a few best use cases for Git submodules.

 When an external component or subproject is changing too fast or upcoming changes will break the API, you can lock the code to a specific commit for your own safety.
 When you have a component that isn’t updated very often and you want to track it as a vendor dependency.
 When you are delegating a piece of the project to a third party and you want to integrate their work at a specific time or release. Again this works when updates are not too frequent.
databases
RELATED MATERIAL
How to move a full Git repository
Read article
Bitbucket logo
SEE SOLUTION
Learn Git with Bitbucket Cloud
Read tutorial
Common commands for Git submodules
Add Git submodule
The git submodule add is used to add a new submodule to an existing repository. The following is an example that creates an empty repo and explores Git submodules.

$ mkdir git-submodule-demo
$ cd git-submodule-demo/
$ git init
Initialized empty Git repository in /Users/atlassian/git-submodule-demo/.git/
This sequence of commands will create a new directory git-submodule-demo, enter that directory, and initialize it as a new repository. Next we will add a submodule to this fresh new repo.

$ git submodule add https://bitbucket.org/jaredw/awesomelibrary
Cloning into '/Users/atlassian/git-submodule-demo/awesomelibrary'...
remote: Counting objects: 8, done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 8 (delta 1), reused 0 (delta 0)
Unpacking objects: 100% (8/8), done.
The git submodule add command takes a URL parameter that points to a git repository. Here we have added the awesomelibrary as a submodule. Git will immediately clone the submodule. We can now review the current state of the repository using git status...

$ git status
On branch main

No commits yet

Changes to be committed:
  (use "git rm --cached <file>..." to unstage)

 new file:   .gitmodules
 new file:   awesomelibrary
There are now two new files in the repository .gitmodules and the awesomelibrary directory. Looking at the contents of .gitmodules shows the new submodule mapping

[submodule "awesomelibrary"]
 path = awesomelibrary
 url = https://bitbucket.org/jaredw/awesomelibrary
$ git add .gitmodules awesomelibrary/
$ git commit -m "added submodule"
[main (root-commit) d5002d0] added submodule
 2 files changed, 4 insertions(+)
 create mode 100644 .gitmodules
 create mode 160000 awesomelibrary
Cloning git submodules
git clone /url/to/repo/with/submodules
git submodule init
git submodule update
Git submodule Init
The default behavior of git submodule init is to copy the mapping from the .gitmodules file into the local ./.git/config file. This may seem redundant and lead to questioning git submodule init usefulness. git submodule init has extend behavior in which it accepts a list of explicit module names. This enables a workflow of activating only specific submodules that are needed for work on the repository. This can be helpful if there are many submodules in a repo but they don't all need to be fetched for work you are doing.

Submodule workflows
Once submodules are properly initialized and updated within a parent repository they can be utilized exactly like stand-alone repositories. This means that submodules have their own branches and history. When making changes to a submodule it is important to publish submodule changes and then update the parent repositories reference to the submodule. Let’s continue with the awesomelibrary example and make some changes:
```
$ cd awesomelibrary/
$ git checkout -b new_awesome
Switched to a new branch 'new_awesome'
$ echo "new awesome file" > new_awesome.txt
$ git status
On branch new_awesome
Untracked files:
  (use "git add <file>..." to include in what will be committed)

 new_awesome.txt

nothing added to commit but untracked files present (use "git add" to track)
$ git add new_awesome.txt
$ git commit -m "added new awesome textfile"
[new_awesome 0567ce8] added new awesome textfile
 1 file changed, 1 insertion(+)
 create mode 100644 new_awesome.txt
$ git branch
  main
* new_awesome
  ```
Here we have changed directory to the awesomelibrary submodule. We have created a new text file new_awesome.txt with some content and we have added and committed this new file to the submodule. Now let us change directories back to the parent repository and review the current state of the parent repo.
```
$ cd ..
$ git status
On branch main
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)
```
 modified:   awesomelibrary (new commits)

no changes added to commit (use "git add" and/or "git commit -a")
Executing git status shows us that the parent repository is aware of the new commits to the awesomelibrary submodule. It doesn't go into detail about the specific updates because that is the submodule repositories responsibility. The parent repository is only concerned with pinning the submodule to a commit. Now we can update the parent repository again by doing a git add and git commit on the submodule. This will put everything into a good state with the local content. If you are working in a team environment it is critical that you then git push the submodule updates, and the parent repository updates.

When working with submodules, a common pattern of confusion and error is forgetting to push updates for remote users. If we revisit the awesomelibrary work we just did, we pushed only the updates to the parent repository. Another developer would go to pull the latest parent repository and it would be pointing at a commit of awesomelibrary that they were unable to pull because we had forgotten to push the submodule. This would break the remote developers local repo. To avoid this failure scenario make sure to always commit and push the submodule and parent repository.

Conclusion
Git submodules are a powerful way to leverage Git as an external dependency management tool. Weigh the pros and cons of Git submodules before using them, as they are an advanced feature and may take a learning curve for team members to adopt.

##
##


7.11 Git Tools - Submodules
Submodules
It often happens that while working on one project, you need to use another project from within it. Perhaps it’s a library that a third party developed or that you’re developing separately and using in multiple parent projects. A common issue arises in these scenarios: you want to be able to treat the two projects as separate yet still be able to use one from within the other.

Here’s an example. Suppose you’re developing a website and creating Atom feeds. Instead of writing your own Atom-generating code, you decide to use a library. You’re likely to have to either include this code from a shared library like a CPAN install or Ruby gem, or copy the source code into your own project tree. The issue with including the library is that it’s difficult to customize the library in any way and often more difficult to deploy it, because you need to make sure every client has that library available. The issue with copying the code into your own project is that any custom changes you make are difficult to merge when upstream changes become available.

Git addresses this issue using submodules. Submodules allow you to keep a Git repository as a subdirectory of another Git repository. This lets you clone another repository into your project and keep your commits separate.

Starting with Submodules
We’ll walk through developing a simple project that has been split up into a main project and a few sub-projects.

Let’s start by adding an existing Git repository as a submodule of the repository that we’re working on. To add a new submodule you use the git submodule add command with the absolute or relative URL of the project you would like to start tracking. In this example, we’ll add a library called “DbConnector”.

$ git submodule add https://github.com/chaconinc/DbConnector
Cloning into 'DbConnector'...
remote: Counting objects: 11, done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 11 (delta 0), reused 11 (delta 0)
Unpacking objects: 100% (11/11), done.
Checking connectivity... done.
By default, submodules will add the subproject into a directory named the same as the repository, in this case “DbConnector”. You can add a different path at the end of the command if you want it to go elsewhere.

If you run git status at this point, you’ll notice a few things.

$ git status
On branch master
Your branch is up-to-date with 'origin/master'.

Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

	new file:   .gitmodules
	new file:   DbConnector
First you should notice the new .gitmodules file. This is a configuration file that stores the mapping between the project’s URL and the local subdirectory you’ve pulled it into:

[submodule "DbConnector"]
	path = DbConnector
	url = https://github.com/chaconinc/DbConnector
If you have multiple submodules, you’ll have multiple entries in this file. It’s important to note that this file is version-controlled with your other files, like your .gitignore file. It’s pushed and pulled with the rest of your project. This is how other people who clone this project know where to get the submodule projects from.

Note
Since the URL in the .gitmodules file is what other people will first try to clone/fetch from, make sure to use a URL that they can access if possible. For example, if you use a different URL to push to than others would to pull from, use the one that others have access to. You can overwrite this value locally with git config submodule.DbConnector.url PRIVATE_URL for your own use. When applicable, a relative URL can be helpful.

The other listing in the git status output is the project folder entry. If you run git diff on that, you see something interesting:

$ git diff --cached DbConnector
diff --git a/DbConnector b/DbConnector
new file mode 160000
index 0000000..c3f01dc
--- /dev/null
+++ b/DbConnector
@@ -0,0 +1 @@
+Subproject commit c3f01dc8862123d317dd46284b05b6892c7b29bc
Although DbConnector is a subdirectory in your working directory, Git sees it as a submodule and doesn’t track its contents when you’re not in that directory. Instead, Git sees it as a particular commit from that repository.

If you want a little nicer diff output, you can pass the --submodule option to git diff.

$ git diff --cached --submodule
diff --git a/.gitmodules b/.gitmodules
new file mode 100644
index 0000000..71fc376
--- /dev/null
+++ b/.gitmodules
@@ -0,0 +1,3 @@
+[submodule "DbConnector"]
+       path = DbConnector
+       url = https://github.com/chaconinc/DbConnector
Submodule DbConnector 0000000...c3f01dc (new submodule)
When you commit, you see something like this:

$ git commit -am 'Add DbConnector module'
[master fb9093c] Add DbConnector module
 2 files changed, 4 insertions(+)
 create mode 100644 .gitmodules
 create mode 160000 DbConnector
Notice the 160000 mode for the DbConnector entry. That is a special mode in Git that basically means you’re recording a commit as a directory entry rather than a subdirectory or a file.

Lastly, push these changes:

$ git push origin master
Cloning a Project with Submodules
Here we’ll clone a project with a submodule in it. When you clone such a project, by default you get the directories that contain submodules, but none of the files within them yet:

$ git clone https://github.com/chaconinc/MainProject
Cloning into 'MainProject'...
remote: Counting objects: 14, done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 14 (delta 1), reused 13 (delta 0)
Unpacking objects: 100% (14/14), done.
Checking connectivity... done.
$ cd MainProject
$ ls -la
total 16
drwxr-xr-x   9 schacon  staff  306 Sep 17 15:21 .
drwxr-xr-x   7 schacon  staff  238 Sep 17 15:21 ..
drwxr-xr-x  13 schacon  staff  442 Sep 17 15:21 .git
-rw-r--r--   1 schacon  staff   92 Sep 17 15:21 .gitmodules
drwxr-xr-x   2 schacon  staff   68 Sep 17 15:21 DbConnector
-rw-r--r--   1 schacon  staff  756 Sep 17 15:21 Makefile
drwxr-xr-x   3 schacon  staff  102 Sep 17 15:21 includes
drwxr-xr-x   4 schacon  staff  136 Sep 17 15:21 scripts
drwxr-xr-x   4 schacon  staff  136 Sep 17 15:21 src
$ cd DbConnector/
$ ls
$
The DbConnector directory is there, but empty. You must run two commands: git submodule init to initialize your local configuration file, and git submodule update to fetch all the data from that project and check out the appropriate commit listed in your superproject:

$ git submodule init
Submodule 'DbConnector' (https://github.com/chaconinc/DbConnector) registered for path 'DbConnector'
$ git submodule update
Cloning into 'DbConnector'...
remote: Counting objects: 11, done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 11 (delta 0), reused 11 (delta 0)
Unpacking objects: 100% (11/11), done.
Checking connectivity... done.
Submodule path 'DbConnector': checked out 'c3f01dc8862123d317dd46284b05b6892c7b29bc'
Now your DbConnector subdirectory is at the exact state it was in when you committed earlier.

There is another way to do this which is a little simpler, however. If you pass --recurse-submodules to the git clone command, it will automatically initialize and update each submodule in the repository, including nested submodules if any of the submodules in the repository have submodules themselves.

$ git clone --recurse-submodules https://github.com/chaconinc/MainProject
Cloning into 'MainProject'...
remote: Counting objects: 14, done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 14 (delta 1), reused 13 (delta 0)
Unpacking objects: 100% (14/14), done.
Checking connectivity... done.
Submodule 'DbConnector' (https://github.com/chaconinc/DbConnector) registered for path 'DbConnector'
Cloning into 'DbConnector'...
remote: Counting objects: 11, done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 11 (delta 0), reused 11 (delta 0)
Unpacking objects: 100% (11/11), done.
Checking connectivity... done.
Submodule path 'DbConnector': checked out 'c3f01dc8862123d317dd46284b05b6892c7b29bc'
If you already cloned the project and forgot --recurse-submodules, you can combine the git submodule init and git submodule update steps by running git submodule update --init. To also initialize, fetch and checkout any nested submodules, you can use the foolproof git submodule update --init --recursive.

Working on a Project with Submodules
Now we have a copy of a project with submodules in it and will collaborate with our teammates on both the main project and the submodule project.

Pulling in Upstream Changes from the Submodule Remote
The simplest model of using submodules in a project would be if you were simply consuming a subproject and wanted to get updates from it from time to time but were not actually modifying anything in your checkout. Let’s walk through a simple example there.

If you want to check for new work in a submodule, you can go into the directory and run git fetch and git merge the upstream branch to update the local code.

$ git fetch
From https://github.com/chaconinc/DbConnector
   c3f01dc..d0354fc  master     -> origin/master
$ git merge origin/master
Updating c3f01dc..d0354fc
Fast-forward
 scripts/connect.sh | 1 +
 src/db.c           | 1 +
 2 files changed, 2 insertions(+)
Now if you go back into the main project and run git diff --submodule you can see that the submodule was updated and get a list of commits that were added to it. If you don’t want to type --submodule every time you run git diff, you can set it as the default format by setting the diff.submodule config value to “log”.

$ git config --global diff.submodule log
$ git diff
Submodule DbConnector c3f01dc..d0354fc:
  > more efficient db routine
  > better connection routine
If you commit at this point then you will lock the submodule into having the new code when other people update.

There is an easier way to do this as well, if you prefer to not manually fetch and merge in the subdirectory. If you run git submodule update --remote, Git will go into your submodules and fetch and update for you.

$ git submodule update --remote DbConnector
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 4 (delta 2), reused 4 (delta 2)
Unpacking objects: 100% (4/4), done.
From https://github.com/chaconinc/DbConnector
   3f19983..d0354fc  master     -> origin/master
Submodule path 'DbConnector': checked out 'd0354fc054692d3906c85c3af05ddce39a1c0644'
This command will by default assume that you want to update the checkout to the default branch of the remote submodule repository (the one pointed to by HEAD on the remote). You can, however, set this to something different if you want. For example, if you want to have the DbConnector submodule track that repository’s “stable” branch, you can set it in either your .gitmodules file (so everyone else also tracks it), or just in your local .git/config file. Let’s set it in the .gitmodules file:

$ git config -f .gitmodules submodule.DbConnector.branch stable

$ git submodule update --remote
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 4 (delta 2), reused 4 (delta 2)
Unpacking objects: 100% (4/4), done.
From https://github.com/chaconinc/DbConnector
   27cf5d3..c87d55d  stable -> origin/stable
Submodule path 'DbConnector': checked out 'c87d55d4c6d4b05ee34fbc8cb6f7bf4585ae6687'
If you leave off the -f .gitmodules it will only make the change for you, but it probably makes more sense to track that information with the repository so everyone else does as well.

When we run git status at this point, Git will show us that we have “new commits” on the submodule.

$ git status
On branch master
Your branch is up-to-date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

  modified:   .gitmodules
  modified:   DbConnector (new commits)

no changes added to commit (use "git add" and/or "git commit -a")
If you set the configuration setting status.submodulesummary, Git will also show you a short summary of changes to your submodules:

$ git config status.submodulesummary 1

$ git status
On branch master
Your branch is up-to-date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   .gitmodules
	modified:   DbConnector (new commits)

Submodules changed but not updated:

* DbConnector c3f01dc...c87d55d (4):
  > catch non-null terminated lines
At this point if you run git diff we can see both that we have modified our .gitmodules file and also that there are a number of commits that we’ve pulled down and are ready to commit to our submodule project.

$ git diff
diff --git a/.gitmodules b/.gitmodules
index 6fc0b3d..fd1cc29 100644
--- a/.gitmodules
+++ b/.gitmodules
@@ -1,3 +1,4 @@
 [submodule "DbConnector"]
        path = DbConnector
        url = https://github.com/chaconinc/DbConnector
+       branch = stable
 Submodule DbConnector c3f01dc..c87d55d:
  > catch non-null terminated lines
  > more robust error handling
  > more efficient db routine
  > better connection routine
This is pretty cool as we can actually see the log of commits that we’re about to commit to in our submodule. Once committed, you can see this information after the fact as well when you run git log -p.

$ git log -p --submodule
commit 0a24cfc121a8a3c118e0105ae4ae4c00281cf7ae
Author: Scott Chacon <schacon@gmail.com>
Date:   Wed Sep 17 16:37:02 2014 +0200

    updating DbConnector for bug fixes

diff --git a/.gitmodules b/.gitmodules
index 6fc0b3d..fd1cc29 100644
--- a/.gitmodules
+++ b/.gitmodules
@@ -1,3 +1,4 @@
 [submodule "DbConnector"]
        path = DbConnector
        url = https://github.com/chaconinc/DbConnector
+       branch = stable
Submodule DbConnector c3f01dc..c87d55d:
  > catch non-null terminated lines
  > more robust error handling
  > more efficient db routine
  > better connection routine
Git will by default try to update all of your submodules when you run git submodule update --remote. If you have a lot of them, you may want to pass the name of just the submodule you want to try to update.

Pulling Upstream Changes from the Project Remote
Let’s now step into the shoes of your collaborator, who has their own local clone of the MainProject repository. Simply executing git pull to get your newly committed changes is not enough:

$ git pull
From https://github.com/chaconinc/MainProject
   fb9093c..0a24cfc  master     -> origin/master
Fetching submodule DbConnector
From https://github.com/chaconinc/DbConnector
   c3f01dc..c87d55d  stable     -> origin/stable
Updating fb9093c..0a24cfc
Fast-forward
 .gitmodules         | 2 +-
 DbConnector         | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

$ git status
 On branch master
Your branch is up-to-date with 'origin/master'.
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   DbConnector (new commits)

Submodules changed but not updated:

* DbConnector c87d55d...c3f01dc (4):
  < catch non-null terminated lines
  < more robust error handling
  < more efficient db routine
  < better connection routine

no changes added to commit (use "git add" and/or "git commit -a")
By default, the git pull command recursively fetches submodules changes, as we can see in the output of the first command above. However, it does not update the submodules. This is shown by the output of the git status command, which shows the submodule is “modified”, and has “new commits”. What’s more, the brackets showing the new commits point left (<), indicating that these commits are recorded in MainProject but are not present in the local DbConnector checkout. To finalize the update, you need to run git submodule update:

$ git submodule update --init --recursive
Submodule path 'vendor/plugins/demo': checked out '48679c6302815f6c76f1fe30625d795d9e55fc56'

$ git status
 On branch master
Your branch is up-to-date with 'origin/master'.
nothing to commit, working tree clean
Note that to be on the safe side, you should run git submodule update with the --init flag in case the MainProject commits you just pulled added new submodules, and with the --recursive flag if any submodules have nested submodules.

If you want to automate this process, you can add the --recurse-submodules flag to the git pull command (since Git 2.14). This will make Git run git submodule update right after the pull, putting the submodules in the correct state. Moreover, if you want to make Git always pull with --recurse-submodules, you can set the configuration option submodule.recurse to true (this works for git pull since Git 2.15). This option will make Git use the --recurse-submodules flag for all commands that support it (except clone).

There is a special situation that can happen when pulling superproject updates: it could be that the upstream repository has changed the URL of the submodule in the .gitmodules file in one of the commits you pull. This can happen for example if the submodule project changes its hosting platform. In that case, it is possible for git pull --recurse-submodules, or git submodule update, to fail if the superproject references a submodule commit that is not found in the submodule remote locally configured in your repository. In order to remedy this situation, the git submodule sync command is required:

# copy the new URL to your local config
$ git submodule sync --recursive
# update the submodule from the new URL
$ git submodule update --init --recursive
Working on a Submodule
It’s quite likely that if you’re using submodules, you’re doing so because you really want to work on the code in the submodule at the same time as you’re working on the code in the main project (or across several submodules). Otherwise you would probably instead be using a simpler dependency management system (such as Maven or Rubygems).

So now let’s go through an example of making changes to the submodule at the same time as the main project and committing and publishing those changes at the same time.

So far, when we’ve run the git submodule update command to fetch changes from the submodule repositories, Git would get the changes and update the files in the subdirectory but will leave the sub-repository in what’s called a “detached HEAD” state. This means that there is no local working branch (like master, for example) tracking changes. With no working branch tracking changes, that means even if you commit changes to the submodule, those changes will quite possibly be lost the next time you run git submodule update. You have to do some extra steps if you want changes in a submodule to be tracked.

In order to set up your submodule to be easier to go in and hack on, you need to do two things. You need to go into each submodule and check out a branch to work on. Then you need to tell Git what to do if you have made changes and later git submodule update --remote pulls in new work from upstream. The options are that you can merge them into your local work, or you can try to rebase your local work on top of the new changes.

First of all, let’s go into our submodule directory and check out a branch.

$ cd DbConnector/
$ git checkout stable
Switched to branch 'stable'
Let’s try updating our submodule with the “merge” option. To specify it manually, we can just add the --merge option to our update call. Here we’ll see that there was a change on the server for this submodule and it gets merged in.

$ cd ..
$ git submodule update --remote --merge
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 4 (delta 2), reused 4 (delta 2)
Unpacking objects: 100% (4/4), done.
From https://github.com/chaconinc/DbConnector
   c87d55d..92c7337  stable     -> origin/stable
Updating c87d55d..92c7337
Fast-forward
 src/main.c | 1 +
 1 file changed, 1 insertion(+)
Submodule path 'DbConnector': merged in '92c7337b30ef9e0893e758dac2459d07362ab5ea'
If we go into the DbConnector directory, we have the new changes already merged into our local stable branch. Now let’s see what happens when we make our own local change to the library and someone else pushes another change to the upstream at the same time.

$ cd DbConnector/
$ vim src/db.c
$ git commit -am 'Unicode support'
[stable f906e16] Unicode support
 1 file changed, 1 insertion(+)
Now if we update our submodule we can see what happens when we have made a local change and upstream also has a change we need to incorporate.

$ cd ..
$ git submodule update --remote --rebase
First, rewinding head to replay your work on top of it...
Applying: Unicode support
Submodule path 'DbConnector': rebased into '5d60ef9bbebf5a0c1c1050f242ceeb54ad58da94'
If you forget the --rebase or --merge, Git will just update the submodule to whatever is on the server and reset your project to a detached HEAD state.

$ git submodule update --remote
Submodule path 'DbConnector': checked out '5d60ef9bbebf5a0c1c1050f242ceeb54ad58da94'
If this happens, don’t worry, you can simply go back into the directory and check out your branch again (which will still contain your work) and merge or rebase origin/stable (or whatever remote branch you want) manually.

If you haven’t committed your changes in your submodule and you run a submodule update that would cause issues, Git will fetch the changes but not overwrite unsaved work in your submodule directory.

$ git submodule update --remote
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 4 (delta 0), reused 4 (delta 0)
Unpacking objects: 100% (4/4), done.
From https://github.com/chaconinc/DbConnector
   5d60ef9..c75e92a  stable     -> origin/stable
error: Your local changes to the following files would be overwritten by checkout:
	scripts/setup.sh
Please, commit your changes or stash them before you can switch branches.
Aborting
Unable to checkout 'c75e92a2b3855c9e5b66f915308390d9db204aca' in submodule path 'DbConnector'
If you made changes that conflict with something changed upstream, Git will let you know when you run the update.

$ git submodule update --remote --merge
Auto-merging scripts/setup.sh
CONFLICT (content): Merge conflict in scripts/setup.sh
Recorded preimage for 'scripts/setup.sh'
Automatic merge failed; fix conflicts and then commit the result.
Unable to merge 'c75e92a2b3855c9e5b66f915308390d9db204aca' in submodule path 'DbConnector'
You can go into the submodule directory and fix the conflict just as you normally would.

Publishing Submodule Changes
Now we have some changes in our submodule directory. Some of these were brought in from upstream by our updates and others were made locally and aren’t available to anyone else yet as we haven’t pushed them yet.

$ git diff
Submodule DbConnector c87d55d..82d2ad3:
  > Merge from origin/stable
  > Update setup script
  > Unicode support
  > Remove unnecessary method
  > Add new option for conn pooling
If we commit in the main project and push it up without pushing the submodule changes up as well, other people who try to check out our changes are going to be in trouble since they will have no way to get the submodule changes that are depended on. Those changes will only exist on our local copy.

In order to make sure this doesn’t happen, you can ask Git to check that all your submodules have been pushed properly before pushing the main project. The git push command takes the --recurse-submodules argument which can be set to either “check” or “on-demand”. The “check” option will make push simply fail if any of the committed submodule changes haven’t been pushed.

$ git push --recurse-submodules=check
The following submodule paths contain changes that can
not be found on any remote:
  DbConnector

Please try

	git push --recurse-submodules=on-demand

or cd to the path and use

	git push

to push them to a remote.
As you can see, it also gives us some helpful advice on what we might want to do next. The simple option is to go into each submodule and manually push to the remotes to make sure they’re externally available and then try this push again. If you want the “check” behavior to happen for all pushes, you can make this behavior the default by doing git config push.recurseSubmodules check.

The other option is to use the “on-demand” value, which will try to do this for you.

$ git push --recurse-submodules=on-demand
Pushing submodule 'DbConnector'
Counting objects: 9, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (8/8), done.
Writing objects: 100% (9/9), 917 bytes | 0 bytes/s, done.
Total 9 (delta 3), reused 0 (delta 0)
To https://github.com/chaconinc/DbConnector
   c75e92a..82d2ad3  stable -> stable
Counting objects: 2, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (2/2), 266 bytes | 0 bytes/s, done.
Total 2 (delta 1), reused 0 (delta 0)
To https://github.com/chaconinc/MainProject
   3d6d338..9a377d1  master -> master
As you can see there, Git went into the DbConnector module and pushed it before pushing the main project. If that submodule push fails for some reason, the main project push will also fail. You can make this behavior the default by doing git config push.recurseSubmodules on-demand.

Merging Submodule Changes
If you change a submodule reference at the same time as someone else, you may run into some problems. That is, if the submodule histories have diverged and are committed to diverging branches in a superproject, it may take a bit of work for you to fix.

If one of the commits is a direct ancestor of the other (a fast-forward merge), then Git will simply choose the latter for the merge, so that works fine.

Git will not attempt even a trivial merge for you, however. If the submodule commits diverge and need to be merged, you will get something that looks like this:

$ git pull
remote: Counting objects: 2, done.
remote: Compressing objects: 100% (1/1), done.
remote: Total 2 (delta 1), reused 2 (delta 1)
Unpacking objects: 100% (2/2), done.
From https://github.com/chaconinc/MainProject
   9a377d1..eb974f8  master     -> origin/master
Fetching submodule DbConnector
warning: Failed to merge submodule DbConnector (merge following commits not found)
Auto-merging DbConnector
CONFLICT (submodule): Merge conflict in DbConnector
Automatic merge failed; fix conflicts and then commit the result.
So basically what has happened here is that Git has figured out that the two branches record points in the submodule’s history that are divergent and need to be merged. It explains it as “merge following commits not found”, which is confusing but we’ll explain why that is in a bit.

To solve the problem, you need to figure out what state the submodule should be in. Strangely, Git doesn’t really give you much information to help out here, not even the SHA-1s of the commits of both sides of the history. Fortunately, it’s simple to figure out. If you run git diff you can get the SHA-1s of the commits recorded in both branches you were trying to merge.

$ git diff
diff --cc DbConnector
index eb41d76,c771610..0000000
--- a/DbConnector
+++ b/DbConnector
So, in this case, eb41d76 is the commit in our submodule that we had and c771610 is the commit that upstream had. If we go into our submodule directory, it should already be on eb41d76 as the merge would not have touched it. If for whatever reason it’s not, you can simply create and checkout a branch pointing to it.

What is important is the SHA-1 of the commit from the other side. This is what you’ll have to merge in and resolve. You can either just try the merge with the SHA-1 directly, or you can create a branch for it and then try to merge that in. We would suggest the latter, even if only to make a nicer merge commit message.

So, we will go into our submodule directory, create a branch named “try-merge” based on that second SHA-1 from git diff, and manually merge.

$ cd DbConnector

$ git rev-parse HEAD
eb41d764bccf88be77aced643c13a7fa86714135

$ git branch try-merge c771610

$ git merge try-merge
Auto-merging src/main.c
CONFLICT (content): Merge conflict in src/main.c
Recorded preimage for 'src/main.c'
Automatic merge failed; fix conflicts and then commit the result.
We got an actual merge conflict here, so if we resolve that and commit it, then we can simply update the main project with the result.

$ vim src/main.c (1)
$ git add src/main.c
$ git commit -am 'merged our changes'
Recorded resolution for 'src/main.c'.
[master 9fd905e] merged our changes

$ cd .. (2)
$ git diff (3)
diff --cc DbConnector
index eb41d76,c771610..0000000
--- a/DbConnector
+++ b/DbConnector
@@@ -1,1 -1,1 +1,1 @@@
- Subproject commit eb41d764bccf88be77aced643c13a7fa86714135
 -Subproject commit c77161012afbbe1f58b5053316ead08f4b7e6d1d
++Subproject commit 9fd905e5d7f45a0d4cbc43d1ee550f16a30e825a
$ git add DbConnector (4)

$ git commit -m "Merge Tom's Changes" (5)
[master 10d2c60] Merge Tom's Changes
First we resolve the conflict.

Then we go back to the main project directory.

We can check the SHA-1s again.

Resolve the conflicted submodule entry.

Commit our merge.

It can be a bit confusing, but it’s really not very hard.

Interestingly, there is another case that Git handles. If a merge commit exists in the submodule directory that contains both commits in its history, Git will suggest it to you as a possible solution. It sees that at some point in the submodule project, someone merged branches containing these two commits, so maybe you’ll want that one.

This is why the error message from before was “merge following commits not found”, because it could not do this. It’s confusing because who would expect it to try to do this?

If it does find a single acceptable merge commit, you’ll see something like this:

$ git merge origin/master
warning: Failed to merge submodule DbConnector (not fast-forward)
Found a possible merge resolution for the submodule:
 9fd905e5d7f45a0d4cbc43d1ee550f16a30e825a: > merged our changes
If this is correct simply add it to the index for example
by using:

  git update-index --cacheinfo 160000 9fd905e5d7f45a0d4cbc43d1ee550f16a30e825a "DbConnector"

which will accept this suggestion.
Auto-merging DbConnector
CONFLICT (submodule): Merge conflict in DbConnector
Automatic merge failed; fix conflicts and then commit the result.
The suggested command Git is providing will update the index as though you had run git add (which clears the conflict), then commit. You probably shouldn’t do this though. You can just as easily go into the submodule directory, see what the difference is, fast-forward to this commit, test it properly, and then commit it.

$ cd DbConnector/
$ git merge 9fd905e
Updating eb41d76..9fd905e
Fast-forward

$ cd ..
$ git add DbConnector
$ git commit -am 'Fast forward to a common submodule child'
This accomplishes the same thing, but at least this way you can verify that it works and you have the code in your submodule directory when you’re done.

Submodule Tips
There are a few things you can do to make working with submodules a little easier.

Submodule Foreach
There is a foreach submodule command to run some arbitrary command in each submodule. This can be really helpful if you have a number of submodules in the same project.

For example, let’s say we want to start a new feature or do a bugfix and we have work going on in several submodules. We can easily stash all the work in all our submodules.

$ git submodule foreach 'git stash'
Entering 'CryptoLibrary'
No local changes to save
Entering 'DbConnector'
Saved working directory and index state WIP on stable: 82d2ad3 Merge from origin/stable
HEAD is now at 82d2ad3 Merge from origin/stable
Then we can create a new branch and switch to it in all our submodules.

$ git submodule foreach 'git checkout -b featureA'
Entering 'CryptoLibrary'
Switched to a new branch 'featureA'
Entering 'DbConnector'
Switched to a new branch 'featureA'
You get the idea. One really useful thing you can do is produce a nice unified diff of what is changed in your main project and all your subprojects as well.

$ git diff; git submodule foreach 'git diff'
Submodule DbConnector contains modified content
diff --git a/src/main.c b/src/main.c
index 210f1ae..1f0acdc 100644
--- a/src/main.c
+++ b/src/main.c
@@ -245,6 +245,8 @@ static int handle_alias(int *argcp, const char ***argv)

      commit_pager_choice();

+     url = url_decode(url_orig);
+
      /* build alias_argv */
      alias_argv = xmalloc(sizeof(*alias_argv) * (argc + 1));
      alias_argv[0] = alias_string + 1;
Entering 'DbConnector'
diff --git a/src/db.c b/src/db.c
index 1aaefb6..5297645 100644
--- a/src/db.c
+++ b/src/db.c
@@ -93,6 +93,11 @@ char *url_decode_mem(const char *url, int len)
        return url_decode_internal(&url, len, NULL, &out, 0);
 }

+char *url_decode(const char *url)
+{
+       return url_decode_mem(url, strlen(url));
+}
+
 char *url_decode_parameter_name(const char **query)
 {
        struct strbuf out = STRBUF_INIT;
Here we can see that we’re defining a function in a submodule and calling it in the main project. This is obviously a simplified example, but hopefully it gives you an idea of how this may be useful.

Useful Aliases
You may want to set up some aliases for some of these commands as they can be quite long and you can’t set configuration options for most of them to make them defaults. We covered setting up Git aliases in Git Aliases, but here is an example of what you may want to set up if you plan on working with submodules in Git a lot.

$ git config alias.sdiff '!'"git diff && git submodule foreach 'git diff'"
$ git config alias.spush 'push --recurse-submodules=on-demand'
$ git config alias.supdate 'submodule update --remote --merge'
This way you can simply run git supdate when you want to update your submodules, or git spush to push with submodule dependency checking.

Issues with Submodules
Using submodules isn’t without hiccups, however.

Switching branches
For instance, switching branches with submodules in them can also be tricky with Git versions older than Git 2.13. If you create a new branch, add a submodule there, and then switch back to a branch without that submodule, you still have the submodule directory as an untracked directory:

$ git --version
git version 2.12.2

$ git checkout -b add-crypto
Switched to a new branch 'add-crypto'

$ git submodule add https://github.com/chaconinc/CryptoLibrary
Cloning into 'CryptoLibrary'...
...

$ git commit -am 'Add crypto library'
[add-crypto 4445836] Add crypto library
 2 files changed, 4 insertions(+)
 create mode 160000 CryptoLibrary

$ git checkout master
warning: unable to rmdir CryptoLibrary: Directory not empty
Switched to branch 'master'
Your branch is up-to-date with 'origin/master'.

$ git status
On branch master
Your branch is up-to-date with 'origin/master'.

Untracked files:
  (use "git add <file>..." to include in what will be committed)

	CryptoLibrary/

nothing added to commit but untracked files present (use "git add" to track)
Removing the directory isn’t difficult, but it can be a bit confusing to have that in there. If you do remove it and then switch back to the branch that has that submodule, you will need to run submodule update --init to repopulate it.

$ git clean -ffdx
Removing CryptoLibrary/

$ git checkout add-crypto
Switched to branch 'add-crypto'

$ ls CryptoLibrary/

$ git submodule update --init
Submodule path 'CryptoLibrary': checked out 'b8dda6aa182ea4464f3f3264b11e0268545172af'

$ ls CryptoLibrary/
Makefile	includes	scripts		src
Again, not really very difficult, but it can be a little confusing.

Newer Git versions (Git >= 2.13) simplify all this by adding the --recurse-submodules flag to the git checkout command, which takes care of placing the submodules in the right state for the branch we are switching to.

$ git --version
git version 2.13.3

$ git checkout -b add-crypto
Switched to a new branch 'add-crypto'

$ git submodule add https://github.com/chaconinc/CryptoLibrary
Cloning into 'CryptoLibrary'...
...

$ git commit -am 'Add crypto library'
[add-crypto 4445836] Add crypto library
 2 files changed, 4 insertions(+)
 create mode 160000 CryptoLibrary

$ git checkout --recurse-submodules master
Switched to branch 'master'
Your branch is up-to-date with 'origin/master'.

$ git status
On branch master
Your branch is up-to-date with 'origin/master'.

nothing to commit, working tree clean
Using the --recurse-submodules flag of git checkout can also be useful when you work on several branches in the superproject, each having your submodule pointing at different commits. Indeed, if you switch between branches that record the submodule at different commits, upon executing git status the submodule will appear as “modified”, and indicate “new commits”. That is because the submodule state is by default not carried over when switching branches.

This can be really confusing, so it’s a good idea to always git checkout --recurse-submodules when your project has submodules. For older Git versions that do not have the --recurse-submodules flag, after the checkout you can use git submodule update --init --recursive to put the submodules in the right state.

Luckily, you can tell Git (>=2.14) to always use the --recurse-submodules flag by setting the configuration option submodule.recurse: git config submodule.recurse true. As noted above, this will also make Git recurse into submodules for every command that has a --recurse-submodules option (except git clone).

Switching from subdirectories to submodules
The other main caveat that many people run into involves switching from subdirectories to submodules. If you’ve been tracking files in your project and you want to move them out into a submodule, you must be careful or Git will get angry at you. Assume that you have files in a subdirectory of your project, and you want to switch it to a submodule. If you delete the subdirectory and then run submodule add, Git yells at you:

$ rm -Rf CryptoLibrary/
$ git submodule add https://github.com/chaconinc/CryptoLibrary
'CryptoLibrary' already exists in the index
You have to unstage the CryptoLibrary directory first. Then you can add the submodule:

$ git rm -r CryptoLibrary
$ git submodule add https://github.com/chaconinc/CryptoLibrary
Cloning into 'CryptoLibrary'...
remote: Counting objects: 11, done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 11 (delta 0), reused 11 (delta 0)
Unpacking objects: 100% (11/11), done.
Checking connectivity... done.
Now suppose you did that in a branch. If you try to switch back to a branch where those files are still in the actual tree rather than a submodule — you get this error:

$ git checkout master
error: The following untracked working tree files would be overwritten by checkout:
  CryptoLibrary/Makefile
  CryptoLibrary/includes/crypto.h
  ...
Please move or remove them before you can switch branches.
Aborting
You can force it to switch with checkout -f, but be careful that you don’t have unsaved changes in there as they could be overwritten with that command.

$ git checkout -f master
warning: unable to rmdir CryptoLibrary: Directory not empty
Switched to branch 'master'
Then, when you switch back, you get an empty CryptoLibrary directory for some reason and git submodule update may not fix it either. You may need to go into your submodule directory and run a git checkout . to get all your files back. You could run this in a submodule foreach script to run it for multiple submodules.

It’s important to note that submodules these days keep all their Git data in the top project’s .git directory, so unlike much older versions of Git, destroying a submodule directory won’t lose any commits or branches that you had.

With these tools, submodules can be a fairly simple and effective method for developing on several related but still separate projects simultaneously.
