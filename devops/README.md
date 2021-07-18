33. Git Bootcamp and Cheat Sheet

Note

This section provides instructions on common tasks in CPython’s workflow. It’s designed to assist new contributors who have some familiarity with git and GitHub.

If you are new to git and GitHub, please become comfortable with these instructions before submitting a pull request. As there are several ways to accomplish these tasks using git and GitHub, this section reflects one method suitable for new contributors. Experienced contributors may desire a different approach.

In this section, we will go over some commonly used Git commands that are relevant to CPython’s workflow.

Note

Setting up git aliases for common tasks can be useful to you. You can get more information about that in git documentation
33.1. Forking CPython GitHub Repository

You will only need to do this once.

    Go to https://github.com/python/cpython.

    Press Fork on the top right.

    When asked where to fork the repository, choose to fork it to your username.

    Your forked CPython repository will be created at https://github.com/<username>/cpython.

33.2. Cloning a Forked CPython Repository

You will only need to do this once. From your command line:

git clone git@github.com:<username>/cpython.git

It is also recommended to configure an upstream remote repository:

cd cpython
git remote add upstream git@github.com:python/cpython.git

You can also use SSH-based or HTTPS-based URLs.
33.3. Listing the Remote Repositories

To list the remote repositories that are configured, along with their URLs:

git remote -v

You should have two remote repositories: origin pointing to your forked CPython repository, and upstream pointing to the official CPython repository:

origin  git@github.com:<username>/cpython.git (fetch)
origin  git@github.com:<username>/cpython.git (push)
upstream        git@github.com:python/cpython.git (fetch)
upstream        git@github.com:python/cpython.git (push)

33.4. Setting Up Your Name and Email Address

git config --global user.name "Your Name"
git config --global user.email your.email@example.com

The --global flag sets these parameters globally while the --local flag sets them only for the current project.
33.5. Enabling autocrlf on Windows

The autocrlf option will fix automatically any Windows-specific line endings. This should be enabled on Windows, since the public repository has a hook which will reject all changesets having the wrong line endings:

git config --global core.autocrlf input

33.6. Creating and Switching Branches

Important

Never commit directly to the main branch.

Create a new branch and switch to it:

# creates a new branch off main and switch to it
git checkout -b <branch-name> main

This is equivalent to:

# create a new branch from main, without checking it out
git branch <branch-name> main
# check out the branch
git checkout <branch-name>

To find the branch you are currently on:

git branch

The current branch will have an asterisk next to the branch name. Note, this will only list all of your local branches.

To list all the branches, including the remote branches:

git branch -a

To switch to a different branch:

git checkout <another-branch-name>

Other releases are just branches in the repository. For example, to work on the 2.7 release from the upstream remote:

git checkout -b 2.7 upstream/2.7

33.7. Deleting Branches

To delete a local branch that you no longer need:

git checkout main
git branch -D <branch-name>

To delete a remote branch:

git push origin -d <branch-name>

You may specify more than one branch for deletion.
33.8. Renaming Branch

The CPython repository’s default branch was renamed from master to main after the Python 3.10b1 release.

If you have a fork on GitHub (as described in Forking CPython GitHub Repository) that was created before the rename, you should visit the GitHub page for your fork to rename the branch there. You only have to do this once. GitHub should provide you with a dialog for this. If it doesn’t (or the dialog was already dismissed), you can rename the branch in your fork manually by following these GitHub instructions

After renaming the branch in your fork, you need to update any local clones as well. This only has to be done once per clone:

git branch -m master main
git fetch origin
git branch -u origin/main main
git remote set-head origin -a

(GitHub also provides these instructions after you rename the branch.)

If you do not have a fork on GitHub, but rather a direct clone of the main repo created before the branch rename, you still have to update your local clones. This still only has to be done once per clone. In that case, you can rename your local branch as follows:

git branch -m master main
git fetch upstream
git branch -u upstream/main main

33.9. Staging and Committing Files

    To show the current changes:

    git status

To stage the files to be included in your commit:

git add <filename1> <filename2>

To commit the files that have been staged (done in step 2):

git commit -m "bpo-XXXX: This is the commit message."

33.10. Reverting Changes

To revert changes to a file that has not been committed yet:

git checkout <filename>

If the change has been committed, and now you want to reset it to whatever the origin is at:

git reset --hard HEAD

33.11. Stashing Changes

To stash away changes that are not ready to be committed yet:

git stash

To re-apply the last stashed change:

git stash pop

33.12. Committing Changes

Add the files you want to commit:

git add <filename>

Commit the files:

git commit -m "<message>"

33.13. Pushing Changes

Once your changes are ready for a review or a pull request, you will need to push them to the remote repository.

git checkout <branch-name>
git push origin <branch-name>

33.14. Creating a Pull Request

    Go to https://github.com/python/cpython.

    Press the New pull request button.

    Click the compare across forks link.

    Select the base repository: python/cpython and base branch: main.

    Select the head repository: <username>/cpython and head branch: the branch containing your changes.

    Press the Create pull request button.

33.15. Updating your CPython Fork

Scenario:

    You forked the CPython repository some time ago.

    Time passes.

    There have been new commits made in the upstream CPython repository.

    Your forked CPython repository is no longer up to date.

    You now want to update your forked CPython repository to be the same as the upstream CPython repository.

Please do not try to solve this by creating a pull request from python:main to <username>:main as the authors of the patches will get notified unnecessarily.

Solution:

git checkout main
git pull upstream main
git push origin main

Note

For the above commands to work, please follow the instructions found in the Get the source code section

Another scenario:

    You created some-branch some time ago.

    Time passes.

    You made some commits to some-branch.

    Meanwhile, there are recent changes from the upstream CPython repository.

    You want to incorporate the recent changes from the upstream CPython repository into some-branch.

Solution:

git checkout some-branch
git fetch upstream
git merge upstream/main
git push origin some-branch

You may see error messages like “CONFLICT” and “Automatic merge failed;” when you run git merge upstream/main.

When it happens, you need to resolve conflict. See these articles about resolving conflicts:

    About merge conflicts

    Resolving a merge conflict using the command line

33.16. Applying a Patch from Mercurial to Git

Scenario:

    A Mercurial patch exists but there is no pull request for it.

Solution:

    Download the patch locally.

    Apply the patch:

    git apply /path/to/issueNNNN-git.patch

If there are errors, update to a revision from when the patch was created and then try the git apply again:

git checkout $(git rev-list -n 1 --before="yyyy-mm-dd hh:mm:ss" main)
git apply /path/to/issueNNNN-git.patch

If the patch still won’t apply, then a patch tool will not be able to apply the patch and it will need to be re-implemented manually.

If the apply was successful, create a new branch and switch to it.

Stage and commit the changes.

If the patch was applied to an old revision, it needs to be updated and merge conflicts need to be resolved:

git rebase main
git mergetool

    Push the changes and open a pull request.

33.17. Downloading Other’s Patches

Scenario:

    A contributor made a pull request to CPython.

    Before merging it, you want to be able to test their changes locally.

On Unix and MacOS, set up the following git alias:

$ git config --global alias.pr '!sh -c "git fetch upstream pull/${1}/head:pr_${1} && git checkout pr_${1}" -'

On Windows, reverse the single (') and double (") quotes:

git config --global alias.pr "!sh -c 'git fetch upstream pull/${1}/head:pr_${1} && git checkout pr_${1}' -"

The alias only needs to be done once. After the alias is set up, you can get a local copy of a pull request as follows:

git pr <pr_number>

Note

hub command line utility makes this workflow very easy. You can check out the branch by hub pr checkout <pr_number> [<branch_name>]. This command configures remote URL for the branch too. So you can git push if the pull request author checked “Allow edits from maintainers” when creating the pull request.
33.18. Accepting and Merging a Pull Request

Pull requests can be accepted and merged by a Python Core Developer.

    At the bottom of the pull request page, click the Squash and merge button.

    Replace the reference to GitHub pull request #NNNN with GH-NNNN. If the title is too long, the pull request number can be added to the message body.

    Adjust and clean up the commit message.

    Example of good commit message:

    bpo-12345: Improve the spam module (GH-777)

    * Add method A to the spam module
    * Update the documentation of the spam module

Example of bad commit message:

bpo-12345: Improve the spam module (#777)

* Improve the spam module
* merge from main
* adjust code based on review comment
* rebased

    Note

    How to Write a Git Commit Message is a nice article describing how to write a good commit message.

    Press the Confirm squash and merge button.

33.19. Backporting Merged Changes

A pull request may need to be backported into one of the maintenance branches after it has been accepted and merged into main. It is usually indicated by the label needs backport to X.Y on the pull request itself.

Use the utility script cherry_picker.py from the core-workflow repository to backport the commit.

The commit hash for backporting is the squashed commit that was merged to the main branch. On the merged pull request, scroll to the bottom of the page. Find the event that says something like:

<core_developer> merged commit <commit_sha1> into python:main <sometime> ago.

By following the link to <commit_sha1>, you will get the full commit hash.

Alternatively, the commit hash can also be obtained by the following git commands:

git fetch upstream
git rev-parse ":/bpo-12345"

The above commands will print out the hash of the commit containing "bpo-12345" as part of the commit message.

When formatting the commit message for a backport commit: leave the original one as is and delete the number of the backport pull request.

Example of good backport commit message:

bpo-12345: Improve the spam module (GH-777)

* Add method A to the spam module
* Update the documentation of the spam module

(cherry picked from commit 62adc55)

Example of bad backport commit message:

bpo-12345: Improve the spam module (GH-777) (#888)

* Add method A to the spam module
* Update the documentation of the spam module

33.20. Editing a Pull Request Prior to Merging

When a pull request submitter has enabled the Allow edits from maintainers option, Python Core Developers may decide to make any remaining edits needed prior to merging themselves, rather than asking the submitter to do them. This can be particularly appropriate when the remaining changes are bookkeeping items like updating Misc/ACKS.

To edit an open pull request that targets main:

    In the pull request page, under the description, there is some information about the contributor’s forked CPython repository and branch name that will be useful later:

    <contributor> wants to merge 1 commit into python:main from <contributor>:<branch_name>

Fetch the pull request, using the git pr alias:

git pr <pr_number>

This will checkout the contributor’s branch at <pr_number>.

Make and commit your changes on the branch. For example, merge in changes made to main since the PR was submitted (any merge commits will be removed by the later Squash and Merge when accepting the change):

git fetch upstream
git merge upstream/main
git add <filename>
git commit -m "<message>"

Push the changes back to the contributor’s PR branch:

git push git@github.com:<contributor>/cpython <pr_number>:<branch_name>

Optionally, delete the PR branch.
