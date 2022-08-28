
https://medium.com/swlh/hacking-git-directories-e0e60fa79a36

##
##
#
#
#
##
##

Hacking Git Directories
How to reconstruct source code from an exposed .git directory

Photo by Yancy Min on Unsplash
When attacking an application, obtaining the application’s source code can be extremely helpful for constructing an exploit. This is because some bugs, like SQL injections, are way easier to find using static code analysis compared to black-box testing.

Obtaining an application's source also often means getting a hold of developer comments, hardcoded API keys, and other sensitive data. So the source code of an application should always be protected from public view.

Finding .git directory information leaks
A way that applications accidentally expose source code to the public is through an exposed .git directory.

When a developer uses Git to version control a project’s source code, a git directory (located at project.com/.git) is used to store all the version control information of the project, including the commit history of project files. Normally, the .git folder should not be accessible to the public. But sometimes the .git folder is accidentally made available, and this is when information leaks happen.

To check if an application’s .git folder is exposed, simply go to the application’s root directory, for example project.com, and add /.git to the URL. There are three possibilities that can happen when you browse to the /.git directory:

If you get a 404 error, this means that the .git directory of the application is not made available to the public, and you won’t be able to leak information this way.
If you get a 403 error, the .git directory is available on the server, but you won’t be able to directly access the folder’s root, and therefore will not be able to list all the files contained in the directory.
If you don’t get an error and the server responds with the document tree of the .git directory, you can directly browse the folder’s contents and retrieve any information contained in it.

Photo by Luke Chesser on Unsplash
Reconstructing project source from .git directory
If directory listing is enabled, an attacker can simply browse through the files and retrieve the leaked information. She can also use the wget command in recursive mode (-r) to mass-download the contents of the directory.

> wget -r project.com/.git
But if directory listing is not enabled and the directory’s files are not shown, there are still ways for an attacker to reconstruct the entire .git directory. To understand how this is done, we must first understand the structure of .git directories.

.git directory structure
The .git directory is laid out in a specific way. When you execute the command:

> ls .git
In the command line, you would probably see this:

COMMIT_EDITMSG HEAD branches config description hooks index info logs objects refs
Here are a few standard files and folders in the .git directory that is important in reconstructing the project’s source.

The /objects folder
The /objects directory is used to store Git objects. This directory contains additional folders that each have two character names. These subdirectories are named after the first two characters of the SHA1 hash of the git objects stored in it.

Within these subdirectories, there are files named after the SHA1 hash of the git object stored in it.

For example, the command below will return a list of folders:

> ls .git/objects
00 0a 14 5a 64 6e 82 8c 96 a0 aa b4 be c8 d2 dc e6 f0 fa info pack
And this command will reveal the git objects stored in that particular folder:

> ls .git/objects/0a
082f2656a655c8b0a87956c7bcdc93dfda23f8 4a1ee2f3a3d406411a72e1bea63507560092bd 66452433322af3d319a377415a890c70bbd263 8c20ea4482c6d2b0c9cdaf73d4b05c2c8c44e9 ee44c60c73c5a622bb1733338d3fa964b333f0
0ec99d617a7b78c5466daa1e6317cbd8ee07cc 52113e4f248648117bc4511da04dd4634e6753 72e6850ef963c6aeee4121d38cf9de773865d8 
Git objects are stored in /objects according to the first two characters of their SHA1 hash. For example, the Git object with a hash of 0a082f2656a655c8b0a87956c7bcdc93dfda23f8 will be stored with the file name of 082f2656a655c8b0a87956c7bcdc93dfda23f8 in the directory .git/objects/0a.

Git stores different types of objects in .git/objects. An object stored here could either be a commit, a tree, a blob, and an annotated tag. You can determine the type of an object by using the command:

> git cat-file -t OBJECT-HASH
Commit objects store information about the commit’s directory tree object hash, parent commit, author, committer, date, and message of a commit. Tree objects contain the directory listings for commits. Blob objects contain copies of files that were committed (read: actual source code!). Whereas tag objects contain information about tagged objects and their associated tag names.

You can display the file associated with a Git object by using the command:

> git cat-file -p OBJECT-HASH
The /config file is the Git configuration file for the project.
The /HEAD file is a file that contains a reference to the current branch.
> cat .git/HEAD
ref: refs/heads/master
Confirming that files are accessible
If you are not able to access the .git directory listing, you’ll need to confirm that the folder’s contents are indeed available to the public. You can do this by trying to access the config file of the .git directory.

> curl https://project.com/.git/config
If this file is accessible, you might be able to download the entire contents of the .git directory.

Downloading the files
If you cannot access the /.git folder’s directory listing, you have to download each file you want instead of recursively downloading from the directory root.

But how do you find out which files on the server are available when object files have complex paths such as “.git/objects/0a/72e6850ef963c6aeee4121d38cf9de773865d8”?

You start with file paths that you already know exist, like “.git/HEAD”! Reading this file will give you a reference to the current branch (for example, .git/refs/heads/master) that you can use to find more files on the system.

> cat .git/HEAD
ref: refs/heads/master
> cat .git/refs/heads/master
0a66452433322af3d319a377415a890c70bbd263
> git cat-file -t 0a66452433322af3d319a377415a890c70bbd263
commit
> git cat-file -p 0a66452433322af3d319a377415a890c70bbd263
tree 0a72e6850ef963c6aeee4121d38cf9de773865d8
The .git/refs/heads/master file will point you to the corresponding object hash that stores the directory tree of the commit. From there, you can see that the object is a commit and is associated with a tree object, 0a72e6850ef963c6aeee4121d38cf9de773865d8.

Now when you examine the tree object stored at 0a72e6850ef963c6aeee4121d38cf9de773865d8:

> git cat-file -p 0a72e6850ef963c6aeee4121d38cf9de773865d8
100644 blob 6ad5fb6b9a351a77c396b5f1163cc3b0abcde895 .gitignore
040000 blob 4b66088945aab8b967da07ddd8d3cf8c47a3f53c source.py
040000 blob 9a3227dca45b3977423bb1296bbc312316c2aa0d README
040000 tree 3b1127d12ee43977423bb1296b8900a316c2ee32 resources
Bingo! You discover some source code files and additional object trees to explore.

On a remote server, your requests to discovering the different files would look more like this:

https://project.com/.git/HEAD (to determine the HEAD)
https://project.com/.git/refs/heads/master (to find the object stored in that HEAD)
https://project.com/.git/objects/0a/72e6850ef963c6aeee4121d38cf9de773865d8 (to access the tree associated with the commit)
https://project.com/.git/objects/9a/3227dca45b3977423bb1296bbc312316c2aa0d (to download the source code stored in the README file)
On a remote server like this, you will need to decompress the downloaded object file before you read it. This can be done using Ruby:

ruby -rzlib -e 'print Zlib::Inflate.new.inflate(STDIN.read)' < OBJECT_FILE
Finding useful information
After recovering the project’s source code, you can grep for hardcoded credentials, encryption keys and developer comments for quick wins. You should also look for new and deprecated endpoints and record them for further analysis.

If you have time, you can simply browse through the entire recovered codebase to find potential vulnerabilities. Here’s a guide to reviewing code for security purposes:

Code Review 101
How to perform source code review to find vulnerabilities in web applications
medium.com


##
##
##

    
Enumerate git repository URL from list of URL / User / Org. Friendly to pipeline

This tool is available when the repository, such as github, is included in the bugbounty scope. Sometimes specified as an org name or user name rather than a specific repository, you can use this tool to extract url from all public repositories included in the org/user.

This can be used for various actions such as scanning or cloning for multiple repositories.

🚧 NOTICE
For unauthenticated requests in github api, the rate limit allows for up to 60 requests per hour. Unauthenticated requests are associated with the originating IP address, and not the user making requests. https://docs.github.com/en/rest/overview/resources-in-the-rest-api

So too many tasks can be blocked by the API for a certain time from github. In this case, you can select the appropriate destination or access and use any IP using the torsocks(e.g torsocks gitls -l user.list) or -tor options.

Installation
From go-get
▶ GO111MODULE=on go get -v github.com/hahwul/gitls
Using homebres
▶ brew tap hahwul/gitls
▶ brew install gitls
Using snapcraft
▶ sudo snap install gitls
Usage
Usage of gitls:
  -include-users
    	include repo of org users(member)
  -l string
    	List of targets (e.g -l sample.lst)
  -o string
    	write output file (optional)
  -proxy string
    	using custom proxy
  -tor
    	using tor proxy / localhost:9050
  -version
    	version of gitls
Case Study
Make all repo urls from repo/org/user urls
sample.lst

https://github.com/hahwul
https://github.com/tomnomnom/gron
https://github.com/tomnomnom/httprobe
https://github.com/s0md3v
make repo url list from sample file

▶ gitls -l sample.lst
https://github.com/hahwul/a2sv
https://github.com/hahwul/action-dalfox
https://github.com/hahwul/asset-of-hahwul.com
https://github.com/hahwul/awesome-zap-extensions
https://github.com/hahwul/backbomb
https://github.com/hahwul/booungJS
https://github.com/hahwul/buildpack-nmap
https://github.com/hahwul/buildpack-zap-daemon
https://github.com/hahwul/can-i-protect-xss
https://github.com/hahwul/cyan-snake
https://github.com/hahwul/dalfox
https://github.com/hahwul/DevSecOps
https://github.com/hahwul/droid-hunter
https://github.com/hahwul/exploit-db_to_dokuwiki
https://github.com/hahwul/ftc
https://github.com/hahwul/gitls
https://github.com/hahwul/go-github-selfupdate-patched
https://github.com/hahwul/hack-pet
...snip...
https://github.com/hahwul/zap-cloud-scan
https://github.com/tomnomnom/gron
https://github.com/tomnomnom/httprobe
https://github.com/s0md3v/Arjun
https://github.com/s0md3v/AwesomeXSS
https://github.com/s0md3v/Blazy
https://github.com/s0md3v/Bolt
...snip...
https://github.com/s0md3v/velocity
https://github.com/s0md3v/XSStrike
https://github.com/s0md3v/Zen
https://github.com/s0md3v/zetanize
Get all repository in org and included users(members)
▶ echo https://github.com/paypal | ./gitls -include-users
....
https://github.com/paypal/tech-talks
https://github.com/paypal/TLS-update
https://github.com/paypal/yurita
https://github.com/ahunnargikar
https://github.com/ahunnargikar/docker-chronos-image
https://github.com/ahunnargikar/docker-tomcat7
https://github.com/ahunnargikar/DockerConDemo
https://github.com/ahunnargikar/elasticsearch-registry-backend
https://github.com/ahunnargikar/elasticsearchindex
https://github.com/ahunnargikar/jenkins-dind
https://github.com/ahunnargikar/jenkins-standalone
https://github.com/ahunnargikar/vagrant-mesos
https://github.com/ahunnargikar/vagrant_docker_registry
https://github.com/anandpalanisamy
https://github.com/anilgursel
https://github.com/anilgursel/squbs-sample
https://github.com/bluepnume
Automated testing with gitleaks
▶ gitls -l sample.lst | xargs -I % gitleaks --repo-url=% -v
All clone target's repo
▶ echo "https://github.com/paypal" | gitls | xargs -I % git clone %

##
##
##

# Git cheat sheet

## Common commands

### General

Create repository:

	git init

Add file:

	git add <file>

Remove file:

	git rm <file>

Move or rename file:

	git mv <from> <to>

Commit changes:

	git commit

Show changes:

	git status

Show log:

	git log

Show log with tags:

	git log --decorate

Search thru commit messages:

	git log --grep="<search>"

Add remote repository:

	git remote add origin <url>

### Branches

Show branches:

	git branch

Create branch:

	git branch <branch>

Create and checkout branch:

	git checkout -b <branch>

Checkout branch:

	git checkout <branch>

Rename branch:

	git branch -m <from> <to>

Delete branch:

	git branch -d <branch>

Delete remote branch:

	git push origin :<branch>

Review branch changes:

	git diff <branch>

Merge branch into current:

	git merge <branch>

Resolve merge conflicts:

	mate <file>
	git add <file>
	git commit

Discard branch changes:

	git checkout -f master

### Tags

Show tags:

	git tag

Create tag:

	git tag -a <tag>

Create tag for specific commit:

	git tag -a <tag> <commit>

Show tag data:

	git show <tag>

Delete tag:

	git tag -d <tag>

Delete remote tag:

	git push origin :refs/tags/<tag>

### Push

Push to master:

	git push origin master

Push with tags:

	git push origin master --tags

### Pull

Fetch from remote repository:

	git fetch origin

Merge remote branch into current:

	git merge origin/master

Fetch and merge into current branch:

	git pull

### Clone

Clone repository:

	git clone <url>

Clone with submodules:

	git clone --recursive <url>

### Submodules

Add submodule to repository:

	git submodule add <url>

Update submodule:

	git submodule update

### Stash

Stash changes:

	git stash

Show stashes:

	git stash list

Restore stash:

	git stash apply

Restore stash and restage files:

	git stash apply --index

Restore specific stash:

	git stash apply <stash>

Remove stash:

	git stash drop <stash>

Restore and remove stash:

	git stash pop

Create branch from stash:

	git stash branch <branch>

## Special

Remove last commit (not pushed):

	git reset --hard HEAD~1

## Misc

Get the number of commits in the current branch:

	git log --pretty=oneline | wc -l

## Configuration

Set name:

	git config --global user.name "<name>"

Set email:

	git config --global user.email "<email>"

Set editor (e.g. TextMate):

	git config --global core.editor "mate -w"

Use colors:

	git config --global color.ui true

