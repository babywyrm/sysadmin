How to Use truffleHog and git-secrets

https://sweetcode.io/how-use-truffle-hog-git-secrets/




BY WENDY SEGURA2 YEARS AGO
IN APPLICATION DEVELOPMENT
git · tutorial
Git-secrets is a tool released by AWS Labs that will scan commits and commit messages. It lets you scan a file or a folder recursively to look for secrets. This works great for trying to find AWS secrets, such as an AWS Access Key ID and AWS Secret Access Key in your repository.

The second tool is truffleHog. Per their GitHub README, “this module will go through the entire commit history of each branch, and check each diff from each commit, and check for secrets. This is both by regex and by entropy. For entropy checks, truffleHog will evaluate the shannon entropy for both the base64 charset and hexadecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.”

Why does this matter? With GitHub’s “over 28 million users and 57 million repositories making it the largest host of source code in the world,” it makes it an easy target to try and find user keys and passwords. One just needs to go onto GitHub’s toolbar and search — and in seconds, you will come across thousands of commits holding sensitive information. With that being said, you should never commit such things as passwords, or any confidential information. This is equivalent to giving someone your credit card number. Just don’t do it.

Now, on to the good stuff: how to actually use these tools and start scanning your repositories.

Installation:
There are two ways to install — through cloning the repository or using Homebrew.

1) Git Clone:

`git clone https://github.com/awslabs/git-secrets`
`cd git-secrets`
`make install`
2) Homebrew:

`brew install git-secrets`
To Use:
Open up a terminal window and perform the following steps (please note this must be done for every repo you want to use git-secrets with):

`cd /path/to/my/repo`
`git secrets --install`
`git secrets --register-aws`


Git-secrets scanning time — you can run the following commands below. If that does not output anything, it probably means that you have no secrets to reveal.

Helpful Commands
Scan all files in the repo:

`git secrets –-scan`
Scan all files in the repo and all its revisions. Git-secrets recommends you run the following command before making a repository public to prevent any secrets from being leaked:

`git secrets –-scan-history`
Scans a directory recursively for secrets:

`git secrets --scan -r /path/to/directory`
Scans multiple files for secrets:

`git secrets --scan /path/to/file /path/to/other/file`
For more information and documentation on git-secrets, you can click on the link: git-secrets README.
Now, on to the more popularly used scanning tool — truffleHog. This GitHub repository scanner will look into your commit history and spot anything that looks like a password or confidential information using regex and entropy.

To install:
`pip install truffleHog`


To run it against a repository to find the secrets:

`truffleHog --regex --entropy=False </path/to/directory/of/repo>`


Something to note about truffleHog: when using the flag –entropy=False, it can sometimes cause too much signal cancellation. So if you don’t receive any output after you run the command `truffleHog –regex –entropy=False </path/to/directory/of/repo>`, I suggest you try running it without the entropy, like so: `truffleHog –regex </path/to/directory/of/repo>`.

Personally, I’ve preferred using both of the commands above, first with the entropy and then without it. This will help you get a better and bigger picture of any secrets that might be revealed in your repository — seeing which command makes the most sense in terms of output information and whether the information given is really confidential information being leaked, or simply noise.

Helpful Commands
usage: trufflehog [-h] [–json] [–regex] [–rules RULES] [–entropy DO_ENTROPY] [–since_commit SINCE_COMMIT] [–max_depth MAX_DEPTH]

optional arguments:
-h, –help Show this help message and exit
–json Output in JSON
–regex Enable high signal regex checks
–rules RULES Ignore default regexes and source from JSON list file
–entropy DO_ENTROPY Enable entropy checks
–since_commit SINCE_COMMIT
Only scan from a given commit hash
–max_depth MAX_DEPTH
The max commit depth to go back when searching for
secrets

For more information on truffleHog, see this link: truffleHog README

I hope you enjoyed this quick tutorial on how to get started using truffleHog and git-secrets. Remember, it is always important not to push any type of keys or tokens that can compromise your accounts, especially if you are using a public repository — because anyone has access to that information. If you want to learn more on how to encrypt your credentials check out these two links: Vault by HashiCorp, blackbox to help you be on your way to a more secure repository.
