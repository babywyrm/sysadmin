My favorite Bash hacks
Improve your productivity with aliases and other shortcuts for the things you forget too often.
By Katie McLaughlin
January 9, 2020 | 9 Comments | 6 min read
Register or Login to like
bash logo on green background
Image by:Opensource.com
When you work with computers all day, it's fantastic to find repeatable commands and tag them for easy use later on. They all sit there, tucked away in ~/.bashrc (or ~/.zshrc for Zsh users), waiting to help improve your day!

In this article, I share some of my favorite of these helper commands for things I forget a lot, in hopes that they will save you, too, some heartache over time.

Say when it's over
When I'm using longer-running commands, I often multitask and then have to go back and check if the action has completed. But not anymore, with this helpful invocation of say (this is on MacOS; change for your local equivalent):

function looooooooong {
    START=$(date +%s.%N)
    $*
    EXIT_CODE=$?
    END=$(date +%s.%N)
    DIFF=$(echo "$END - $START" | bc)
    RES=$(python -c "diff = $DIFF; min = int(diff / 60); print('%s min' % min)")
    result="$1 completed in $RES, exit code $EXIT_CODE."
    echo -e "\n⏰  $result"
    ( say -r 250 $result 2>&1 > /dev/null & )
}
This command marks the start and end time of a command, calculates the minutes it takes, and speaks the command invoked, the time taken, and the exit code. I find this super helpful when a simple console bell just won't do.

Install helpers
I started using Ubuntu back in the Lucid days, and one of the first things I needed to learn was how to install packages. And one of the first aliases I ever added was a helper for this (named based on the memes of the day):

alias canhas="sudo apt-get install -y"
GNU Privacy Guard (GPG) signing
On the off chance I have to sign a GPG email without having an extension or application to do it for me, I drop down into the command line and use these terribly dorky aliases:

alias gibson="gpg --encrypt --sign --armor"
alias ungibson="gpg --decrypt"
Docker
There are many Docker commands, but there are even more docker compose commands. I used to forget the --rm flags, but not anymore with these useful aliases:

alias dc="docker-compose"
alias dcr="docker-compose run --rm"
alias dcb="docker-compose run --rm --build"
gcurl helper for Google Cloud
This one is relatively new to me, but it's heavily documented. gcurl is an alias to ensure you get all the correct flags when using local curl commands with authentication headers when working with Google Cloud APIs. 

Git and ~/.gitignore
I work a lot in Git, so I have a special section dedicated to Git helpers.

One of my most useful helpers is one I use to clone GitHub repos. Instead of having to run:

git clone git@github.com:org/repo /Users/glasnt/git/org/repo
I set up a clone function:

clone(){
    echo Cloning $1 to ~/git/$1
    cd ~/git
    git clone git@github.com:$1 $1
    cd $1
}
Even though I always forget and giggle any time I'm diving into my ~/.bashrc file, I also have my "refresh upstream" command:

alias yoink="git checkout master && git fetch upstream master && git merge upstream/master"
Another helper for Git-ville is a global ignore file. In your git config --global --list you should see a core.excludesfile. If not, create one, and fill it full of things that you always put into your individual .gitignore files. As a Python developer on MacOS, for me this is:

.DS_Store     # macOS clutter
venv/         # I never want to commit my virtualenv
*.egg-info/*  # ... nor any locally compiled packages
__pycache__   # ... or source
*.swp         # ... nor any files open in vim
You can find other suggestions over on Gitignore.io or on the Gitignore repo on GitHub.

Your turn
What are your favorite helper commands? Please share them in the comments.

What to read next
Chat via email
Create fancy text for your social media posts with this Gawk script
Add a little style to your status updates by posting text in script, fraktur, or double-strike characters.


Jim Hall
(Correspondent)
January 6, 2020
Blender Hotkey Cheat Sheet
Bash cheat sheet: Key combos and special syntax
Download our new cheat sheet for Bash commands and shortcuts you need to talk to your computer.


Seth Kenlon
(Team, Red Hat)
November 22, 2019
Woman sitting in front of her laptop
How to port an awk script to Python
Porting an awk script to Python is more about code style than transliteration.


Moshe Zadka
(Correspondent)
November 15, 2019
Tags
SCRIPTING
COMMAND LINE
BASH
WOMEN IN TECH
Katie McLaughlin
User profile image.
Katie has worn many different hats over the years. She has previously been a software developer for many languages, systems administrator for multiple operating systems, and speaker on many different topics. When she's not changing the world, she enjoys making cooking, tapestries, and seeing just how well various application stacks handle emoji.
More about me
9 Comments
These comments are closed, however you can Register or Login to post a comment on another article.
Avatar
Rahul Das | January 9, 2020
Register or Login to like
Those aliases were definitely the highlight of my day! yoink indeed ?

Avatar
Victorhck
| January 9, 2020
Register or Login to like
I liked the "yoink" ! :)
one of my alias: alias untar='tar -zxvf '
bc you know not alway can remember the right options :)
https://www.xkcd.com/1168/

Happy hacking!

Avatar
Sean
| January 10, 2020
Register or Login to like
Get all my HomeBrew stuff updated and cleaned up:

alias buu=‘brew update && brew upgrade && brew cleanup’

Make Terminal recognize any updates I’ve made without closing and reopening the window:

alias tsrc=‘source ~/.bash_profile’

Avatar
laundmo | January 10, 2020
Register or Login to like
alias editenv='sudo -H nano /etc/environment'
alias editalias='sudo nano ~/.bash_aliases'
alias sourcealias='source ~/.bash_aliases'

cuz dumb me forgets the locations of these

killscreen() {
screen -X -S "$1" quit
screen -ls
}

i can never remember the correct args for killing a screen

docker-sh() {
docker exec -it $1 /bin/bash
}

bash into a docker, i do it often enough to make me bot want to type that out

composeup() {
docker-compose --compatibility up -d
}

some of my compose files require compatibility, with this i never forget

alias vi='nano'
alias vim='nano'

fuck vi/vim

alias python='python3'
alias pip='python3 -m pip'

no i dont want to use python 2

alias gitp='git pull origin master'

another one thats just there to be short

alias ports='netstat -tuplen |sed -n "s/^.*127.0.0.1:\([0-9]*\).*$/\1/p"'
give me all my localhost ports, i use this to check if a port is open to use for a docker service

subdomains(){
for f in /etc/nginx/sites-available/*;do cat $f |tr '\n' ' ' | sed -nE "s/^.*server_name\s (\w*\.\w*.\w*).*proxy_pass.*\:.*\:([0-9]*).*/\2 \1 \n/p"; done
}

this shows all subdomains configured in my avaliable nginx sites and their proxy pass localhost port. usefull for figuring out which container is serving which subdomain

Avatar
Huskie
| January 10, 2020
Register or Login to like
I use something similar for my projects,
alias testdemall='.for script in $(ls | grep '^[0-9]*_.*.sh'); do
echo "Executing script '$script'."
./$script
done'
Got it from the MLL project, and use it for quite alot of lengthy builds with a lot of files.

Avatar
Beni Peled
| January 13, 2020
Register or Login to like
1) Display the current branch in git folders:
git_branch() { git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'; }
export PS1="\u@\h \[\033[32m\]\w\[\033[33m\]\$(git_branch)\[\033[00m\]$ "

2) Alias (log) for a more convenient view of git log:
alias log='git log --decorate=full --date=relative --date-order --format=format:"%C(bold blue)%h%C(reset) - %C(bold green)(%ar)%C(reset) %C(white)%s%C(reset) %C(dim white)- %an%C(reset)%C(bold yellow)%d%C(reset)"'

Avatar
Bob Fahr
| January 21, 2020
Register or Login to like
Great article! espeak can be used in place of say on Linux. Here's an article for espeak on Fedora:
https://fedoramagazine.org/add-speech-fedora-system/

Avatar
The Doctor
| January 21, 2020
Register or Login to like
alias yolo='git commit -am "DEAL WITH IT" && git push -f origin master'

Dorky, but when I'm working in an isolated repo (and not the project repo) and have to run leave the office fast (say, a fire drill), it's nice to have five keys to hit before locking and abandoning my laptop.

##
##
##
