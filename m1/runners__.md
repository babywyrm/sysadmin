https://github.blog/changelog/2023-10-02-github-actions-apple-silicon-m1-macos-runners-are-now-available-in-public-beta/

https://github.blog/changelog/2024-01-30-github-actions-introducing-the-new-m1-macos-runner-available-to-open-source/



https://github.com/hkratz/gha-runner-osx-arm64/pull/2
https://github.com/dotnet/runtime/issues/64103
```
export COMPlus_ReadyToRun=0
git clone https://github.com/hkratz/gha-runner-osx-arm64.git -b macos-arm64
cd gha-runner-osx-arm64/src/
./dev.sh layout
cd ../_layout/
./config.sh --url  {repo-url} --token AA... # use your repo URL and your runner registration token
```




https://gist.github.com/tadhgboyle/a0c859b7d7c0a258593dc00cdc5006cc




    install homebrew if you have not already
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    install qemu
        brew install qemu

    extract the .ova file
        tar -xvf /path/to/ova

    convert the .ova file to a .qcow2 file
        qemu-img convert -O qcow2 /path/to/vdmk /path/to/output/qcow2
        make sure you have the .qcow2 extension in the output path
        there is no output until the processing is complete. it might take up to 5 minutes

    download utm

    make a new virtual machine in utm
        click the + icon on the top menu and then "start from scratch"
        go to the "drives" tab and click "import drive", then select the .qcow2 we just made
        in some cases you might have to disable uefi booting
            click on "system", then "advanced settings", and then unselect "uefi booting"
        by default, preformance is awful. to fix this you should give at least 6gb of RAM, 6 cores and enable mulicore mode
        click "save"

    start the virtual machine and enjoy x86_64 emulation on your m1 mac!
    ```



     How to run on M1 Mac runners? #48854


```
```


# https://github.com/orgs/community/discussions/48854

     
Closed Unanswered
jsoneaday asked this question in Actions
jsoneaday
Mar 1, 2023
Select Topic Area

Question
Body

I am running some actions that have build steps using node-gyp. Node-gyp can build as x86_64 or arm64, but on my runner it is building as x86_64. My runner uses runs-on: macos-12. When I build the same project with the same settings on my M1 dev machine it builds as arm64.

How can I use a MacOS runner image that is M1 compatible?
Replies: 2 comments · 2 replies

jsoref
Mar 6, 2023

You'll probably need to install node yourself, the default appears to be x86_64: actions/setup-node#462

Try using brew?
2 replies
@cbackas
cbackas
Apr 11, 2023

@jsoref I'm confused, macos-12 isn't an ARM runner so what would it matter how you try to install node?

How do you actually tell it to use an M1 runner? The github roadmap was updated yesterday to imply that M1 runners are in public beta and all you need to do is update your runs-on: but it doesn't say what to set it to and I can't find it otherwise.
@jsoref
jsoref
Apr 11, 2023

So, the short of it is that at the time you could have self-hosted on an m1, but then you'd have to tell something you want to install the arm version (e.g. brew).

As for using the m1 runners from github, I'm sure they'll post a blog entry explaining how to select them.
github-actions[bot]
bot
May 9, 2024

🕒 Discussion Activity Reminder 🕒

This Discussion has been labeled as dormant by an automated system for having no activity in the last 60 days. Please consider one the following actions:

1️⃣ Close as Out of Date: If the topic is no longer relevant, close the Discussion as out of date at the bottom of the page.

2️⃣ Provide More Information: Share additional details or context — or let the community know if you've found a solution on your own.

3️⃣ Mark a Reply as Answer: If your question has been answered by a reply, mark the most helpful reply as the solution.

Note: This dormant notification will only apply to Discussions with the Question label. To learn more, see our recent announcement.

Thank you for helping bring this Discussion to a resolution! 💬

