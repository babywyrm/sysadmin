
##
#
https://wiki.alpinelinux.org/wiki/APKBUILD_examples:JavaScript
#
https://superuser.com/questions/1125969/how-to-install-npm-in-alpine-linux
#
##



APKBUILD examples:JavaScript

    Page
    Discussion

    Read
    View source
    View history

This material is work-in-progress ...

Alternate message.
(Last edited by Orson Teodoro on 3 Mar 2018.)

Packaging JavaScript based apps is easy as long as there is no heavy dependencies that may break on musl. Currently Electron based GUI apps are not supported but a wide range of command line apps are available on Linux which can be packaged for use for Alpine users.

Because there are literally hundreds of dependencies for a Node.js application, it makes more sense to just keep them all internal dependencies except those that require special patching. We are going to just cover the trivial packages easy packages for now.

Again, only package applications not Node.js libraries, but only if the Node.js package requires patching on musl.
Requirements

    Node.js -- nodejs
    npm -- nodejs-npm
    A open source project with a package.json file in the root or in the app folder

Which archive to get?

You still want to grab the archive file (.zip, .tar.gz, ...). Do not use npm install $pkgname@$pkgver. If the archive doesn't exist, then you can use that command in snapshot().
Global variables

 depends="nodejs-npm"

Build

In this step we tell npm to get the dependencies and build the binary dependencies if any. These dependencies will be placed in a folder called node_modules in the same directory as the package.json. You may need to do this repetitively at the root level and in the app folder if any, or wherever you see a package.json file without a node_modules.

 build() {
       cd "$builddir"
       npm install
 }

Package

This is a simple example without documentation. You need to package the bin folder, the package*.json file, and the lib folder. There may be other files that need to be packaged. All apps should be placed in the "$pkgdir"/usr/lib/node_modules/$pkgname to make them visible for other nodejs programs or to keep track of the npm dependencies for CVE check for future tool.

You also want to place symlinks for some programs but not all because there is some overlap between npm apps for compatibility reasons and the native apps. Only symlink the main or major programs not the dependencies.

 package() {
       cd "$builddir"
       install -d "$pkgdir"/usr/share/doc/$pkgname "$pkgdir"/usr/lib/node_modules/$pkgname
       cp -a bin lib node_modules package*.json "$pkgdir"/usr/lib/node_modules/$pkgname
       ln -s /usr/lib/node_modules/$pkgname/bin/$pkgname "$pkgdir"/usr/bin
 }

Testing

 check() {
       cd "$builddir"
       npm test
 }

Licensing

Since you are packaging the dependencies and the app under one package, you should list all the licenses for those dependencies in the license field. Use grep and find to find them.
Security updates

In an event of a CVE notice and a update to fix that CVE for a npm dependency, you need to rebuild the package(s) and increment the pkgrel. 




How to install npm in alpine linux
Asked 7 years, 5 months ago
Modified 6 months ago
Viewed 340k times
167

So I can't get to install npm in alpine linux. I thought perhaps I can just do a apk add npm but apparently apk search npm returns nothing, even after a apk update. I'm experimenting with all this from the nginx:alpine docker image, i.e. docker run -it nginx:alpine /bin/sh

Edit 1: I can see how the nodejs:alpine dockerfile builds node, but I don't understand how it builds npm

Edit 2: now that I know that npm gets installed with nodejs on alpine, and just for clarification, the reason this wasn't evident to me at first is that on ubuntu 14.04 a sudo apt-get install nodejs would still require a sudo apt-get install npm (which installs development packages e.g. gcc)

    linuxalpine-linux

Share
Improve this question
Follow
edited Jan 9, 2017 at 3:40
asked Sep 19, 2016 at 15:20
Shadi's user avatar
Shadi
1,91533 gold badges1111 silver badges1010 bronze badges
Add a comment
9 Answers
Sorted by:
196

For the recent versions of Alpine (v3.8+) the correct way to install nodejs with npm is:

apk add --update nodejs npm

However, npm package depends on nodejs, so you can do:

apk add --update npm

Note: since Alpine 3.8 there is no nodejs-npm package.
Share
Improve this answer
Follow
answered Apr 13, 2019 at 7:58
Ruslan Isay's user avatar
Ruslan Isay
2,07611 gold badge77 silver badges33 bronze badges

    6
    How do we install a specific version of nodejs? – 
    JollyRoger
    Oct 29, 2020 at 14:26
    9
    @JollyRoger specify the version to the apk command apk add --update nodejs=12.20.1-r0 – 
    eemelipa
    Jan 10, 2021 at 7:13 

    1
    @S.SaeidHosseini could you elaborate a bit more why specifying exact version is not good idea with containers? – 
    eemelipa
    Jan 13, 2022 at 10:18
    1
    @eemelipa since not all versions of node.js will be available through alpine repositories forever, you'll need to continuously update your Dockerfile with the latest available version, to docker/CI build errors. – 
    Saeid Hosseini
    Jan 23, 2022 at 9:38
    2
    In 2022, apk add --update nodejs npm works for me. – 
    Eyong Kevin Enowanyo
    Jul 25, 2022 at 16:01

Show 1 more comment
205

I had an issue with the apk manager.

The package nodejs is no longer installing NPM (see pkgs.alpinelinux.org) You have to install nodejs-npm

apk add --update nodejs nodejs-npm

Share
Improve this answer
Follow
edited Aug 13, 2017 at 9:03
Panthro's user avatar
Panthro
10333 bronze badges
answered Mar 10, 2017 at 10:40
Faisal HUSSAIN's user avatar
Faisal HUSSAIN
2,15122 gold badges99 silver badges22 bronze badges

    3
    I do not understand it. Npm should be the core dependency of node, npm install npm@latest might be impacted by the node version itself so they would not be compatible... – 
    dmi3y
    May 30, 2017 at 19:47 

6
This should be the accepted answer with the latest alpine image. npm was not installed for me with just nodejs – 
kevinc
Jul 29, 2017 at 15:35
1
Agreed, this is normally a dependency, but if you're installing nodejs manually (I was installing it from the 'edge' repo as well because as of now 6.7 is deprecated) then you need to install nodejs-npm separately Here's what I ran: apk add nodejs=6.11.2-r0 nodejs-npm=6.11.2-r0 --update-cache --repository dl-cdn.alpinelinux.org/alpine/edge/main --allow-untrusted – 
Anton Babushkin
Aug 22, 2017 at 23:53

    8
    Side question: while this answer works just fine, I can't seem to find nodejs-npm on pkgs.alpinelinux.org/packages. There is npm package which also does the job. Is it some kind of alias? – 
    Tad Lispy
    Jul 25, 2018 at 14:28
    4
    nodejs-npm is no longer available, now it's just "npm" pkgs.alpinelinux.org/package/v3.14/main/x86_64/npm – 
    BotanMan
    Jul 7, 2021 at 9:33

Show 1 more comment
31

I could be wrong, but I think npm is actually a dependency of nodejs.

I've never seen any flavor of package manager install npm alone. Always seems to come packaged with yum install nodejs, or apt-get install nodejs, or apk add --update nodejs.
Share
Improve this answer
Follow
edited Dec 30, 2016 at 21:01
Kamil Maciorowski's user avatar
Kamil Maciorowski
73.6k2222 gold badges142142 silver badges218218 bronze badges
answered Dec 30, 2016 at 20:50
Joseph Roberts's user avatar
Joseph Roberts
42755 silver badges33 bronze badges

    20
    this is no longer accepted, as apk does not installs npm by default when installing nodejs – 
    Panthro
    Aug 12, 2017 at 22:52
    upvoted just because nobody provided a better answer – 
    Alexander Mills
    Aug 31, 2017 at 1:01
    1
    I believe it is 'apk add --update nodejs-npm' for Alpine 3.6+ – 
    Ali Cheaito
    Feb 13, 2019 at 15:14
    npm isn't a dependency of nodejs. Some using node might prefer to use yarn instead as package manager. – 
    cefigueiredo
    Nov 26, 2020 at 17:15

Add a comment
9

apk update && apk add nodejs installed the npm binary for me.
Share
Improve this answer
Follow
answered Jan 6, 2017 at 11:39
John Delaney's user avatar
John Delaney
9111 silver badge11 bronze badge

    3
    Disputing if something works should include versions of things... – 
    Eric Swanson
    Jan 3, 2019 at 22:00

Add a comment
5

The issue here is a recent one and is due to changes in Alpine's package repositories between v3.5 and v3.6 or edge.

In v3.5 nodejs included npm In v3.6 nodesjs does not include npm and the new nodejs-npm package exists.

See here for Alpine packages. To see what version of packages you are pulling from look at the contents of /etc/apk/repositories
Share
Improve this answer
Follow
answered Nov 1, 2017 at 23:14
Peter's user avatar
Peter
5111 silver badge11 bronze badge
Add a comment
3

npm comes hand in hand with nodejs. In the case you cant install node with apk add nodejs, you need fix that first. Step 1 - do you have the community repo added to your /etc/apk/repositories list? If not, it is very useful to do so. Further details: https://wiki.alpinelinux.org/wiki/Enable_Community_Repository
Share
Improve this answer
Follow
answered Sep 20, 2017 at 4:04
vizmi's user avatar
vizmi
13922 bronze badges

    3
    Can you explain the down vote? – 
    vizmi
    Sep 20, 2017 at 4:20

Add a comment
3

I could successfully install nodejs and npm in alpine Linux with the below commands. Added benefit for this method is we can choose different node version with nvm

```
apk add -U curl bash ca-certificates openssl ncurses coreutils python2 make gcc g++ libgcc linux-headers grep util-linux binutils findutils

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash

export NVM_DIR="$HOME/.nvm"

[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

nvm install -s <version>

For reference visit here
