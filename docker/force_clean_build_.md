
##
#
https://stackoverflow.com/questions/35594987/how-to-force-docker-for-a-clean-build-of-an-image
#
##

How to force Docker for a clean build of an image
Asked 8 years, 3 months ago
Modified 1 year, 3 months ago
Viewed 1.5m times
1632

I have build a Docker image from a Docker file using the below command.

$ docker build -t u12_core -f u12_core .
When I am trying to rebuild it with the same command, it's using the build cache like:

Step 1 : FROM ubuntu:12.04
 ---> eb965dfb09d2
Step 2 : MAINTAINER Pavan Gupta <pavan.gupta@gmail.com>
 ---> Using cache
 ---> 4354ccf9dcd8
Step 3 : RUN apt-get update
 ---> Using cache
 ---> bcbca2fcf204
Step 4 : RUN apt-get install -y openjdk-7-jdk
 ---> Using cache
 ---> 103f1a261d44
Step 5 : RUN apt-get install -y openssh-server
 ---> Using cache
 ---> dde41f8d0904
Step 6 : RUN apt-get install -y git-core
 ---> Using cache
 ---> 9be002f08b6a
Step 7 : RUN apt-get install -y build-essential
 ---> Using cache
 ---> a752fd73a698
Step 8 : RUN apt-get install -y logrotate
 ---> Using cache
 ---> 93bca09b509d
Step 9 : RUN apt-get install -y lsb-release
 ---> Using cache
 ---> fd4d10cf18bc
Step 10 : RUN mkdir /var/run/sshd
 ---> Using cache
 ---> 63b4ecc39ff0
Step 11 : RUN echo 'root:root' | chpasswd
 ---> Using cache
 ---> 9532e31518a6
Step 12 : RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
 ---> Using cache
 ---> 47d1660bd544
Step 13 : RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
 ---> Using cache
 ---> d1f97f1c52f7
Step 14 : RUN wget -O aerospike.tgz 'http://aerospike.com/download/server/latest/artifact/ubuntu12'
 ---> Using cache
 ---> bd7dde7a98b9
Step 15 : RUN tar -xvf aerospike.tgz
 ---> Using cache
 ---> 54adaa09921f
Step 16 : RUN dpkg -i aerospike-server-community-*/*.deb
 ---> Using cache
 ---> 11aba013eea5
Step 17 : EXPOSE 22 3000 3001 3002 3003
 ---> Using cache
 ---> e33aaa78a931
Step 18 : CMD /usr/sbin/sshd -D
 ---> Using cache
 ---> 25f5fe70fa84
Successfully built 25f5fe70fa84
The cache shows that aerospike is installed. However, I don't find it inside containers spawn from this image, so I want to rebuild this image without using the cache. How can I force Docker to rebuild a clean image without the cache?

docker
Share
Follow
edited Dec 16, 2021 at 9:03
Cecilya's user avatar
Cecilya
52711 gold badge66 silver badges2323 bronze badges
asked Feb 24, 2016 at 6:37
Pavan Gupta's user avatar
Pavan Gupta
18.7k44 gold badges2323 silver badges2929 bronze badges
30
As an aside, you should generally try to minimize the number of RUN directives. – 
tripleee
 CommentedSep 27, 2017 at 11:29
26
@Ya. It used to be that Docker always created a separate layer for each RUN directive, so a Dockerfile with many RUN directives would consume ginormous amounts of disk space; but this has apparently been improved somewhat in recent versions. – 
tripleee
 CommentedFeb 20, 2019 at 17:02 
When I try docker-compose up -d, where can I use --no-cache? – 
Kid
 CommentedJan 29, 2020 at 1:56
9
@O.o that's not possible. You first have to do docker-compose build --no-cache and then docker-compose up -d – 
Martin Melka
 CommentedMay 5, 2020 at 8:40
At the end of the day, I was being dumb with the --volume option. I was using the wrong path the entire time, thinking the old one was being cached – 
smac89
 CommentedApr 15, 2021 at 3:54
Add a comment
10 Answers
Sorted by:

Highest score (default)
2641

There's a --no-cache option:

docker build --no-cache -t u12_core -f u12_core .
In older versions of Docker you needed to pass --no-cache=true, but this is no longer the case.

Share
Follow
edited Jul 24, 2018 at 15:38
Peter Mortensen's user avatar
Peter Mortensen
31.3k2222 gold badges109109 silver badges132132 bronze badges
answered Feb 24, 2016 at 6:40
Assaf Lavie's user avatar
Assaf Lavie
74.8k3434 gold badges149149 silver badges204204 bronze badges
196
Also note that --no-cache works with docker-compose build. – 
Blackus
 CommentedAug 25, 2017 at 12:53 
97
You might also want to use --pull. This will tell docker to get the latest version of the base image. This is necessary in addition to --no-cache if you already have the base image (ex: ubuntu/latest) and the base image has been updated since you last pulled it. See the docs here. – 
Collin Krawll
 CommentedDec 19, 2018 at 20:39 
8
@CollinKrawll: The --pull option did the trick for me. Just --no-cache, build still broke. Put in --pull as well, build worked! Thank you! – 
Erdős-Bacon
 CommentedApr 5, 2019 at 22:04
2
If someone is calling docker build isn't it assumed that they want to rebuild without the cache? In what use case would someone want to build an image and use a previously built image? <rant> I just lost a day because an earlier build failed silently yet completed "successful" and I was using the broken image not understanding why updates to the build script wasnt working </rant> – 
Jeff
 CommentedMay 24, 2019 at 19:46 
8
@Jeff When you're developing a docker image, docker build will only redo layers/steps that have been modified. If I have five steps, and I add a new step at index 3, the layers associated with step 1 and 2 can be re-used. This greatly speeds up the development process – 
flakes
 CommentedAug 8, 2019 at 16:41
Show 2 more comments
264

In some extreme cases, your only way around recurring build failures is by running:

docker system prune
The command will ask you for your confirmation:

WARNING! This will remove:
    - all stopped containers
    - all volumes not used by at least one container
    - all networks not used by at least one container
    - all images without at least one container associated to them
Are you sure you want to continue? [y/N]
This is of course not a direct answer to the question, but might save some lives... It did save mine.

Share
Follow
edited Nov 23, 2017 at 10:13
Iulian Onofrei's user avatar
Iulian Onofrei
9,4871010 gold badges6868 silver badges117117 bronze badges
answered Jul 14, 2017 at 7:43
Wallace Sidhrée's user avatar
Wallace Sidhrée
11.5k66 gold badges5050 silver badges5858 bronze badges
23
adding -a -f makes it better – 
Ravi
 CommentedOct 4, 2017 at 2:22
1
@IulianOnofrei Works for me, Docker version 17.09.0-ce, build afdb6d4 – 
Per Lundberg
 CommentedNov 23, 2017 at 10:10
5
This is way overkill for this scenario and not a usable answer if you do not want to delete everything. – 
M_dk
 CommentedSep 26, 2019 at 11:16 
51
This will even delete the images of stopped containers, probably something you do not want. Recent versions of docker have the command docker builder prune to clear the cached build layers. Just fell into the trap after blindly copying commands from stack overflow. – 
Evil Azrael
 CommentedNov 24, 2019 at 17:31
5
This doesn't even work as a solution to the problem. – 
Robin Green
 CommentedOct 6, 2020 at 8:31
Show 2 more comments
207

To ensure that your build is completely rebuild, including checking the base image for updates, use the following options when building:

--no-cache - This will force rebuilding of layers already available

--pull - This will trigger a pull of the base image referenced using FROM ensuring you got the latest version.

The full command will therefore look like this:

docker build --pull --no-cache --tag myimage:version .
Same options are available for docker-compose:

docker-compose build --no-cache --pull
Note that if your docker-compose file references an image, the --pull option will not actually pull the image if there is one already.

To force docker-compose to re-pull this, you can run:

docker-compose pull
Share
Follow
edited Oct 31, 2020 at 18:18
answered Sep 26, 2019 at 11:23
M_dk's user avatar
M_dk
2,39411 gold badge1515 silver badges1515 bronze badges
3
Curiously this didn't work for me! – 
jtlz2
 CommentedNov 11, 2022 at 9:50
I had to go via stackoverflow.com/a/58801213/1021819 – 
jtlz2
 CommentedNov 11, 2022 at 9:54
Add a comment
81

The command docker build --no-cache . solved our similar problem.

Our Dockerfile was:

RUN apt-get update
RUN apt-get -y install php5-fpm
But should have been:

RUN apt-get update && apt-get -y install php5-fpm
To prevent caching the update and install separately.

See: Best practices for writing Dockerfiles

Share
Follow
edited Jul 24, 2018 at 15:39
Peter Mortensen's user avatar
Peter Mortensen
31.3k2222 gold badges109109 silver badges132132 bronze badges
answered Dec 13, 2016 at 11:11
Youniteus's user avatar
Youniteus
98366 silver badges44 bronze badges
11
The "should have been" is misleading. If Docker sees that it has a cached copy of RUN apt-get update && apt-get -y install php5-fpm you would still see it get reused with the old contents. – 
tripleee
 CommentedSep 27, 2017 at 11:28
14
Actually it still makes sense to join them, because otherwise if you change the installation line, it will still use the old package cache, which will often have problems if the cache is out of date (usually, files will 404.) – 
John Chadwick
 CommentedJan 24, 2018 at 17:12 
1
But should have been: RUN apt-get update && apt-get -y install php5-fpm && rm -rf /var/lib/apt/lists/* In fact, is best practice to cleanup the apt/lists files before the "closing" of the RUN – 
fiorentinoing
 CommentedMay 11, 2022 at 13:02 
Add a comment
66

Most of information here are correct.
Here a compilation of them and my way of using them.

The idea is to stick to the recommended approach (build specific and no impact on other stored docker objects) and to try the more radical approach (not build specific and with impact on other stored docker objects) when it is not enough.

Recommended approach :

1) Force the execution of each step/instruction in the Dockerfile :

docker build --no-cache 
or with docker-compose build :

docker-compose build --no-cache
We could also combine that to the up sub-command that recreate all containers:

docker-compose build --no-cache &&
docker-compose up -d --force-recreate 
These way don't use cache but for the docker builder and the base image referenced with the FROM instruction.

2) Wipe the docker builder cache (if we use Buildkit we very probably need that) :

docker builder prune -af
3) If we don't want to use the cache of the parent images, we may try to delete them such as :

docker image rm -f fooParentImage
In most of cases, these 3 things are perfectly enough to allow a clean build of our image.
So we should try to stick to that.

More radical approach :

In corner cases where it seems that some objects in the docker cache are still used during the build and that looks repeatable, we should try to understand the cause to be able to wipe the missing part very specifically. If we really don't find a way to rebuild from scratch, there are other ways but it is important to remember that these generally delete much more than it is required. So we should use them with cautious overall when we are not in a local/dev environment.

1) Remove all images without at least one container associated to them :

docker image prune -a
2) Remove many more things :

docker system prune -a
That says :

WARNING! This will remove:
  - all stopped containers
  - all networks not used by at least one container
  - all images without at least one container associated to them
  - all build cache
Using that super delete command may not be enough because it strongly depends on the state of containers (running or not). When that command is not enough, I try to think carefully which docker containers could cause side effects to our docker build and to allow these containers to be exited in order to allow them to be removed with the command.

Share
Follow
answered Feb 9, 2020 at 18:47
davidxxx's user avatar
davidxxx
129k2323 gold badges220220 silver badges223223 bronze badges
docker image prune (without -a) is friendlier and won't nuke all your images you might want. – 
java-addict301
 CommentedJun 3, 2021 at 7:07
Any ideas why I am in an edge case? :( Can give more details as required - but under what circumstances could they occur? – 
jtlz2
 CommentedNov 11, 2022 at 9:52
I had to go via stackoverflow.com/a/58801213/1021819 – 
jtlz2
 CommentedNov 11, 2022 at 9:54
Add a comment
39

With docker-compose try docker-compose up -d --build --force-recreate

Share
Follow
answered Jul 11, 2019 at 15:10
Yash's user avatar
Yash
49144 silver badges22 bronze badges
( docker-compose pull or --pullis necessary to get the base image updated before ) – 
Bash Stack
 CommentedMar 1, 2023 at 14:37 
What is the equivalent of this code with a single container Dockerfile? – 
Ömer An
 CommentedSep 15, 2023 at 2:40
Add a comment
17

I would not recommend using --no-cache in your case.

You are running a couple of installations from step 3 to 9 (I would, by the way, prefer using a one liner) and if you don't want the overhead of re-running these steps each time you are building your image you can modify your Dockerfile with a temporary step prior to your wget instruction.

I use to do something like RUN ls . and change it to RUN ls ./ then RUN ls ./. and so on for each modification done on the tarball retrieved by wget

You can of course do something like RUN echo 'test1' > test && rm test increasing the number in 'test1 for each iteration.

It looks dirty, but as far as I know it's the most efficient way to continue benefiting from the cache system of Docker, which saves time when you have many layers...

Share
Follow
edited Jul 24, 2018 at 15:40
Peter Mortensen's user avatar
Peter Mortensen
31.3k2222 gold badges109109 silver badges132132 bronze badges
answered Jul 12, 2018 at 13:31
Olivier's user avatar
Olivier
2,09233 gold badges2525 silver badges3737 bronze badges
4
The ability to be able to not use the cache after a certain point is a feature requested by many (see github.com/moby/moby/issues/1996 for alternatives for cache busting) – 
leszek.hanusz
 CommentedNov 13, 2018 at 7:31
I had to go via stackoverflow.com/a/58801213/1021819 – 
jtlz2
 CommentedNov 11, 2022 at 9:54
Add a comment
13

sometimes docker build --no-cache and even removing all containers and images on the system does not clear all docker stuffs , in such case you should use docker system prune , to remove all unused containers, networks, images, and volumes. This will remove all cached data, including any dangling images or containers. so to achieve a force fresh build run this commands:

//remove all containers
1- docker rm -f $(docker ps -aq) 

//remove all images
2- docker image rm $(docker images -q)  

/remove all unused containers, networks, images, and volumes
3- docker system prune  /
so now anything related to the docker is gone and docker cache is completely deleted , like you have a fresh docker installation .

Share
Follow
answered Feb 28, 2023 at 11:34
Neo Mn's user avatar
Neo Mn
48955 silver badges1515 bronze badges
Add a comment
5

You can manage the builder cache with docker builder

To clean all the cache with no prompt: docker builder prune -af

Share
Follow
answered Mar 21, 2019 at 16:31
0bel1sk's user avatar
0bel1sk
52555 silver badges55 bronze badges
OP is not using buildkit – 
user3710044
 CommentedAug 18, 2020 at 6:53
Add a comment
-1

GUI-driven approach: Open the docker desktop tool (that usually comes with Docker):

under "Containers / Apps" stop all running instances of that image
under "Images" remove the build image (hover over the box name to get a context menu), eventually also the underlying base image
Share
