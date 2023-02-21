
##
#
https://stackoverflow.com/questions/1585989/how-to-parse-proc-pid-cmdline
#
##

How to parse /proc/pid/cmdline
Asked 13 years, 4 months ago
Modified 1 year, 8 months ago
Viewed 40k times

23


I'm trying to split the cmdline of a process on Linux but it seems I cannot rely on it to be separated by '\0' characters. Do you know why sometimes the '\0' character is used as separator and sometimes it is a regular space?

Do you know any other ways of retrieving the executable name and the path to it? I have been trying to get this information with 'ps' but it always returns the full command line and the executable name is truncated.

Thanks.

linux
Share
Improve this question
Follow
asked Oct 18, 2009 at 20:46
ryotakatsuki's user avatar
ryotakatsuki
28111 gold badge22 silver badges44 bronze badges
Add a comment
8 Answers
Sorted by:

Highest score (default)

23


use strings

$ cat /proc/self/cmdline | strings -1
cat
/proc/self/cmdline
Share
Improve this answer
Follow
answered Feb 8, 2013 at 1:24
riywo's user avatar
riywo
1,33811 gold badge1111 silver badges1414 bronze badges
For busybox users: cat /proc/self/cmdline | strings -n 1 – 
dubbaluga
 May 31, 2021 at 10:24
Add a comment

20


The /proc/PID/cmdline is always separated by NUL characters.

To understand spaces, execute this command:

cat -v /proc/self/cmdline "a b" "c d e"
EDIT: If you really see spaces where there shouldn't be any, perhaps your executable (intentionally or inadvertently) writes to argv[], or is using setproctitle()?

When the process is started by the kernel, cmdline is NUL-separated, and the kernel code simply copies the range of memory where argv[] was at process startup into the output buffer when you read /proc/PID/cmdline.

Share
Improve this answer
Follow
edited Oct 19, 2009 at 0:39
answered Oct 18, 2009 at 20:53
Employed Russian's user avatar
Employed Russian
192k3131 gold badges289289 silver badges353353 bronze badges
As I said above, while I was explaining the "solution" to a coworker, I realized his cmdlines wasn't behave like I was expecting. We both are using Ubuntu, so I don't know if this is a behavior that can be configured or depends on the Kernel used. – 
ryotakatsuki
 Oct 18, 2009 at 21:26
This is wrong. Sometimes there are spaces separating the arguments - i.e. it's all in argv[0]. I know this because I have see this. – 
camh
 Oct 18, 2009 at 22:23
The mutability of the argument vector by the program is why I objected to your statement. If you hadn't said "always" and emphasised it, I wouldn't have commented. – 
camh
 Oct 19, 2009 at 0:50
Uhm, interesting. I have to check but I believed it happened for all of the processes. I don't remember which was the process I checked. Thanks for the update :) – 
ryotakatsuki
 Oct 19, 2009 at 0:58
I always believed they'd be NUL separated until I found a process where it wasn't. That was postgrey - a perl program using Net::Server which rewrites the command line, all in one argument. – 
camh
 Oct 19, 2009 at 1:02
Show 1 more comment

17


Use

cat /proc/2634/cmdline | tr "\0" " "
to get the args separated by blanks, as you would see it on a command line.

Share
Improve this answer
Follow
answered May 1, 2014 at 18:33
Dag Rende's user avatar
Dag Rende
17911 silver badge33 bronze badges
3
No need to use "cat+tr" when "tr" alone can do it, see @hek2mgl answer. – 
Patrick Allaert
 Feb 23, 2018 at 11:49
Pipe to tr "\0" "\n" if you want each argument on a separate line, which is sometimes useful for readability w/ complex command lines. – 
Per Lundberg
 Jun 17, 2022 at 8:37
Add a comment

14


The command line arguments in /proc/PID/cmdline are separated by null bytes. You can use tr to replace them by new lines:

tr '\0' '\n' < /proc/"$PID"/cmdline
Share
Improve this answer
Follow
answered May 24, 2016 at 9:28
hek2mgl's user avatar
hek2mgl
149k2828 gold badges242242 silver badges263263 bronze badges
3
vendor boxes don't always have 'strings', they often have 'tr'. – 
jouell
 Jun 28, 2019 at 14:44
Add a comment

4


A shot in the dark, but is it possible that \0 is separating terms and spaces are separating words within a term? For example,

myprog "foo bar" baz
might appear in /proc/pid/cmdline as...

/usr/bin/myprog\0foo bar\0baz
Complete guess here, I can't seem to find any spaces on one of my Linux boxes.

Share
Improve this answer
Follow
answered Oct 18, 2009 at 20:52
Jed Smith's user avatar
Jed Smith
15.4k77 gold badges5252 silver badges5959 bronze badges
1
Hi. As you mention, spaces are used to separate words in the same term, this was what I was expecting, but I have access to a machine which is using spaces to separate terms too. It was an Ubuntu, don't know which release. – 
ryotakatsuki
 Oct 18, 2009 at 21:21
Add a comment

2


Have a look at my answer here. It covers what I found when trying to do this myself.

Edit: Have a look at this thread on debian-user for a bash script that tries its best to do what you want (look for version 3 of the script in that thread).

Share
Improve this answer
Follow
edited May 23, 2017 at 12:25
Community's user avatar
CommunityBot
111 silver badge
answered Oct 18, 2009 at 22:26
camh's user avatar
camh
40k1313 gold badges6161 silver badges7070 bronze badges
Hi. I'm already doing something similar to track processes by its path, reading the exe symlink, but the big issue is to get the executable name in the cmd. I mean, usually, when you refer to a process executable you say: "I want the PID of emacs" so you expect to find "emacs", not "/usr/bin/emacs22-gtk" as the exe points to. What I haven't taken into account is the '(Deleted)' string reported by readlink. If I could properly split the information in cmdline I could mix its information with the one provided by the 'exe'. In any case, it seems there is not an evident way :). Thanks! – 
ryotakatsuki
 Oct 18, 2009 at 22:55
I added a link to a thread where I posted a script that contains my implementation. It wont handle an executable name with a space in it, but they're rare (so rare that I've never seen one) – 
camh
 Oct 18, 2009 at 23:23
Add a comment

2


Super-simple (but for only one process, not bulk parsing, etc):

$ cat /proc/self/cmdline "a b" "cd e" | xargs -0
How it works: by default, xargs just echo'es its input, and switch -0 allows it to read null-separated lines rather than newline-separated ones.

Share
Improve this answer
Follow
answered Oct 2, 2018 at 21:32
Anthony's user avatar
Anthony
1,8441616 silver badges2121 bronze badges
Add a comment

0


Executable name:

cat /proc/${pid}/comm
Executable path:

readlink -f /proc/${pid}/exe
If you have a recent bash, you can use mapfile to split the command line into its arguments and put them in an array "command_line" like this:

mapfile -d '' -t command_line < "/proc/${pid}/cmdline"
Much more about /proc/ here: proc(5) — Linux manual page
