grep all .java files in a directory for a particular string
Asked 14 years ago
Modified 3 years, 1 month ago
Viewed 20k times
13

How would I search all .java files for a simple string (not a regex) in the current directory and all sub-directories on Mac OS X? I just want to print a list of file and directory names that match.

macosmacunixgrep
Share
Improve this question
Follow
edited Aug 6, 2009 at 16:51
John T's user avatar
John T
163k2727 gold badges340340 silver badges347347 bronze badges
asked Jul 15, 2009 at 20:06
John Topley's user avatar
John Topley
1,72833 gold badges1818 silver badges2222 bronze badges
Thanks for asking this so I don't have to. Now I just have to figure out how to exclude ".git" and I'm done for a bit. – 
Dan Rosenstark
 Nov 16, 2010 at 21:13
I think js's answer is more concise, still sucks you have to type out --include, but still. Could probably just write an alias to hide that – 
Craig Tataryn
 Jul 5, 2011 at 16:14
Add a comment
9 Answers
Sorted by:

Highest score (default)
19

And the always popular

find . -name '*.java' | xargs grep -l 'string'
EDIT (by Frank Szczerba):

If you are dealing with filenames or directories that have spaces in them, the safest way to do this is:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
There's always more than one way to do it.

Share
Improve this answer
Follow
edited Aug 13, 2011 at 5:56
Tamara Wijsman's user avatar
Tamara Wijsman
57.1k2727 gold badges185185 silver badges256256 bronze badges
answered Jul 15, 2009 at 20:13
David Mackintosh's user avatar
David Mackintosh
3,93477 gold badges3333 silver badges4242 bronze badges
mdfind is a more OSXy way to do this! – 
user22908
 Oct 10, 2011 at 20:43
Add a comment
11

The traditional UNIX answer would be the one that was accepted for this question:

find . -name '*.java' | xargs grep -l 'string'
This will probably work for Java files, but spaces in filenames are a lot more common on Mac than in the traditional UNIX world. When filenames with spaces are passed through the pipeline above, xargs will interpret the individual words as different names.

What you really want is to nul-separate the names to make the boundaries unambiguous:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
The alternative is to let find run grep for you, as Mark suggests, though that approach is slower if you are searching large numbers of files (as grep is invoked once per file rather than once with the whole list of files).

Share
Improve this answer
Follow
answered Jul 31, 2009 at 15:24
Frank Szczerba's user avatar
Frank Szczerba
51544 silver badges1111 bronze badges
You can also use the "--replace" option in xargs to deal with filenames having spaces in them: ... | xargs --replace grep 'string' '{}' ({} would be replaced by the filename) – 
arathorn
 Aug 6, 2009 at 15:41
1
Modern versions of find (including the one installed on OS X) support "-exec <command> {} +" where the plus sign at the end (instead of \;) tells find to replace {} with "as many pathnames as possible... This is is similar to that of xargs(1)" (from the man page). – 
Doug Harris
 Aug 6, 2009 at 16:23
Add a comment
8

Use the grep that is better than grep, ack:

ack -l --java  "string" 
Share
Improve this answer
Follow
edited Jul 16, 2009 at 6:49
answered Jul 15, 2009 at 20:23
bortzmeyer's user avatar
bortzmeyer
1,1711111 silver badges1111 bronze badges
3
ack isn't installed on Mac OS X by default. – 
John Topley
 Jul 15, 2009 at 20:25
I don't know what "by default" means. On many OS, you choose what you install so it is difficult to find programs which are always present. At a time, a C compiler was always there and Perl was uncommon... – 
bortzmeyer
 Jul 15, 2009 at 20:34
1
It means that it's part of the standard OS install. I have the developer tools installed on my Mac and they don't install ack. You have to install it yourself. If you have it, then it's a nice syntax. – 
John Topley
 Jul 15, 2009 at 20:41
In the case of ack, it's a single Perl program with no module dependencies. If you can "install" programs in your ~/bin directory, then you can just as easily "install" ack. – 
Andy Lester
 May 3, 2010 at 18:53
Add a comment
6

grep -rl --include="*.java" simplestring *
Share
Improve this answer
Follow
edited Jul 6, 2011 at 14:39
answered Aug 6, 2009 at 22:31
js.'s user avatar
js.
17311 silver badge44 bronze badges
2
This seems to be the best answer here - if grep does it all, why use find & xargs? – 
Peter Gibson
 Jul 13, 2010 at 2:05
FYI, given what's asked in the question, it should be small "l" not big "L" in that command – 
Craig Tataryn
 Jul 5, 2011 at 16:18
Craig is right, I corrected my answer. – 
js.
 Jul 6, 2011 at 14:40
Add a comment
4

This will actually use a regex if you want, just stay away from the metacharacters, or escape them, and you can search for strings.

find . -iname "*.java" -exec egrep -il "search string" {} \;
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:10
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
1

Since this is an OSX question, here is a more OSX specific answer.
Skip find and use Spotlight from the command line. Much more powerful!

COMMAND LINE SPOTLIGHT – FIND MEETS GREP

Most people don’t know you can do Spotlight searches from the command line. Why remember all the arcane find and grep options and what not when you can let Spotlight do the work for you. The command line interface to Spotlight is called mdfind. It has all the same power as the GUI Spotlight search and more because it is scriptable at the command line!

Share
Improve this answer
Follow
edited Jun 12, 2020 at 13:48
Community's user avatar
CommunityBot
1
answered Oct 10, 2011 at 20:41
user22908
Add a comment
0

Give this a go:

grep -rl "string" */*java
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:09
dwj's user avatar
dwj
1,44455 gold badges2121 silver badges2626 bronze badges
1
This gives "grep: */*java: No such file or directory" on Mac OS X. – 
John Topley
 Jul 15, 2009 at 20:12
The problem here is that it will only find *.java files one level deep. See Mark Thalman's answer for IMHO the proper way to do it. – 
Ludwig Weinzierl
 Jul 15, 2009 at 20:17
Sorry, not at my Mac. Doesn't the Mac version of grep have the -r (recursive) flag? – 
dwj
 Jul 15, 2009 at 20:36
It does, but that was the output that I got when searching for a string that I know is in the files. – 
John Topley
 Jul 15, 2009 at 20:40
Add a comment
0

You could also use a GUI program like TextWrangler to do a more intuitive search where the options are in the interface.

Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:13
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
0

grep "(your string)" -rl $(find ./ -name "*.java")
If you want to ignore case, replace -rl with -irl. (your string) may also be a regex if you ever see the need.

Share
Improve this answer
Follow
