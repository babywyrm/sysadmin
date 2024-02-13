Delete BASH history on exit for all users
Asked 10 years, 4 months ago
Modified 2 years, 11 months ago
Viewed 4k times
6

Using Red Hat Enterprise Linux is it possible to place a global option that whenever a user exits an SSH connection the BASH history for that user is cleared?

bashrhel
Share
Improve this question
Follow
asked Oct 8, 2013 at 19:41
user2656114's user avatar
user2656114
94944 gold badges1818 silver badges3535 bronze badges
There's not much you can do if the users have customized their bash session to save their history in an arbitrary file. – 
chepner
 Oct 8, 2013 at 20:25
Try setting /etc/bash.bash_logout as I suggest in my answer. – 
lurker
 Oct 8, 2013 at 21:17
None of the below suggested answers work. – 
user2656114
 Nov 18, 2013 at 14:20
Add a comment
5 Answers
Sorted by:

Highest score (default)
1

In the /etc/bash.bash_logout script you can put:

unset HISTFILE
The default for HISTFILE is ~/.bash_history. The user can set this to whatever they wish. If it's not set, the logout process doesn't write the history information that's in RAM to the history file.

Share
Improve this answer
Follow
edited Oct 8, 2013 at 21:12
answered Oct 8, 2013 at 19:48
lurker's user avatar
lurker
57.4k99 gold badges7171 silver badges106106 bronze badges
This would only clear the in-memory history, which doesn't persist after the shell exits anyway. – 
chepner
 Oct 8, 2013 at 20:24
See my answer. There's no guarantee that .bash_history is used to store the history. – 
chepner
 Oct 8, 2013 at 20:38
bash does not have a global logout file by default, although it appears you can enable it at compile time. I don't know if that is executed before or after ~/.bash_logout where available. – 
chepner
 Oct 8, 2013 at 21:14
@chepner I have a fairly "default" installation of Fedora 18 and /etc/bash.bash_logout is operational on my system. I didn't compile the system myself. – 
lurker
 Oct 8, 2013 at 21:16
Looks like it's disabled in the bashs installed on my Mac OS X box, but is enabled on one of my Linux boxes at work. It also appears (which you have probably confirmed) that it is sourced after the user's logout file. – 
chepner
 Oct 8, 2013 at 21:20
Show 2 more comments
1

Put the following in ~/.bash_logout

echo > $HISTFILE
This will erase the saved history for a user at logout, but will keep a useful running history when user is logged-in.

Share
Improve this answer
Follow
answered Mar 15, 2021 at 12:16
elig's user avatar
elig
2,80433 gold badges1616 silver badges2424 bronze badges
Add a comment
0

I know you can manually run

history -c
I think you can put this into your ~/.bash_logout.

Share
Improve this answer
Follow
answered Oct 8, 2013 at 19:47
CS Pei's user avatar
CS Pei
10.9k11 gold badge2828 silver badges4646 bronze badges
Add a comment
0

The user can always save their history to a non-standard file and reload it on the next login, so their isn't much you can do from a global standpoint to stop it.

For example, Bob might put the following in his ~/.bash_login:

HISTFILE=~/my_secret_history_file
Share
Improve this answer
Follow
answered Oct 8, 2013 at 20:29
chepner's user avatar
chepner
509k7373 gold badges548548 silver badges699699 bronze badges
Is it possible globally to set history to /dev/null or something? – 
user2656114
 Oct 8, 2013 at 20:35
No, because the user configuration files are sourced after the global ones. The best you can do is set a policy that history cannot be stored, but there's no technical way to enforce such a policy. – 
chepner
 Oct 8, 2013 at 20:38
Add a comment
0

When needed to let the histories empty - I use symlinking them to /dev/null...

lrwxrwxrwx  1 root root    9 Dez 16 19:10 .ash_history -> /dev/null
lrwxrwxrwx  1 root root    9 Dez 16 19:10 .bash_history -> /dev/null
...then the history of typed commands work only for current session.
Starting a new shell, starting a new empty temporary history.
Symlinking them for normal users to /dev/null have to be done by: root


##
##


Symlinking /dev/null to a user's bash history file is not a recommended approach, as it might lead to unexpected behavior and could potentially cause issues with the user's shell. Instead, it's better to modify the user's shell configuration to disable history or redirect it to /dev/null directly.

To disable history for a specific user, you can add the following line to the user's .bashrc or .bash_profile file:

bash
Copy code
unset HISTFILE
This will prevent the shell from saving the history to a file. Keep in mind that this change will only affect new shell sessions for that user.

If you specifically want to redirect the history file to /dev/null, you can use:

bash
Copy code
export HISTFILE=/dev/null
Again, make sure to apply such changes carefully and consider the potential impact on user experience and system behavior.
