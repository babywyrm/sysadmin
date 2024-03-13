

##
#
https://unix.stackexchange.com/questions/766380/apparmor-error-preventing-removing-aa-repairing-aa-or-install-new-apps-with-apt
#
https://docs.docker.com/engine/security/apparmor/
#
##


```

https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor.d/usr.sbin.apache2

https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor.d/usr.lib.apache2.mpm-prefork.apache2

https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor.d/php-fpm

That's for Ubuntu. You could adapt them.

https://presentations.nordisch.org/apparmor/#/

https://gitlab.com/apparmor/apparmor/-/wikis/Documentation

https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference

```

AppArmor is causing problems with my system. I have AppArmor disabled now because it was preventing me from booting. I am unable to install new apt apps. When I try anyway I get...

E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.

When I run that command I get...

Reloading AppArmor profiles

It just sits there, and until I reboot. When I try to remove AppArmor I get similar message. This is preventing me from adding new apps and from upgrading existing app.

From LSB-RELEASE:

DISTRIB_ID=neon
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="KDE neon 5.27"

What can I do to solve this?

    ubuntuaptapparmor

Share
Improve this question
Follow
edited Jan 9 at 20:10
eyoung100's user avatar
eyoung100
6,2342323 silver badges5353 bronze badges
asked Jan 7 at 18:54
Rick Knight's user avatar
Rick Knight
111 bronze badge

    What is the error when trying to remove AppArmor? I know you say it's similar, but it may help – 
    eyoung100
    Jan 9 at 20:12
    Eyoung100, thank yo for the reply. I don't believe this. I ran "sudo apt purge apparmor" again to remove AppArmor just to get the exact failure message to post here, only this time it seems to have worked. The command completed without error! I'm going to reboot to make sure all is OK. – 
    Rick Knight
    Jan 10 at 17:42
    AppArmor is required, as it replaces SELinux. That was the next step anyhow. What happens, when you try to reinstall it now? – 
    eyoung100
    Jan 10 at 17:45
    I have re-installed AppArmor with "sudo apt update" and then "sudo apt -y install apparmor". Everything appears to go well until it hangs at "Reloading AppArmor profiles". The only way I have been able to stop the process is to close the terminal. Apt also suggests apparmor-profiles-extra apparmor-utils. Any other suggestions? – 
    Rick Knight
    Jan 10 at 20:49
    Get:1 archive.ubuntu.com/ubuntu jammy-updates/main amd64 apparmor amd64 3.0.4-2ubuntu2.3 [595 kB] Fetched 595 kB in 1s (671 kB/s) Preconfiguring packages ... Selecting previously unselected package apparmor. (Reading database ... 325477 files and directories currently installed.) Preparing to unpack .../apparmor_3.0.4-2ubuntu2.3_amd64.deb ... Unpacking apparmor (3.0.4-2ubuntu2.3) ... Setting up apparmor (3.0.4-2ubuntu2.3) ... Created symlink /etc/systemd/system/sysinit.target.wants/apparmor.service → /lib/systemd/system/apparmor.service. Reloading AppArmor profiles – 
    Rick Knight
    Jan 10 at 20:52

Show 2 more comments
2 Answers
Sorted by:
0

Truly disabling AppArmor is a bit tricky, but not especially laborious if you know the order in which to perform the steps. The lynchpin is actually not in userspace at all, but takes place in the kernel command line arguments, specifically the lsm= values which control the activation and order of precedence of the Linux Security Modules.

Start off by getting a reference point for what modules your kernel is loading now by issuing cat /sys/kernel/security/lsm in the terminal, which will likely report something along the lines of lockdown,capability,landlock,yama,apparmor. Now it's time to prepare your system to not get hung up on the absence of AppArmor when you reboot it with the AppArmor LSM removed from the 1sm= argument.

    Review the output of aa-status tp see what AA profiles are active.

    Issue sudo aa-teardown, which should unload all of the profiles that were reported active. Verify that it was successful with another invocation of aa-status once the teardown process exits.

    Instruct your service manager not to load the AppArmor daemon on system start, since that will necessarily fail once your altered the kernel command line to prevent the module from being loaded. Most everybody seems to be using SystemD these days, so this will look something like…

    sudo systemctl stop apparmor.service
    sudo systemctl disable apparmor.service

    You are also free to use sudo systemctl mask apparmor.service in place of the second command (my personal preference), which doesn't just prevent it from running but also prevents all other services from being aware that it is present on the system. Or if you're old school and use rc.d still, this sequence will get the job done just as well.

    sudo invoke-rc.d apparmor stop
    sudo update-rc.d -f apparmor remove

    Decide whether to alter your bootloader configuration now from the running system or by interrupting the boot process and editing the current default kernel command line through the bootloader's interface during startup. Either way, this is where the magic happens. Start by adding apparmor=0 as the very first argument on the kernel command line, then go to wherever the lsm= is specified and remove apparmor from its comma-delimited list that you reviewed at the very beginning of this process. If your current kernel parameters don't specify lsm= anywhere (thus relying on the defaults the kernel was compiled with), feel free to insert it anywhere you like, position doesn't affect this one.

    To be clear, if the output of the earlier cat command was something like lockdown,capability,landlock,yama,apparmor, you would be adding lsm=lockdown,capability,landlock,yama to your kernel command line parameters to remove it from the security stack, which works in concert with having blacklisted the module with apparmor=0 and prevents internal friction at low levels in the system.

Now when your system has booted, you should have an empty output for lsmod | grep apparmor and ps aux | grep -v grep | grep apparmor, confirming that it has been well and truly disabled. Hopefully that will allow your package management task to complete successfully and have you up and running again.
Share
Improve this answer
Follow
answered Jan 11 at 8:19
Peter J. Mello's user avatar
Peter J. Mello
48933 silver badges1717 bronze badges
Add a comment
0
Performing Maintenance

I misread your comments, so before they get too long, I'll post a "progressive answer" as we troubleshoot together. It looks as if the package installs successfully, but the service refuses to load all the profiles. Let's start with the steps below:

    Now that the package has installed, let's "move" the service out of the way for now with: sudo systemctl stop apparmor.
    If it successfully stops, issue a sudo systemctl disable apparmor.
    Reboot, to make sure the system doesn't hang.

Now that the service isn't hanging the system, we'll continue...

    Read the AppArmor Entry on the Ubuntu Wiki.
    Perform an update and upgrade: sudo apt update && sudo apt upgrade
        Resolve any issues with the above upgrade and we'll circle back around to 1, which contains pieces of Peter's answer.

I believe we either have a problematic profile, or a problematic application. We'll see if we can find it if your update completes
Preparing Our Troubleshooting Approach

Since we don't know what profile is either faulty, corrupted or cruft, we need to list and test every apparmor profile that's installed. Let's grab a tool to help us prettify our output, and test the APT tool at the same time:

    If you haven't already, add the universe repository with sudo add-apt-repository universe
    Install tree with sudo apt install -y tree
    Issue tree /etc/apparmor.d/ > ~/apparmorProfilesList.txt

Open apparmorProfilesList.txt and count how many we have to check.
Disabling Profiles

Unfortunately, there's no way to disable all profiles at once without a bit of help via scripting. As such, we need to disable each profile listed in your txt file one at a time. Also, after a bit more research, complain mode only reports violations of working profiles. Since yours aren't working complain mode won't help. Therefore, we've no choice but to disable them one by one, and then re-enable one by one. Let me know via comment if this is acceptable because it's going to take awhile to write up.

(Since I received no comments, I'm going to go ahead and finish this answer.)
Approach

My approach to solving this is a bit different from Peter's below in that, I don't want to "turn off" items in a distribution supported kernel. Ubuntu supports LSM's and AppArmor therefore the kernel support should stay enabled. My approach will be as follows:

    Disable the AppArmor SystemD service.
    Move all the AppArmor profiles to the disabled directory
    Restart the AppArmor SystemD service with no profiles loaded. Note this may generate an error, which would be expected, but it shouldn't hang the service.
    Move each profile from Step 2 back into the active profiles directory one at a time, until we find the profile that hangs the SystemD service.
    Report a bug on the offending profile, if any.

Implementing

We can speed up the disabling process with the following script. Editors/Moderators please feel free to edit this script, as I'm nowhere near a BASH pro (Name this disableAllProfiles, and make it executable [+x]):

#!/bin/bash
# NOTE : Quote it else use array to avoid problems #
PROFILES="/etc/apparmor.d/*"
for p in $PROFILES
do
  echo "Processing $p file..."
  # take action on each file. $p stores current profile
  mv -v "$p" /etc/apparmor.d/disable/
done

Issue a ls on both /etc/apparmor.d/ and /etc/apparmor.d/disable. Hint: Disable should have files, it's parent should not. If the hint is correct, continue on. You can now:

    Reenable and restart the SystemD service: systemctl enable apparmor && systemctl start apparmor (This may generate an error as the profile directory is empty).
    Move the first service in the disabled directory back to it's parent /etc/apparmor.d/.
    Reload the service to notify the system that a profile was added: sudo service apparmor reload
    Continue moving profiles, ensuring that step 3 is repeated after each move until you receive the stuck Reloading AppArmor Profiles status. Kill the process and make note of the profile that hung. Put the hung profile back in the disable directory, and continue down the listing, until all the profiles have been put back or disabled.

Bug Reporting

Should everything above complete, you should end up with the profile causing the hang in the disabled directory. Issue the following:

dpkg -S <offending profile>

This should tell us the package the profile belongs to. Use the Ubuntu Launchpad to search for the package. See if there is already a bug related to your profile, or report a new one.

Note: If the above testing approach fails on the first profile or every profile there is something worse going on.
Share
Improve this answer
Follow
edited Jan 22 at 21:49
answered Jan 10 at 21:28
eyoung100's user avatar
eyoung100
6,2342323 silver badges5353 bronze badges

    I was able to run "sudo apt update" successfully. I have KDE Neon so I had to run "sudo apt dist-upgrade" instead of "apt upgrade". Dist-upgrade failed on Reloading AppArmor profiles at 81%. – 
    Rick Knight
    Jan 11 at 19:30
    I just realized there was a typo. That should be apt upgrade without the dash. Either way, it will work out. Let's leave the modules enabled in the lsm, but disable the service again by performing steps 1 and 2. Before doing so, post the output of: sudo aa-status. – 
    eyoung100
    Jan 11 at 20:34
    Right now apt is hung at "Reloading AppArmor profiles". It's been stuck for hours now. I can kill the process. Other than that I'm not sure what to do. – 
    Rick Knight
    Jan 12 at 0:58
    Kill it. One of the profiles is either corrupted or something else. I'll try and help narrow down which one. – 
    eyoung100
    Jan 12 at 16:57
    Ok, I've killed the process. How do we go about identifying the bad/corrupt profile? – 
    Rick Knight
    Jan 12 at 18:19

