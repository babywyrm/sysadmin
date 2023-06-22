
##
#
https://linux.how2shout.com/how-to-install-winehq-on-ubuntu-22-04-lts-jammy/
#
##

How to install WineHQ on Ubuntu 22.04 LTS Jammy
Last Updated on: February 2, 2023 by Heyan Maurya
Learn the commands to install WineHQ on Ubuntu 22.04 LTS Jammy JellyFish. If you don’t know about Wine then it stands for Wine Is Not an Emulator, a program that allows us to use Windows software on Linux. You do not need a Windows installation on your computer to start programs programmed for Windows with Wine.

How well does Wine work?

Programs that date back to the Windows 95/98 era, but also many programs for Windows 2000 and XP, usually work splendidly. The newer and more complex the program, the more likely problems are. Many games work (see also PlayOnLinux), especially those that use older DirectX versions or even OpenGL. Development is currently progressing very rapidly. With the current version, many games and programs can be used without problems that only a few weeks ago did not run or only ran with tricks.

Depending on the Windows program that is executed with the help of Wine, the demand for resources (primarily CPU power and available RAM) is very moderate to very high. Unfortunately, no general statement can be made here as to which program runs “smoothly” and which does not.

Windows programs that can be run with Wine, but which require many special Wine settings or extensions in addition to the normal installation, are installed in a separate Wine environment so as not to affect other Windows programs. This is especially true for many games.

On the Page  hide 
Steps to install Wine on Ubuntu 22.04 LTS Jammy JellyFish
1. Enable 32-bit architecture
2. Add WineHQ repository on Ubuntu 22.04
3. Download and add the repository key
4. Run APT update
5. Install Wine on Ubuntu 22.04 LTS
6. Setup Wine
Wine Configuration on Ubuntu 22.04
Steps to install Wine on Ubuntu 22.04 LTS Jammy JellyFish
1. Enable 32-bit architecture
Many apps still support 32-bit architecture hence will not work correctly on 64-bit systems. Thus, if your system is 64-bit, first enable the 32-bit architecture support using the below command:

sudo dpkg --add-architecture i386
2. Add WineHQ repository on Ubuntu 22.04
Wine is already present in the official repository to install easily using the APT package manager of Ubuntu 22.04. However, the version will not be the latest one. Hence, to get the current version and future updates for Wine, let’s manually add the WineHQ repository officially published by the developers of this program.

Here is the command to add the one meant for Ubuntu 22.04:

Download using wget:

sudo apt install wget
wget -nc https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources
Move it source directory:

sudo mv winehq-jammy.sources /etc/apt/sources.list.d/
3. Download and add the repository key
Now, we also have to add the GPG key used by the developers of Wine to sign its packages. This lets our system confirm the packages we get via the newly added repo are from the source as published by its developers without any modification.

sudo mkdir -pm755 /etc/apt/keyrings

sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
4. Run APT update
Well, after adding the repository the system needs to rebuild the APT package manager cache so that it could recognize the latest packages available through it.

sudo apt update
5. Install Wine on Ubuntu 22.04 LTS
We have already configured all the things we needed to get the latest version of Wine. Next, install it using APT as we do for any other software on Ubuntu 22.04.

If you need the stable version, use this command:

sudo apt install --install-recommends winehq-stable
For staging branch

sudo apt install --install-recommends winehq-staging
Those who are developers and want to experience the development branch packages can use:

sudo apt install --install-recommends winehq-devel
Note: While writing this article the “stable” package of Wine was not available, hence if the same is for you then go for the developer package.

To check the version:

wine --version
6. Setup Wine
Configure Wine environment for Windows applications you can set it to 64-bit as well as 32-bit according to the software you want to install. Here we are setting it to 32-bit.

export WINEARCH=win32
export WINEPREFIX=~/.wine32
winecfg
The winecfg command will open the Wine Configuration window, however, it would say “Wine could not find wine-mono packages” and then allow it to install that along with others. Because we need these packages for the .NET framework-based application.

Install WineHQ on Ubuntu 22.04 LTS
Wine Configuration on Ubuntu 22.04
Select the Windows version which you want to default on your Linux system from the dropdown box. Graphics, themes, screen resolution, and more…

Wine Configuration
To install any Windows Application on Linux using the WINE. Just navigate to that directory-> Open the command terminal there and run:

wine setupfilename.exe

Note: Replace the setupfilename.exe with the executable file of that Windows software you want to install. I have successfully installed Adobe Acrobat on my Ubuntu system using the WINE open source.

Other Articles:

• Install Adobe Photoshop CS6 using Wine on Ubuntu
• 6 Linux distributions to revive an old laptop
• Install Ubuntu 22.04 Jammy alongside Windows 11
• Dual Boot Ubuntu 22.04 Jammy alongside Windows 10

CategoriesUbuntu
TagsUbuntu 22.04, Wine, winehq
How to install AnyDesk on Mx linux
How to install Anaconda on Ubuntu 22.04 LTS Jammy
You Might Also Like:
How to Search For a File in Ubuntu 22.04 or 20.04 Terminal

How to Search For a File in Ubuntu 22.04 or 20.04 Terminal
4 Different commands to Shutdown or Restart Ubuntu Linux

4 Different commands to Shutdown or Restart Ubuntu Linux
How to install FF in Ubuntu Linux?

How to install FF in Ubuntu Linux?
How to install default Ubuntu 22.04’s desktop environment?

How to install default Ubuntu 22.04’s desktop environment?
2 ways to install Element Desktop Client on Ubuntu 22.04 | 20.04

2 ways to install Element Desktop Client on Ubuntu 22.04 | 20.04
Installing Flask on Ubuntu 22.04 or 20.04 LTS Linux

Installing Flask on Ubuntu 22.04 or 20.04 LTS Linux
3 thoughts on “How to install WineHQ on Ubuntu 22.04 LTS Jammy”

kerrjnr
June 4, 2022 at 7:36 am
The correct sources appear to be “wine-xxx”, not “winehq-xxx”.

Reply

kath
July 30, 2022 at 9:32 am
Interesting to read how OP managed to install wine-stable for jammy, while it is (to date of this comment) no available on the servers of WineHQ. Can OP help us understand how we can mitigate that too?

Reply

Piotr
August 4, 2022 at 11:22 am
When installing in cmd line, use “wine” and not “winehq”:
sudo apt install –install-recommends wine-stable

Thank you for the tutorial

Reply
