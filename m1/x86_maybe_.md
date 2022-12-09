- install [homebrew](https://brew.sh) if you have not already
  - `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`


- install [qemu](https://formulae.brew.sh/formula/qemu)
  - `brew install qemu`

- extract the `.ova` file
  - `tar -xvf /path/to/ova`

- convert the `.ova` file to a `.qcow2` file
  - `qemu-img convert -O qcow2 /path/to/vdmk /path/to/output/qcow2`
  - *make sure you have the `.qcow2` extension in the output path*
  - *there is no output until the processing is complete. it might take up to 5 minutes*

- download [utm](https://mac.getutm.app/)

- make a new virtual machine in utm
  - click the + icon on the top menu and then "start from scratch"
  - go to the "drives" tab and click "import drive", then select the `.qcow2` we just made
  - in some cases you might have to disable uefi booting
    - click on "system", then "advanced settings", and then unselect "uefi booting"
  - by default, preformance is awful. to fix this you should give at least 6gb of RAM, 6 cores and enable mulicore mode
  - click "save"

- start the virtual machine and enjoy x86_64 emulation on your m1 mac!


##
##
##

@nicholaspshaw
nicholaspshaw commented on Oct 6
Does this actually work? Is it performant even if you have at least 8GB dedicated to it?

@Aberdeener
Author
Aberdeener commented on Oct 6
Does this actually work? Is it performant even if you have at least 8GB dedicated to it?

Yes it works

I had 6gb dedicated to it and it was sluggish but not too awful

@sadn1ck
sadn1ck commented on Oct 29 • 
i dont see a start from scratch from the + top menu, did it change?

EDIT: think i found it, just go custom and skip ISO boot. then edit and add drive

@THEDOBERMANN
THEDOBERMANN commented on Nov 8
Hello @Aberdeener I'm new to UTM, I followed your procedure and when I press the + icon it asks me to choose between emulation end virtualization, whatever I choose it brings me to stuck as shown in the image.

Do you (or anyone) have any suggestion?

Thanks

Screenshot 2022-11-08 alle 18 25 38

@sadn1ck
sadn1ck commented last month
disable UEFI booting in the options

@THEDOBERMANN
THEDOBERMANN commented last month
Hey @sadn1ck thank you a ton for the tip, removing that flag actually got me going through the first step, but afterwards the prompt says "no bootable device". I've tried with all the available drive types but no luck, do you think it could be a problem with the image itself? Consider that it's a RHEL 7 OVA (that now I've converted in .qcow2 as suggested by @Aberdeener ) I used to run smoothly on VMware Fusion with Intel CPU.

Screenshot 2022-11-09 alle 11 42 44

@sadn1ck
sadn1ck commented last month
try removing all other drives and just keep the qcow2 imported one, if that doesn't work - maybe the image itself is the problem. (also disable network booting - I uninstalled UTM since I tried it, so don't remember all the details)

@THEDOBERMANN
THEDOBERMANN commented last month
Kudos @sadn1ck and thanks, you hit the target: by removing the default disk created by UTM my image actually started (although for some reason it doesn't work maybe for controllers issue it starts dracut and doesn't proceed further).
