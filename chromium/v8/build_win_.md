
##
#
https://gist.github.com/jhalon/5cbaab99dccadbf8e783921358020159
#
##

# Building Chrome V8 on Windows

In order to be able to build v8 from scratch on Windows for x64, please follow the following steps.

These instructions were updated to work with Windows 11 Build 10.0.22621, but this should also work on WInodws 10

**NOTE**: While the Chrome team does provide decent documentation, there are some nuances and other additional steps that must be done for v8 to compile on Windows.

**Documentation**:
- https://chromium.googlesource.com/chromium/src/+/master/docs/windows_build_instructions.md#Setting-up-Windows
- https://v8.dev/docs/source-code
- https://v8.dev/docs/build
- https://medium.com/angular-in-depth/how-to-build-v8-on-windows-and-not-go-mad-6347c69aacd4

**Some Nuances:**
-  As of April/May 2023, Chromium **requires** Visual Studio 2022 (>=17.0.0) to build
-  For debugging (that will be us) Visual Studio 2022 is needed. Anything below might result in a build failure
- Desktop development with C++ components and the MFC/ATL support modules must be installed in Visual Studio.
- Building v8 in Debug mode with [ASan](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/asan.md) on Windows is not supported, as it's not yet implemented in LLVM.
  - If you need this functionality, build v8 on Linux or macOS. 

## Get a Fresh Dev VM (Optional):

If you want to start on a fresh Windows 11 Development VM with Visual Studio 2022 then download one of the last W11 Dev VM's from Microsoft:
- [VirtualBox](https://aka.ms/windev_VM_virtualbox)
- [VMWare](https://aka.ms/windev_VM_vmware)

If you want to start on a fresh Windows 10 Development VM with Visual Studio 2019 then download one of the last W10 Dev VM's from Microsoft:
- [VirtualBox](https://download.microsoft.com/download/1/8/c/18c400fa-91d3-4ab2-b232-5e2b0480da43/WinDev2108Eval.VirtualBox.zip)
- [VMWare](https://download.microsoft.com/download/0/d/f/0df7c0ac-b979-4846-a902-5199ee7860a7/WinDev2106Eval.VMware.zip)

## Setting Up Windows:

Once you have Visual Studio 2022 installed, you will need to install the following additional components:

- Desktop Development with C++
- Python Development
- C++ ATL for Latest v143 Build Tools (x86 & x64)
- C++ MFC for Latest v143 Build Tools (x86 & x64)
- C++ Clang Compiler for Windows (15.0.1)
- C++ Clang tools for Windows (15.0.1 - x64/x86)
- C++ CMake tools for Windows
- Windows 11 SDK (10.0.22621.0)

Next, we need to install the "**SDK Debugging Tools"** to be able to build and debug v8. 

> **Note**:
> If you downloaded the W11 Development VM, this should already be installed.
> But if you install the SDK, make sure that you have the correct install path of `C:\Program Files (x86)\Windows Kits\10\WindowsSDK` and that you select `Debugging Tools`, or you will have build failures.

To do that, either download the [Windows 11 SDK (10.0.22621.755)](https://go.microsoft.com/fwlink/p/?linkid=2196241) or do the following if you installed the SDK via Visual Studio:

1. Open up Control Panel
2. Click Program
3. Click "Programs and Features"
4. Select the "Windows Software Development Kit"
5. Click "Change"
6. In the new Window, select "Change"
7. Click "Change"
8. Check the "Debugging Tools For Windows" Option
9. Click "Change"
10. Let the Debugging Tools Install

## Download Chrome Tools and V8

First, start by creating a folder where you will be storing Google's tools and v8. In my case I made a new directory called `dev` in my `C:\` drive.

Download the [depot_tools](https://storage.googleapis.com/chrome-infra/depot_tools.zip) and extract it to your previously created folder. In my case it will be extracted to `C:\dev\depot_tools`.

> **Warning**:
> **DO NOT** use drag-n-drop or copy-n-paste extract from Explorer, this will not extract the hidden “.git” folder which is necessary for depot_tools to auto update itself. You can use “Extract all…” from the context menu though.

Assuming that you unzipped the budle to `C:\dev\depot_tools`, we now need to add the following Environmental Variables:

- Modify the **PATH** System Variable and put `C:\dev\depot_tools` at the front.
- Add the **DEPOT_TOOLS_WIN_TOOLCHAIN** User Variable and set it to **0**.
  - This tells depot_tools to use your locally installed version of Visual Studio
- Add the **vs2022_install** User Variable and set it to your installation path of Visual Studio.
  - For 2022 Community it would be set to => `C:\Program Files (x86)\Microsoft Visual Studio\2022\Community`

Once done, open up `cmd.exe`, `cd` to your `depot_tools` directory and then run the following command:

```
> gclient
```

On the first run, `gclient` will install all the Windows-specific bits needed to work with the code, including msysgit and python.

- If you run `gclient` from a non-cmd shell (e.g., cygwin, PowerShell), it may appear to run properly, but msysgit, python, and other tools may not get installed correctly.
- If you see strange errors with the file system on the first run of gclient, you may want to [disable Windows Indexing](https://tortoisesvn.net/faq.html#cantmove2).

After running gclient open a command prompt and type `where python` and confirm that the depot_tools `python.bat` comes ahead of any copies of `python.exe`, like so:

```
C:\dev\depot_tools>where python
C:\dev\depot_tools\python.bat
C:\Users\User\AppData\Local\Microsoft\WindowsApps\python.exe
```

Create a `v8` directory within your `C:\dev` folder (assuming that's what you created) for the checkout and change to it:

```
> mkdir v8 && cd v8
```

Run the `fetch` tool from `depot_tools` to check out the v8 code and its dependencies:

```
> fetch v8
```

Once the command has completed (~15-30 minutes), we now need to change to the v8 directory and sync the dependencies by running the following command:

```
> cd v8
> git fetch
> gclient sync
```

> **NOTE**:
> Usually, you can update your current v8 branch with `git pull`. Note that if you’re not on a branch, `git pull` won’t work, and you’ll need to use `git fetch` instead.

## Building V8

Now that we have all our tools installed, and dependencies synced, it's time to build v8.

All of your commands should be executed using Windows Command Shell inside the v8 source directory. We will be executing python scripts as part of the build process and we need to ensure that the python executable from `build_tools` is used.

> **WARNING**:
> Take note, that there is a problem in the way Windows can associate python files with other versions of python installed on your PC.
> v8 relies on certain older Python v2 scripts, so always execute commands in the `python path/to/script params` syntax!

So, once we're in the v8 folder, we can execute the following command to build the `debug` version of v8:

```
> python3 tools\dev\gm.py x64.debug
```

If you want the `release` version, just change `x64.debug` to `x64.release` in the command. 

Let this command run, and go get a coffee :coffee: as this will take ~2-3 hours to build.

If the compile is **successful** your console output should be pretty similar to mines, as shown below:

```
C:\dev\v8\v8>python tools/dev/gm.py x64.debug
# mkdir -p out\x64.debug
# echo > out\x64.debug\args.gn << EOF
is_component_build = true
is_debug = true
symbol_level = 2
target_cpu = "x64"
v8_enable_sandbox = true
use_goma = false
v8_enable_backtrace = true
v8_enable_fast_mksnapshot = true
v8_enable_slow_dchecks = true
v8_optimized_debug = false
EOF
# gn gen out\x64.debug
Done. Made 190 targets from 103 files in 5968ms
# autoninja -C out\x64.debug d8
"C:\dev\depot_tools\bootstrap-2@3_8_10_chromium_26_bin\python3\bin\python3.exe" C:\dev\depot_tools\ninja.py -C out\x64.debug d8 -j 6
ninja: Entering directory `out\x64.debug'
[2137/2137] LINK d8.exe d8.exe.pdb
Done! - V8 compilation finished successfully.
```

## Testing d8

Alright! So, we just successfully compiled v8, nice! If you haven't already noticed, `gm` also built [d8](https://v8.dev/docs/d8) for us, which is v8's developer shell.

`d8` is useful for running some JavaScript locally or debugging changes you have made to V8. This will be useful for us in better understanding v8 and writing exploits. 

To test if d8 was successfully built, let's execute it with the `--print-bytecode` command, like so:

```
> out\x64.debug\d8 --print-bytecode
V8 version 11.6.0 (candidate)
d8>
```

From here, to make sure that we can see the bytecode, let's execute a simple function like `Array.from(String('12345'))` which simply creates an array with each number in the index of the string.

Your output should be similar to mines:

```
d8> Array.from(String('12345'))
[generated bytecode for function:  (0x02330025a8c9 <SharedFunctionInfo>)]
Bytecode length: 28
Parameter count 1
Register count 5
Frame size 40
Bytecode age: 0
         000002330025A94A @    0 : 21 00 00          LdaGlobal [0], [0]
         000002330025A94D @    3 : c3                Star2
         000002330025A94E @    4 : 2d f8 01 02       GetNamedProperty r2, [1], [2]
         000002330025A952 @    8 : c4                Star1
         000002330025A953 @    9 : 21 02 04          LdaGlobal [2], [4]
         000002330025A956 @   12 : c2                Star3
         000002330025A957 @   13 : 13 03             LdaConstant [3]
         000002330025A959 @   15 : c1                Star4
         000002330025A95A @   16 : 63 f7 f6 06       CallUndefinedReceiver1 r3, r4, [6]
         000002330025A95E @   20 : c2                Star3
         000002330025A95F @   21 : 5f f9 f8 f7 08    CallProperty1 r1, r2, r3, [8]
         000002330025A964 @   26 : c5                Star0
         000002330025A965 @   27 : aa                Return
Constant pool (size = 4)
000002330025A911: [FixedArray] in OldSpace
 - map: 0x023300002231 <Map(FIXED_ARRAY_TYPE)>
 - length: 4
           0: 0x0233000058e5 <String[5]: #Array>
           1: 0x0233000060a1 <String[4]: #from>
           2: 0x023300006dfd <String[6]: #String>
           3: 0x02330025a8a9 <String[5]: #12345>
Handler Table (size = 0)
Source Position Table (size = 0)
["1", "2", "3", "4", "5"]
```

Congratulations, you built v8 and d8!

# Downloading Pre-Built Binaries

In case you don't want to compile V8, you can just grab fresh Chrome binaries built with ASan from [here](https://commondatastorage.googleapis.com/chromium-browser-asan/index.html). Additionally, you can use [OmahaProxy CSV Viewer](https://omahaproxy.appspot.com/) to look for specific **branch base positions** by specifying a version of Chrome you want to target, and then just downloading the appropriate build from the chromium browser list. 
