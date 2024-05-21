
##
#
https://exploit-notes.hdks.org/exploit/reverse-engineering/reverse-engineering-with-rizin/
#
https://github.com/ReversingID/Awesome-Reversing/blob/master/_software.md
#
##



# Awesome Software Reverse Engineering

A curated list of awesome reverse engineering resources to make you better! 

Managed by Reversing.ID for the reversing community.

## Introduction 

`Software Reverse Engineering` focus on code, related data, and architecture which build a complete software.

The goals:

- Recover lost information, or to make documentation.
- Detect side effects (bugs, backdoor, vulnerabilities)
- Synthesis higher abstraction.
- Facilitate reuse.

In most case, the target of Software Reversing is code in compiled form (native or intermediate), either executable or libraries.

## Table of Contents

- Resources
    - [Books](#books)
    - [White Papers](#hite-papers)
    - [Articles](#articles)
    - [Courses](#courses)
    - [Channels](#channels)
    - [Practices](#practices)
    - [References](#references)
- Tools
    - [Hex Editors](#hex-editors)
    - [Binary Format](#binary-format)
    - [Bytecode Editor](#bytecode-editors)
    - [Disassemblers & Decompilers](#disassemblers--decompilers)
    - [Debuggers](#debuggers)
    - [Behavior Analysis](#behavior-analysis)
    - [Dynamic Binary Instrumentation](#dynamic-binary-instrumentation)
    - [Binary Analysis Framework](#binary-analysis-framework)
    - [Code Emulators](#code-emulators)
    - [Injectors](#injectors)
    - [HTTP Intercept Proxy](#http-intercept-proxy)
    - [Reconstructors](#reconstructors)
    - [Unpackers](#unpackers)
    - [Obfuscators](#obfuscators)
    - [Deobfuscators](#deobfuscators)
    - [Binary Visualization](#binary-visualization)
    - [Document Analysis](#document-analysis)
    - [Misc](#misc)
- Scripting
    - [IDA Pro](#ida-script)
    - [Ghidra](#ghidra-script)

- - - 

## Books

Reversing Concept

* [Reverse Engineering for Beginners](http://beginners.re/)
* [Practical Reverse Engineering](http://amzn.com/B00IA22R2Y)
* [Reversing: Secrets of Reverse Engineering](http://amzn.com/B007032XZK)
* [Practical Malware Analysis](http://amzn.com/1593272901)

Tools

* [The IDA Pro Book](http://amzn.com/1593272898)

Assembly and languages

* [Assembly Language for Intel-Based Computers (5th Edition) ](http://a.co/4OR6I9U)

Specific topic on Software Reverse Engineering

* [Windows Internals Part 1](http://amzn.com/0735648735) [Part 2](http://amzn.com/0735665877)
* [Inside Windows Debugging](http://amzn.com/0735662789)
* [iOS Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering)

## White Papers

* [Next Generation debugger for reverse engineering](https://www.blackhat.com/presentations/bh-europe-07/ERSI/Whitepaper/bh-eu-07-ersi-WP-apr19.pdf)
* [Behind Enemy Lines Reverse Engineering C++ in Modern Ages](https://corecppil.github.io/CoreCpp2019/Presentations/Gal_Behind_Enemy_Lines_Reverse_Engineering_Cpp_in_Modern_Ages.pdf)
* [Overcoming Java Vulnerabilities](https://www2.gemalto.com/download/OvercomingJavaVulnerabilities_WP_(A4)_web.pdf)
* [Reverse engineering tools review](https://www.pelock.com/articles/reverse-engineering-tools-review)

## Articles

* [Intercepting DLL libraries calls. API hooking in practice](https://www.pelock.com/articles/intercepting-dll-libraries-calls-api-hooking-in-practice)
* [Windows Hot Patching Mechanism Explained](https://dev.to/pelock/windows-hot-patching-mechanism-explained-2m1f)
* [How to write a CrackMe for a CTF competition](https://www.pelock.com/articles/how-to-write-a-crackme-for-a-ctf-competition)
* [Anti reverse engineering. Malware vs Antivirus Software](https://www.pelock.com/articles/reverse-engineering-tools-review)
* [Code of destruction – malware analysis](https://www.pelock.com/articles/code-of-destruction-malware-analysis)
* [Polymorphic Encryption Algorithms](https://www.pelock.com/articles/polymorphic-encryption-algorithms)
* [Reversing reading]() - coming soon.

## Courses

*Reverse Engineering Courses*

* [Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)
* [Open Security Training](http://opensecuritytraining.info/Training.html)
* [Dr. Fu's Malware Analysis](http://fumalwareanalysis.blogspot.sg/p/malware-analysis-tutorials-reverse.html)
* [Binary Auditing Course](http://www.binary-auditing.com/)
* [TiGa's Video Tutorials](http://www.woodmann.com/TiGa/)
* [Legend of Random](https://tuts4you.com/download.php?list.97)
* [Practical Malware Analysis](https://samsclass.info/126/126_S17.shtml)
* [Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)
* [RPISEC Malware Course](https://github.com/RPISEC/Malware)
* [begin.re](https://www.begin.re/)
* [RE101](https://securedorg.github.io/RE101/)
* [RE102](https://securedorg.github.io/RE102/)
* [ARM Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/)
* [Offensive and Defensive Android Reversing](https://github.com/rednaga/training/raw/master/DEFCON23/O%26D%20-%20Android%20Reverse%20Engineering.pdf)

## Channels

*Binary Analysis Channels*

* [OALabs](https://www.youtube.com/channel/UC--DwaiMV-jtO-6EvmKOnqg)
* [MalwareTech](https://www.youtube.com/channel/UCLDnEn-TxejaDB8qm2AUhHQ)
* [GynvaelEN](https://www.youtube.com/user/GynvaelEN)
* [VirusBtn](https://www.youtube.com/user/virusbtn)
* [Intro to WinDBG](https://www.youtube.com/playlist?list=PLhx7-txsG6t6n_E2LgDGqgvJtCHPL7UFu)
* [hasherzade](https://www.youtube.com/channel/UCNWVswPNgn5kutPNa5sprkg)
* [Colin Hardy](https://www.youtube.com/channel/UCND1KVdVt8A580SjdaS4cZg)
* [MalwareAnalysisHedgehog](https://www.youtube.com/channel/UCVFXrUwuWxNlm6UNZtBLJ-A)
* [LiveOverflow](https://www.youtube.com/watch?v=iyAyN3GFM7A&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

## Practices

*Practice Reverse Engineering*

* [Reversing.ID Crackmes Repository](https://github.com/ReversingID/Crackmes-Repository/)
* [Crackmes.one](http://www.crackmes.one/)
* [OSX Crackmes](https://reverse.put.as/crackmes/)
* [ESET Challenges](http://www.joineset.com/jobs-analyst.html)
* [Flare-on Challenges](http://flare-on.com/)
* [Github CTF Archives](http://github.com/ctfs/)
* [Reverse Engineering Challenges](http://challenges.re/)
* [xorpd Advanced Assembly Exercises](http://www.xorpd.net/pages/xchg_rax/snip_00.html)
* [Virusshare.com](http://virusshare.com/)
* [Contagio](http://contagiodump.blogspot.com/)
* [Malware-Traffic-Analysis](https://malware-traffic-analysis.com/)
* [Malshare](http://malshare.com/)
* [Malware Blacklist](http://www.malwareblacklist.com/showMDL.php)
* [malwr.com](https://malwr.com/)
* [vxvault](http://vxvault.net/)

## References

Learning Assembly

* [Low-level Code Reference](https://github.com/ReversingID/LowLevelCode-Reference)
* [Assembly code size optimization tricks](https://dev.to/pelock/assembly-code-size-optimization-tricks-2abd)
* [When and how to use an assembler. Assembly programming basics](https://www.pelock.com/articles/when-and-how-to-use-an-assembler-assembly-programming-basics)

Intermediate Representation

* [LLVM IR](https://llvm.org/docs/LangRef.html)
* [REIL](https://www.zynamics.com/binnavi/manual/html/reil_language.htm)
* [OpenREIL](https://github.com/Cr4sh/openreil)

- - - 

## Hex Editors

Hex editor lets you view/edit the binary data of a file.

Multi/cross platform

* [010 Editor](http://www.sweetscape.com/010editor/)
* [wxHexEditor](https://www.wxhexeditor.org/)

Windows 

* [HxD](https://mh-nexus.de/en/hxd/)
* [Hex Workshop](http://www.hexworkshop.com/)
* [Hexinator](https://hexinator.com/)
* [HIEW](http://www.hiew.ru/)

Mac OS X

* [HexFiend](http://ridiculousfish.com/hexfiend/)

## Binary Format

File information and format identifier

* [file](https://linux.die.net/man/1/file)
* [TrID](http://mark0.net/soft-trid-e.html)
* [nm](https://linux.die.net/man/1/nm) - view symbols

Executable detector

* [Detect It Easy](http://ntinfo.biz/)
* [PEiD](https://tuts4you.com/download.php?view.398)

Executable explorer

* [CFF Explorer](http://www.ntcore.com/exsuite.php)
* [Cerbero Profiler](http://cerbero.io/profiler/)  //  [Lite PE Insider](http://cerbero.io/peinsider/)
* [PeStudio](http://www.winitor.com/)
* [PPEE](https://www.mzrst.com/)
* [PE Bear](https://hshrzd.wordpress.com/pe-bear/)
* [MachoView](https://github.com/gdbinit/MachOView)

Dependency check

* [DependencyWalker](http://www.dependencywalker.com/)
* [slid](https://github.com/arvinddoraiswamy/slid) - statically linked library detector.

Format parser and modification

* [ImHex](https://github.com/WerWolv/ImHex) - explore, edit, and represent binary structure with C++-like pattern language.  
* [Kaitai Struct](https://kaitai.io) - develop format parsers by declarative approach 
* [LIEF](https://lief.quarkslab.com/) - Library to Instrument Executable Formats, easily parse, modify and abstract many file formats.
* [QuickBMS](http://aluigi.altervista.org/quickbms.htm) - easily extract and modify file format with support of encryption, compressions, obfuscation, and other algorithms.

## Bytecode Editors

Java bytecode editor

* [Recaf](https://github.com/Col-E/Recaf)
* [JByteMode](https://github.com/GraxCode/JByteMod-Beta)
* [dirtyJOE](http://dirty-joe.com/)

## Disassemblers & Decompilers

Native code disassembler and decompiler

* [Ghidra](https://ghidra-sre.org/)
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml)
* [Binary Ninja](https://binary.ninja/)
* [Relyze Desktop](https://relyze.com)
* [Radare2](http://www.radare.org/r/) // [Cutter](https://cutter.re)
* [Hopper](http://hopperapp.com/)
* [fREedom](https://github.com/cseagle/fREedom)
* [Retdec](https://retdec.com/)
* [Snowman](https://derevenets.com/)
* [objdump](http://linux.die.net/man/1/objdump)
* [Medussa](https://github.com/wisk/medusa)
* [Plasma](https://github.com/joelpx/plasma)
* [Capstone](http://www.capstone-engine.org/) - lightweight multi-platform, multi-architecture disassembly framework based on LLVM.
* [distorm3](https://github.com/gdabah/distorm) - lightweight library for disassembling binary stream.
* [zydis](https://github.com/zyantific/zydis) - fast and lightweight x86/x86-64 disassembler library.

Android application disassembler / decoder

* [JEB2](https://www.pnfsoftware.com/jeb2/) - eclipse-based integrated reverse engineering platform for analyzing various parts of Android application components.

Java decompiler

* [Bytecode Viewer](https://bytecodeviewer.com/) - aggregate of various tools
* [Procyon](https://bitbucket.org/mstrobel/procyon)
* [CFR](http://www.benf.org/other/cfr/)
* [FernFlower](https://github.com/fesh0r/fernflower)
* [Krakatau](https://github.com/Storyyeller/Krakatau)
* [Luyten](https://github.com/deathmarine/Luyten)

.NET decompiler

* [dnSpy](https://github.com/0xd4d/dnSpy)
* [JustDecompile](https://www.telerik.com/products/decompiler.aspx)
* [dotPeek](https://www.jetbrains.com/decompiler/)
* [ILSpy](http://www.ilspy.net/)

Python decompiler

* [uncompyle6](https://pypi.org/project/uncompyle6/)
* [decompile3](https://github.com/rocky/python-decompile3) - reworking and refactoring of `uncompyle6` which focus on Python 3.7+

Flash decompiler

* [JPEXS Flash Decompiler](https://github.com/jindrapetrik/jpexs-decompiler) - open source SWF decompiler and editor, convert SWF to FLA, edit ActionScript, replace resources (images, sounds, texts, fonts).
* [Flare](http://www.nowrap.de/flare.html) - Extract all scripts from SWF.

Delphi decompiler

* [Interactive Delphi Reconstructor](https://github.com/crypto2011/IDR)

Lua decompiler

* [UnLuac](https://sourceforge.net/projects/unluac/) - decompiler for Lua 5.0 - 5.4 and require debugging information (non-stripped).
* [LuaDec](https://github.com/viruscamp/luadec) - decompiler based on luadec 5.0.x and LuaDec51.

AutoIT decompiler

* [myAut2Exe](https://github.com/dzzie/myaut_contrib) - scan and extract the AutoIT script.
* [Exe2Aut](http://domoticx.com/autoit3-decompiler-exe2aut) - extract the AutoIT script by running it.

Ethereum (EVM) Solidity disassembler / decompiler

* [evmdis](https://github.com/Arachnid/evmdis) - EVM disassembler by static analysis on the bytecode.
* [pyevmasm](https://github.com/crytic/pyevmasm) - assembler and disassembler library for EVM (Ethereum Virtual Machine).

## Debuggers

Multi/cross platform

* [GDB](https://www.gnu.org/software/gdb/)
* [lldb](http://lldb.llvm.org/)
* [vdb](https://github.com/vivisect/vivisect)

Windows

* [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
* [x64dbg](http://x64dbg.com/#start)
* [Immunity Debugger](http://debugger.immunityinc.com/)

Linux

* [QIRA](http://qira.me/) - timeless debugger which track all state while program is running.
* [EDB](http://www.codef00.com/projects#debugger)

Virtual Machine Introspection for debugging

* [rVMI](https://github.com/fireeye/rVMI)
* [r2vmi](https://github.com/Wenzel/r2vmi)

Hypervisor debugger

* [HyperDbg](https://github.com/rmusser01/hyperdbg/) - minimalistic hypervisor with hardware-assisted virtualization to debug kernel.

GDB enrichment

* [PEDA](https://github.com/longld/peda)
* [GEF](https://github.com/hugsy/gef)
* [Voltron](https://github.com/snare/voltron) - also available for LLDB, VDB, and WinDbg

OllyDbg variant

* [OllyDbg v1.10](http://www.ollydbg.de/)
* [OllyDbg v2.01](http://www.ollydbg.de/version2.html)
* [OllySnD](https://tuts4you.com/download.php?view.2061)
* [Olly Shadow](https://tuts4you.com/download.php?view.6)
* [Olly CiMs](https://tuts4you.com/download.php?view.1206)
* [Olly UST_2bg](https://tuts4you.com/download.php?view.1206)

Graphic Debugger

* [RenderDoc](https://renderdoc.org/)
* [PIX](https://blogs.msdn.microsoft.com/pix/download/)

## Behavior Analysis

Network simulation

* [iNetSim](http://www.inetsim.org/)
* [Fakenet](http://practicalmalwareanalysis.com/fakenet/)

Packet Capture

* [SmartSniff](http://www.nirsoft.net/utils/smsniff.html)
* [Wireshark](https://www.wireshark.org/download.html)

Process

* [ProcessHacker](https://processhacker.sourceforge.io/)
* [Process Explorer](https://technet.microsoft.com/en-us/sysinternals/processexplorer)
* [Autoruns](https://technet.microsoft.com/en-us/sysinternals/bb963902)

Tracer

* [API Monitor](http://www.rohitab.com/apimonitor)
* [Process Monitor](https://technet.microsoft.com/en-us/sysinternals/processmonitor)
* [SpyStudio](https://www.nektra.com/products/spystudio-api-monitor/)
* [fibratus](https://github.com/rabbitstack/fibratus) - explore and trace windows kernel
* [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)
* [CDA: Code Dynamic Analysis](http://split-code.com/cda.html)

Sandbox

* [Noriben](https://github.com/Rurik/Noriben)
* [Cuckoo](https://www.cuckoosandbox.org/)

Misc

* [Objective-See Utilities](https://objective-see.com/products.html)
* [XCode Instruments](https://developer.apple.com/xcode/download/) - XCode Instruments for Monitoring Files and Processes [User Guide](https://developer.apple.com/library/watchos/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/index.html)
* [dtrace script for Mac](http://dtrace.org/blogs/brendan/2011/10/10/top-10-dtrace-scripts-for-mac-os-x/) - sudo dtruss = strace [dtrace recipes](http://mfukar.github.io/2014/03/19/dtrace.html)
* [fs_usage](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/fs_usage.1.html) - report system calls and page faults related to filesystem activity in real-time.  File I/O: fs_usage -w -f filesystem
* [dmesg](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/dmesg.8.html) - display the system message buffer

## Dynamic Binary Instrumentation

Native 

* [DynamoRIO](http://www.dynamorio.org) - runtime code manipulation system that supports code transformation on any part of program.
* [Frida](https://frida.re) - scriptable DBI toolkit for cross-platform target.
* [Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
* [QBDI](https://qbdi.quarkslab.com/) - modular, cross-platform, and cross-architecture DBI framework backed by LLVM.

.NET

- [Hawkeye2](https://github.com/odalet/Hawkeye2) - view, edit, analyze, and invoke (almost) any object from .net applications.
- [UnityDoorstop](https://github.com/NeighTools/UnityDoorstop) - execute managed assemblies inside Unity as early as possible.

## Binary Analysis Framework

* [Angr](http://angr.io/) - python framework for analyzing binaries, combines both static and dynamic symbolic (concolic) analysis.
* [Triton](https://triton.quarkslab.com) - dynamic binary analysis (DBA) framework.
* [BAP](http://binaryanalysisplatform.github.io/) - suite of utilities and libraries that enable analysis of programs in their machine representations.
* [BitBlaze](http://bitblaze.cs.berkeley.edu/)
* [PANDA](https://github.com/panda-re/panda) - Platform for Architecture-Neutral Dynamic Analysis, built on QEMU system emulator, analyzecode in runtime.
* [BARF](https://github.com/programa-stic/barf-project)
* [S2E](https://s2e.systems/) - platform for in-vivo analysis of software systems.
* [miasm](https://miasm.re/) - analyze / modify / generate binary program with python.
* [soot](https://github.com/soot-oss/soot) - java optimization framework

Symbolic Execution (only)

* [KLEE](https://klee.github.io/) - dynamic symbolic execution engine built on top of the LLVM compiler infrastructure
* [manticore](https://github.com/trailofbits/manticore/) - symbolic execution tool for analysis of smart contracts and binaries.
* [Kite](http://www.cs.ubc.ca/labs/isd/Projects/Kite/) - conflict-driven symbolic execution tool (proof of concept)
* [jCUTE](https://github.com/osl/jcute) - Java Concolic Unit Testing Engine, automatically generate unit tests for Java programs.
* [ExpoSE](https://github.com/ExpoSEJS/ExpoSE) - dynamic symbolic execution engine for JavaScript.
* [ESILSolve](https:/github.com/aemmitt-ns/esilsolve) - python symbolic execution framework using r2 and ESIL.

Binary lifting

* [McSema](https://github.com/lifting-bits/mcsema) - framework for lifting x86, amd64, and aarch64 program binareis to LLVM bitcode.

Theorem prover and solver

* [Z3](https://github.com/Z3Prover/z3) - cross-platform satisfiability modulo theory 
* [STP](https://stp.github.io/)
* [CVC4](https://cvc4.github.io/)
* [Boolector](https://boolector.github.io/)

## Code Emulators

* [unicorn](https://github.com/unicorn-engine/unicorn)
* [libemu](http://libemu.carnivore.it)
* [pegasus](https://github.com/imugee/pegasus)

## Injectors

Windows

* [PolyHook](https://github.com/stevemk14ebr/PolyHook)
* [EasyHook](https://easyhook.github.io/)
* [Deviare2](https://github.com/nektra/Deviare2)
* [Xenos](https://github.com/DarthTon/Xenos)

## HTTP Intercept Proxy

* [Fiddler](https://www.telerik.com/fiddler)
* [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
* [Charles](https://www.charlesproxy.com/)

## Reconstructors

Import reconstructor

* [ImpRec](http://www.woodmann.com/collaborative/tools/index.php/ImpREC)
* [Scylla](https://github.com/NtQuery/Scylla)
* [LordPE](http://www.woodmann.com/collaborative/tools/images/Bin_LordPE_2010-6-29_3.9_LordPE_1.41_Deluxe_b.zip)

Data-type reconstructor

* [ReClassEx](https://github.com/dude719/ReClassEx)
* [ReClass.NET](https://github.com/KN4CK3R/ReClass.NET) - port of ReClass to .NET

## Unpackers

* [FUU](https://github.com/crackinglandia/fuu) - [F]aster [U]niversal [U]npacker
* [TitanEngine](http://www.reversinglabs.com/products/TitanEngine.php)

## Obfuscators

Native

* [Stunnix](http://stunnix.com/prod/cxxo/)
* [M/o/Vfuscator](https://github.com/xoreaxeaxeax/movfuscator)

AutoIt scripts

* [Assembly Source Code Obfuscator](https://www.pelock.com/products/obfuscator)
* [AutoIt Source Code Obfuscator](https://www.pelock.com/products/autoit-obfuscator)

## Deobfuscators

Native

* [LLVM Deobfuscator](https://github.com/RPISEC/llvm-deobfuscator)
* [SATURN]() - software deobfuscation framework based on LLVM.

Java

* [Java Deobfuscator](https://javadeobfuscator.com/)

.NET

* [de4dot](https://github.com/0xd4d/de4dot)

Javascript

* [de4js](https://github.com/lelinhtinh/de4js)

PHP

* [evalhook](https://github.com/unreturned/evalhook)

String extraction

* [FLOSS](https://github.com/fireeye/flare-floss)
* [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR)

## Binary Visualization

See also [Data & Format Reversing](_format.md).

* [Veles](https://codisec.com/veles/)
* [..cantor.dust..](https://sites.google.com/site/xxcantorxdustxx/home)
* [binglide](https://github.com/wapiflapi/binglide)

## Document Analysis

* [Ole Tools](http://www.decalage.info/python/oletools)
* [Didier's PDF Tools](http://blog.didierstevens.com/programs/pdf-tools/)
* [Origami](https://github.com/cogent/origami-pdf)

## Misc

- [bingrep](https://github.com/m4b/bingrep) - grep through binaries

- - - 

## IDA Script

* [IDA Python Src](https://github.com/idapython/src) - source code for IDAPython plugin, enable python script running in IDA Pro .

references

* [IDC Functions Doc](https://www.hex-rays.com/products/ida/support/idadoc/162.shtml)
* [Using IDAPython to Make your Life Easier](http://researchcenter.paloaltonetworks.com/tag/idapython/)
* [Introduction to IDA Python](https://tuts4you.com/download.php?view.3229)
* [The Beginner's Guide to IDA Python](https://leanpub.com/IDAPython-Book)
* [IDA Plugin Contest](https://www.hex-rays.com/contests/)

Script collection

* [fireeye/flare-ida](https://github.com/fireeye/flare-ida) - multiple IDA plugins and IDAPython scripts by FLARE team.
* [devttys0/ida](https://github.com/devttys0/ida) - collection of IDAPython plugins/scripts/modules.
* [onehawt IDA Plugin List](https://github.com/onethawt/idaplugins-list) - list of ida scripts (IDC / IDAPython), links to many repository.

## Ghidra Script

Script collection

* [ghidra ninja](https://github.com/ghidraninja/ghidra_scripts)


```Reverse Engineering with Rizin
Last modified: 2023-07-30

Malware
Reverse Engineering
Rizin is a reverse engineering framework forked from Radare2.

Using Cutter
Cutter is a GUI tool for reverse engineering powered by Rizin.
It can also have a decompiler, so it’s recommended to use it first.

cutter <file>
Copied!
To use the Ghidra decompiler, install the package.

sudo apt install rizin-plugin-ghidra
# or
sudo apt install rz-ghidra
Copied!

Start Debugging
rizin ./example

# Debug mode
rizin -d ./example
# Write mode
rizin -w ./example
Copied!

Analyze
Analyze the program after starting the debugger.

# Analyze all calls
> aaa

# Analyze function
> af 
# List all functions
> afl
> afl | grep main
# Show address of current function
> afo
Copied!

Print Usage
# Print usage
> ?

# Add "?" suffix to print the usage of the specific command.
> i?
> p?
Copied!

Visual Mode
You can enter visual mode for more intuitive operation.

> v

# Visual Debugger Mode
> Vpp
Copied!
Below is a list of basic commands:

# Toggle print mode
p
# or
P

# Step
s

# Toggle cursor mode
c

# Exit
q

# Enable regular rizin commands
:
Copied!

Debug
# Step
> ds
# Step 3 times
> ds 3
# Step back
> dsb

# Setup a breakpoint
> db @ 0x8048920
# Remove a breakpoint
> db @ -0x8048920
# Remove all breakpoints
> db-*
# List all breakpoints
> dbl

# Continue to execute the program until we hit the breakpoint
> dc
# Continue until syscall
> dcs

# Read all registers values
> dr
> dr=
# Read given register value
> dr eip
> dr rip
# Set a register value
> dr eax=24
# Show register references
> drr
Copied!

Seek
# Print current address
> s

# Seek to given function
> s main
> s sym.main

# Seek to given address
> s 0x1360
> s 0x0x00001360

# Seek to register address
> s esp
> s esp+0x40
> s rsp
> s rsp+0x40

# Seek 8 positions
> sd 8

# Show the seek history
> sh
# Undoing
> shu
# Redoing
> shr
Copied!

Print
# Disassemble at current address
> pd
# Disassemble 10 instructions at current address
> pd 10
# Disassemble all possible opcodes at current address
> pda
# Disassemble all possible opcodes 10 instructions at current address
> pda 10
# Disassemble at the given function
> pd @ main
> pd 20 @ main

# Disassemble a function at current address
> pdf
# Disassemble at given address
> pdf @ 0x401005
# Disassemble the main function
> pdf @ main

# Print string
> ps @ 0x2100
# Print zero-terminated string
> psz @0x2100

# Show 200 hex bytes
> px 200
# Show hex bytes at given register
> px @ eip
> px @ esp
Copied!
To decompile functions, we need to Ghidra decompiler so first we need to install the ghidra plugin.

sudo apt install rizin-plugin-ghidra
Copied!
Then below are commands for decompiling.

# Decompile the "main" function
> pdg @ main
Copied!

Write
We need to add '-w' option when the debugger starts.

# Write string
> w Hello World\n @ 0x2100

# Write opcodes at given address
> wa 'mov eax, 1' @ 0x2100
> wa 'mov byte [rbp-0x1], 0x61' @ 0x2100
Copied!

Expressions
> ?vi 0x000011a4
4516

> ?vi 1+2
3
Copied!

Information about Binary File
# Information about the binary file
> i

# All summary
> ia

# Show main address
> iM

# Symbols
is

# List strings
> iz
# List strings in whole binary
> izz
Copied!

Reopen Current File
# Reopen current file in debug mode
> ood
```

##
#
https://hub.docker.com/r/remnux/rizin/dockerfile
#
##

```
# Name: Rizin
# Website: https://rizin.re
# Description: Examine binary files, including disassembling and debugging.
# Category: Dynamically Reverse-Engineer Code: General
# Author: https://github.com/rizinorg/rizin/blob/master/AUTHORS.md
# License: GNU Lesser General Public License (LGPL) v3: https://github.com/rizinorg/rizin/blob/master/COPYING
# Notes: rizin, rz-asm, rz-bin, rz-hash, rz-find, rz-agent, etc.
#
# This Dockerfile is based on the official Rizin Dockerfile file from
# the following URL, adjusted to use Ubuntu instead of Debian:
# https://github.com/rizinorg/rizin/blob/dev/Dockerfile
#
# To run this image after installing Docker, use the command below, replacing
# "~/workdir" with the path to your working directory on the underlying host.
# Before running the docker, create ~/workdir on your host.
#
# docker run --rm -it --cap-drop=ALL --cap-add=SYS_PTRACE -v ~/workdir:/home/rizin/workdir remnux/rizin
#
# Then run "rizin" or other Rizin commands (starting with "rz-") inside the container.
#
# Running 'rz-agent -a' will enable the web-based interface on port 8080 by default.
# To access this, add '-p 8080:8080' to the above docker command (before 'remnux/rizin')
# Then browse to your http://YOUR_IP:8080. 

FROM ubuntu:20.04
LABEL maintainer="Lenny Zeltser (@lennyzeltser, www.zeltser.com)"
LABEL updated="8 Dec 2020"
LABEL updated_by="Lenny Zeltser"
ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

# Rizin branch version
ARG RZ_VERSION=dev

# rz-pipe python version
ARG RZ_PIPE_PY_VERSION=master

ARG with_arm32_as
ARG with_arm64_as
ARG with_ppc_as

ENV RZ_PIPE_PY_VERSION ${RZ_PIPE_PY_VERSION}

RUN echo -e "Building versions:\n\
	RZ_PIPE_PY_VERSION=${RZ_PIPE_PY_VERSION}"

USER root

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl \
  cmake \
	gcc \
	cpp \
	g++ \
	git \
	make \
	libc-dev-bin libc6-dev linux-libc-dev \
	python3-pip \
	python3-setuptools \
	python3-wheel \
	${with_arm64_as:+binutils-aarch64-linux-gnu} \
	${with_arm32_as:+binutils-arm-linux-gnueabi} \
	${with_ppc_as:+binutils-powerpc64le-linux-gnu} && \
	pip3 install meson ninja && \
	cd /tmp && \
	git clone -b "$RZ_PIPE_PY_VERSION" https://github.com/rizinorg/rz-pipe && \
	pip3 install ./rz-pipe/python && \
  git clone -b "$RZ_VERSION" -q --depth 1 --recurse-submodules https://github.com/rizinorg/rizin.git && \
	cd rizin && \
	meson --prefix=/usr /tmp/build && \
	meson compile -C /tmp/build && \
	meson install -C /tmp/build && \
	rm -rf /tmp/build && \
	pip3 uninstall -y meson ninja && \
	apt-get remove --purge -y \
	cmake \
	cpp \
	g++ \
	python3-pip \
	python3-setuptools \
	python3-wheel && \
  apt-get autoremove --purge -y && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV RZ_ARM64_AS=${with_arm64_as:+aarch64-linux-gnu-as}
ENV RZ_ARM32_AS=${with_arm32_as:+arm-linux-gnueabi-as}
ENV RZ_PPC_AS=${with_ppc_as:+powerpc64le-linux-gnu-as}

# Create non-root user
RUN groupadd -r nonroot && \
  useradd -m -d /home/nonroot -g nonroot -s /usr/sbin/nologin -c "Nonroot User" nonroot && \
  mkdir -p /home/nonroot/workdir && \
  chown -R nonroot:nonroot /home/nonroot && \
  usermod -a -G sudo nonroot && echo 'nonroot:nonroot' | chpasswd

# Initilise base user
#USER nonroot
WORKDIR /home/nonroot/workdir
VOLUME ["/home/nonroot/workdir"]
ENV HOME /home/nonroot
ENV LD_LIBRARY_PATH=/usr/lib64

# Setup rz-pm
RUN rz-pm init && \
  rz-pm update && \
  chown -R nonroot:nonroot /home/nonroot/.config

EXPOSE 8080
CMD ["/bin/bash"]

```

##
##
https://www.puckiestyle.nl/upgrade-shell-to-fully-interactive-tty-shell/

Often when we get a shell by exploiting vulnerabilities, the shell that we getting is a dumb terminal or not and interactive shell. This means that you cannot ctrl+c when accidentally run command such as ping where you need to terminate the process. If you do ctrl+c this not only kills the ping process, but also your shell.

To overcome this, I made a guide here where you can follow to convert your non-interactive shell to fully interactive shell.

Step 1
Get victim shell connection from your exploit either reverse or bind shell.

Step 2
On victim shell, upgrade the shell to tty shell. The most common is you can use python to spawn tty shell by using the pty built-in library. Make sure to spawn /bin/bash not /bin/sh. Read more here to see other methods of upgrading shell to tty shell.

$ python -c 'import pty;pty.spawn("/bin/bash")'
Step 3
Export some vars to the victim shell session. The best is to check your local terminal $TERM vars so that it same on the target terminal session.

echo $TERM
xterm-256color
Export that value on the target shell session.

export TERM=xterm-256color
export SHELL=/bin/bash
Step 4
On your local terminal, check for terminal rows and columns.

stty size
24 103
what you need to take note here is the current terminal rows and columns which is for me rows 24 and columns 103. You might be different.

On the victim shell, fork the shell to background by pressing ctrl+z and you’ll bring back to your local terminal.

^Z
[1]+  Stopped        nc -lvp 9091
Execute the following command to set the terminal to echo the input characters so that it catch by the victim terminal session. Follow with the command fg to bring back the victim shell to foreground.

stty raw -echo;fg
After that, your cursor might be somewhere on the middle of the terminal, type reset to reset the victim terminal session.

stty raw -echo;fg
nc -lvp 9091
                reset
Your victim terminal is now interactive, but it is not done yet. You need to specify the “new” terminal with rows and columns to make it display properly.

stty rows 24 columns 103
Now you’re happy with the fully interactive shell on victim.

If you do not have Python on the box

export TERM=xterm
SHELL=/bin/bash script -q /dev/null

scripts -qc /bin/bash /dev/null
