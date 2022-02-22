# Ghidra Info

Here's my notes on using Ghidra.


## Useful Links

* Ghidra documentation (for Java, but Python copies the interface):
  https://ghidra.re/ghidra_docs/api/index.html
* Scripting with Ghidra guide:
  https://ghidra.re/courses/GhidraClass/Intermediate/Scripting_withNotes.html#Scripting.html
* Ghidra scripting course notes:
  https://class.malware.re/2021/03/08/ghidra-scripting.html
* Some script examples in python:
  https://deadc0de.re/articles/ghidra-scripting-python.html
* Python Ghidra snippets (excellent):
  https://github.com/HackOvert/GhidraSnippets
* Docking widgets for GUI/plugins:
  https://ghidra.re/ghidra_docs/api/docking/widgets/package-summary.html
* A couple of simple headless scripts:
  https://github.com/AllsafeCyberSecurity/headless_scripts
* An example of a headless script that decompiles a function (it doesn't work, but still illustrates some things):
  https://gist.github.com/guedou/a358df609c80d9fdc1ec4c348129005b
* An example of a script that colors output:
  https://github.com/alephsecurity/general-research-tools/tree/master/ghidra_scripts/ColorInstructions
* Scripts that dump Pcode:
  https://github.com/d-millar/ghidra_pcode_scripts
* A script that dumps the Pcode:
  https://gist.github.com/edmcman/cfa46c393ac22c19ef288cfbdbdc6006
* How to access the Pcode (from the listings, and from the decompiler):
  https://reverseengineering.stackexchange.com/questions/21297/can-ghidra-show-me-the-p-code-generated-for-an-instruction
* Example of building an analysis (with Pcode):
  https://www.msreverseengineering.com/blog/2019/4/17/an-abstract-interpretation-based-deobfuscation-plugin-for-ghidra (searhc for "jenga")
* Ghidra XML to LLVM:
  https://github.com/toor-de-force/Ghidra-to-LLVM/blob/master/src/GhidraToXML.java
* API to get function info (like XML):
  https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html#buildFunctionXML(ghidra.program.model.address.Address,int)
* Building GUI Apps with Jython (docs):
  https://jython.readthedocs.io/en/latest/GUIApplications/
* Jython examples:
  https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/ghidra_scripts/jython_basics.py
* Ghidra Javax AWT examples:
  https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/ghidra_scripts/jython_basics.py
* An example of a Plugin provider:
  https://github.com/Nalen98/AngryGhidra/blob/master/src/main/java/angryghidra/AngryGhidraProvider.java


## Install Java 11 (macOS):

Download Java 11 JDK (.tar.gz):

* https://www.oracle.com/java/technologies/javase-jdk11-downloads.html

Move it somewhere:

    mkdir -p ~/java
    mv ~/Downloads/jdk-11.0.1_osx-x64_bin.tar.gz ~/java/
    cd ~/java

Unpack it:

    tar xvf jdk-11.0.1_osx-x64_bin.tar.gz


## Activate Java 11

To use Java 11, activate it. In a terminal:

    export PATH=${HOME}/java/jdk-11.0.1.jdk/Contents/Home/bin:${PATH}

Then you can use it:

    java -version

To deactivate it, just close the terminal.


## Install Gradle

Go to https://gradle.org/install/ and download the `binary-only` distribution.

Move it somewhere, e.g.:

```
mkdir -p ${HOME}/gradle
mv ~/Downloads/gradle-7.2-bin.zip ~/gradle/
cd ${HOME}/gradle
```

Unpack it:

```
unzip gradle-7.2-bin.zip
```


## Activate Gradle

Make sure your PATH can see the Gradle `bin` directory:

```
export PATH=${PATH}:${HOME}/gradle/gradle-7.2/bin
```

Confirm the version:

```
gradle -v
```


## Install Ghidra

Download Ghidra:

    curl https://ghidra-sre.org/ghidra_9.2.3_PUBLIC_20210325.zip --output ~/Downloads/ghidra_9.2.3_PUBLIC_20210325.zip

Move it somewhere, e.g.:

    mkdir -p ~/ghidra
    mv ~/Downloads/ghidra_9.2.3_PUBLIC_20210325.zip ~/ghidra/
    cd ~/ghidra

Unpack it:

    unzip ghidra_9.2.3_PUBLIC_20210325.zip

The Ghidra Installation Directory is now at `~/ghidra/ghidra_9.2.3_PUBLIC`.

Inside the Ghidra Installation Directory, e.g., `~/ghidra/ghidra_9.2.3_PUBLIC`, the GUI can be started by running the `ghidraRun` program. The headless version can be run by executing the `support/analyzeHeadless` program. 

Export both of these locations on your PATH so they can easily be found:

    cd ~/ghidra/ghidra_9.2.3_PUBLIC
    export PATH=$(pwd):$(pwd)/support:${PATH}

Create a `projects` directory and a `scripts` directory:

    mkdir -p ~/ghidra/projects
    mkdir -p ~/ghidra/scripts

Export these locations too, for convenince:

    export GHIDRA_PROJECTS=${HOME}/ghidra/projects
    export GHIDRA_SCRIPTS=${HOME}/ghidra/scripts


## Starting Ghidra GUI

* Navigate to the ghidra installation directory. 
* Double click `ghidraRun`. 
* macOS (BigSur) will say you can't open it because it's not a certified Apple developer. Click 'Ok'.
* Go to System Preferences > Security & Privacy, and click the `General` tab. 
* There should be a button that says `Open Anyway' for `ghidraRun`. Click it.
* It will present a confirmation pop up. Click 'Open'.
* Ghidra will ask for the JDK HOME directory. Type it in (without any variables). E.g., `/Users/me/java/jdk-16.0.1.jdk/Contents/Home`
* Click `Agree` at the startup screen.
* Then you should be in.


## Running Ghidra Headless

To execute Ghidra headless, call the `analyzeHeadless` program. It takes two required arguments:

    analyzeHeadless PATH_TO_PROJECTS PROJECT_NAME

The `PATH_TO_PROJECTS` argument should be a path to a folder where you want Ghidra to store your projects. E.g., `${GHIDRA_PROJECTS}` (i.e., `~/ghidra/projects`).

The `PROJECT_NAME` must be the name of a project. If that project doesn't exist, Ghidra will create it for you. If it does exist, headless-Ghidra will try to acquire a lock on it. If you are working on the project elsewhere (say, in the GUI), then it will already be locked, and headless-Ghidra will error, saying it can't get a lock no the project. So, you can only work on one project at a time.

To import a binary into a project:

    analyzeHeadless ${GHIDRA_PROJECTS} MyProject \
        -import /path/to/exe

To re-import (overwrite) a binary into a project:

    analyzeHeadless ${GHIDRA_PROJECTS} MyProject \
        -import /path/to/exe \
        -overwrite

To run an analysis of an already imported binary, use the `-process EXE_NAME` argument. For example:

    analyzeHeadless ${GHIDRA_PROJECTS} MyProject -process hello.exe

To analyze a program, but not save any results, use the `-readonly` flag:

    analyzeHeadless ${GHIDRA_PROJECTS} MyProject \
        -process hello.exe \
        -readonly

To run a script, add a `-scriptPath` (pointing to the folder containing your scripts) and a `-preScript` or `-postScript`, e.g.:

    analyzeHeadless ${GHIDRA_PROJECTS} MyProject \
        -process hello.exe \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -postScript MyAnalysis.java

Helpful examples for running headless can be found here:

* https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html#examples


## Quirk

If I decompile a simple binary with Ghidra in macOS, it gets a completely
raw binary with no information. It's all question marks.

However, I can mount a Ubunut 20 container with Ghidra in it to my local filesystem, 
then use headless Ghidra to decompile the project inside a Ubuntu 20 container:

    analyzeHeadless /path/to/ghidra/projects Test/01 -import /path/to/exe

Then back on my macOS system, I open the project with Ghidra GUI, and it will have all
the nice info like functions and instructions in it.


## Passing arguments to a script (Java)

In `~/ghidra/scripts`, create a script called `ArgPrinter.java` with these contents:

```
import ghidra.app.util.headless.HeadlessScript;

public class ArgPrinter extends HeadlessScript {

  @Override
  public void run() throws Exception {

    // Don't do more passes after this script.
    setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    // Get args.
    String[] args = getScriptArgs ();
    println(String.format("Number of args: %d", args.length));

    // Print them.
    for (int i = 0; i < args.length; i++) {
      System.out.println("args[" + i + "]: " + args[i]);
    }

    return;

  }

}
```

This script doesn't do analysis on a program. It just prints out the arguments passed to it. 

To run a script that does no analysis on a program, use this command: 

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript ArgPrinter.java

At the end of the output, you should see Ghidra say that it got zero arguments:

```
...
INFO  HEADLESS: execution starts (HeadlessAnalyzer)  
INFO  Opening existing project: ~/ghidra/projects/Foo (HeadlessAnalyzer)  
INFO  Opening project: ~/ghidra/projects/Foo (HeadlessProject)  
INFO  SCRIPT: ~/ghidra/scripts/ArgPrinter.java (HeadlessAnalyzer)  
INFO  ArgPrinter.java> Number of args: 0 (GhidraScript) 
```

Here's how to pass the script the arguments `arg1`, `arg2`, and `arg3`:

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript ArgPrinter.java arg1 arg2 arg3

This time, you should see it print out the arguments:

```
...
INFO  ArgPrinter.java> Number of args: 3 (GhidraScript)  
args[0]: arg1
args[1]: arg2
args[2]: arg3
```


## Passing arguments to a script (Python)

In `~/ghidra/scripts`, create a script called `argprinter.py` with these contents:

```
from ghidra.app.util.headless import HeadlessScript

args = getScriptArgs()
print("Number of args: {}".format(len(args)))
        
for i, arg in enumerate(args):
    print("args[{}]: {}".format(i, arg))
```

Run it the same as running a java script:

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript argprinter.py

At the end of the output, you should see Ghidra say that it got zero arguments:

```
...
INFO  SCRIPT: ~/ghidra/scripts/Simple/argprinter.py (HeadlessAnalyzer)  
Number of args: 0
```

Here's how to pass the script the arguments `arg1`, `arg2`, and `arg3`:

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript argprinter.py arg1 arg2 arg3

This time, you should see it print out the arguments:

```
...
INFO  SCRIPT: ~/ghidra/scripts/Simple/argprinter.py (HeadlessAnalyzer)  
Number of args: 3
args[0]: arg1
args[1]: arg2
args[2]: arg3
```


## Getting the Pseudo-C of all functions

In the `${GHIDRA_SCRIPTS}` directory, create a script called `funcs_pseudoc.py` with these contents:

```
from ghidra.app.decompiler import DecompInterface

import __main__ as ghidra


def decompile_func(decompiler, func, timeout=None):
    """Decompile a function."""
    result = decompiler.decompileFunction(func, 0, timeout)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction()

def run():
    """Starts up and runs the script."""

    # Get command line args.
    args = ghidra.getScriptArgs()

    # Get info about the program.
    prog = ghidra.currentProgram
    funcs = prog.getListing().getFunctions(True)

    # Initialize a decompiler for this program.
    decompiler = DecompInterface()
    program = decompiler.openProgram(prog)

    # Decompile all the functions.
    print("Decompiling functions...")
    for func in funcs:
        result = decompile_func(decompiler, func)
        if result:
            pseudo_c = result.getC()
            print(pseudo_c)
        else:
            print("-- Got no results for this func")

    print("Done")

if __name__ == "__main__":
    run()
```

Run it (using `-readOnly` and `-noanalysis` since we don't need to save anything):

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript funcs_pseudoc.py \
        -process hello.exe \
        -readOnly \
        -noanalysis


## Getting the P-Code of all instructions

In the `${GHIDRA_SCRIPTS}` directory, create a script called `instructions_pcode.py` with these contents:

```
from ghidra.program.model.listing import Instruction

import __main__ as ghidra

def run():
    """Starts up and runs the script."""

    # Get command line args.
    args = ghidra.getScriptArgs()

    # Get info about the program.
    prog = ghidra.currentProgram
    listing = prog.getListing()
    instructions = listing.getInstructions(True)

    # Get the PCode for the instructions.
    print("Getting PCode ...")
    for instruction in instructions:
        ctxt = instruction.getInstructionContext()
        addr = ctxt.getAddress()
        print("{}:".format(addr.toString()))
        pcodes = instruction.getPcode()
        for pcode in pcodes:
            print("  {}".format(pcode.toString()))

    print("Done")

if __name__ == "__main__":
    run()
```

Run it:

    analyzeHeadless ${GHIDRA_PROJECTS} Foo \
        -scriptPath ${GHIDRA_SCRIPTS} \
        -preScript instructions_pcode.py \
        -process hello.exe \
        -readOnly \
        -noanalysis


## Example of P Code

Some pcode:

```
00010400:
  (unique, 0x5d0, 4) INT_RIGHT (const, 0x5, 4) , (const, 0x1f, 4)
  (unique, 0x5e0, 1) INT_EQUAL (const, 0x0, 1) , (const, 0x0, 1)
  (unique, 0x5f0, 1) BOOL_AND (unique, 0x5e0, 1) , (register, 0x62, 1)
  (unique, 0x600, 1) INT_NOTEQUAL (const, 0x0, 1) , (const, 0x0, 1)
  (unique, 0x610, 1) SUBPIECE (unique, 0x5d0, 4) , (const, 0x0, 4)
  (unique, 0x620, 1) BOOL_AND (unique, 0x600, 1) , (unique, 0x610, 1)
  (register, 0x68, 1) BOOL_OR (unique, 0x5f0, 1) , (unique, 0x620, 1)
  (register, 0x20, 4) COPY (const, 0x5, 4)
  (register, 0x64, 1) INT_SLESS (register, 0x20, 4) , (const, 0x0, 4)
  (register, 0x65, 1) INT_EQUAL (register, 0x20, 4) , (const, 0x0, 4)
  (register, 0x66, 1) COPY (register, 0x68, 1)
  (register, 0x67, 1) COPY (register, 0x63, 1)
00010404:
  (unique, 0x0, 4) INT_AND (register, 0x58, 4) , (const, 0x1, 4)
  (register, 0xb0, 1) INT_NOTEQUAL (unique, 0x0, 4) , (const, 0x0, 4)
  (register, 0x69, 1) COPY (register, 0xb0, 1)
  (register, 0x5c, 4) INT_AND (register, 0x58, 4) , (const, 0xfffffffe, 4)
   ---  RETURN (register, 0x5c, 4)
```

Which corresponds to this from `objdump`:

```
00010400 <main>:
   10400:	e3a00005 	mov	r0, #5
   10404:	e12fff1e 	bx	lr
```


## Ghidra Extensions

The installation location for extensions is here:

```
${GHIDRA_HOME}/Extensions/Ghidra

```

There are some extensions already there (each is packaged as a `*.zip` file). These extensions come with every Ghidra installation.

To install a new extension, put the `*.zip` file in this directory, then from the main Ghidra GUI window (not the Code Browser), go to `File > Install Extensions`. 

After installing an extension, you may need to restart Ghidra. Then, you need to configure the plugin. To do that, you need to open the code browser for a program. It will autodetect that there is a new extension, and ask you if you would like to configure it. 

(To start the code browser from the main Ghidra GUI window, go to `Tools > Run Tool > Code Browser`.)


### Sample Extensions

There are some scaffolded "skeletons" for different kinds of extensions at:

```
${GHIDRA_HOME}/Extensions/Ghidra/Skeleton
```

In particular, look in `src/main/java/skeleton` for, say, the `SkeletonPlugin.java` file.


### Creating and Publishing an Extension

Create a new module project in Eclipse: `GhidraDev > New > Ghidra Module Project...` and call it, e.g., `MyDemoPlugin`. Click on `Next` instead of `Finish` and select the Plugin option. Use `Next` to set the Ghidra version and to enable Python if you need. Then click `Finish`. That will create the project.

Replace the contents of `build.gradle` with this:

```
def ghidraInstallDir

if (System.env.GHIDRA_INSTALL_DIR) {
  ghidraInstallDir = System.env.GHIDRA_INSTALL_DIR
}
else if (project.hasProperty("GHIDRA_INSTALL_DIR")) {
  ghidraInstallDir = project.getProperty("GHIDRA_INSTALL_DIR")
}

if (ghidraInstallDir) {
  apply from: new File(ghidraInstallDir).getCanonicalPath() + "/support/buildExtension.gradle"
}
else {
  throw new GradleException("GHIDRA_INSTALL_DIR is not defined!")
}
```

When you're ready to publish, go to `File > Export`, choose `Ghidra Module Extension`, and click on `Next`. Select the `MyDemoPlugin` project and click `Next`. Select your Gradle installation directory, e.g., `${HOME}/gradle/gradle-7.2`, then click `Finish`.

When it finishes, there will be a `dist` folder at the project's root. Copy the `*.zip` file into `${GHIDRA_HOME}/Extensions/Ghidra/`. 

Then, from the main Ghidra GUI window, go to `File > Install Extensions` as described above, and install the extension (restarting and configuring as needed).


### Building Plugins Manually

To build a plugin manually (from the command line), go to the root of the project (where the `build.gradle` file lives), and invoke `gradle`. In order for this to work, Gradle needs to know the `GHIDRA_INSTALL_DIR` (an absolute path to the Ghidra installation directory). You can export the path as environment variable:

```
export GHIDRA_INSTALL_DIR=/path/to/Ghidra/installation/dir
gradle
```

Or you can specify it as a parameter to gradle:

```
gradle -PGHIDRA_INSTALL_DIR=/path/to/Ghidra/installation/dir
```


## Plugin-like scripts

It's possible to construct a plugin from a Ghidra script. E.g., `my_pluggy.py`:

```
# JT: My pluggy
# Just a dummy plugin-style script.
#
# @category JT
# @menupath JT.My Pluggy

from docking import ComponentProvider
from ghidra.app.plugin import ProgramPlugin
from java.awt import BorderLayout
from javax.swing import JPanel, JTextArea, JScrollPane

class MyProvider(ComponentProvider):

    def __init__(self, tool, name):
        super(MyProvider, self).__init__(tool, name, name)
        self.setTitle(name)
        self.setVisible(True)
        self.build_panel()

    def build_panel(self):
        layout_manager = BorderLayout()
        self.panel = JPanel(layout_manager)
        text_area = JTextArea(5, 25)
        text_area.setEditable(False)
        scroll_pane = JScrollPane(text_area)
        self.panel.add(scroll_pane)

    def getComponent(self):
        return self.panel

class MyPluggy(ProgramPlugin):

    def __init__(self, tool):
        super(MyPluggy, self).__init__(tool, True, True)
        plugin_name = "My pluggy"
        provider = MyProvider(tool, plugin_name)

state = getState()
project = state.getProject()
program = state.getCurrentProgram()
tool = state.getTool()

plugin = MyPluggy(tool)
```
