from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)



string_and_funcdata=[]
functionManager = currentProgram.getFunctionManager()
for string in DefinedDataIterator.definedStrings(currentProgram):
  for ref in XReferenceUtil.getXRefList(string):
    #print(string, ref)
    #string_and_funcdata.extend([string,ref])
    addr=getAddress(hex(int('0x'+str(ref),16)))
    #print(addr)
    #print(functionManager.getFunctionContaining(addr))
    name_of_function=functionManager.getFunctionContaining(addr)
    temp_list=[]
    temp_list.extend([str(string),str(ref),str(name_of_function)])
    #print(temp_list)
    string_and_funcdata.append(temp_list)
#print (string_and_funcdata[0:100])
func_data={}

for li in string_and_funcdata:
   if li[2] in func_data.keys():    
       temp_list=[]
       temp_list.extend([li[0],li[1]])  
       func_data[li[2]].append(temp_list)
 
   if  li[2]!='None' and not(li[2] in func_data.keys()) :
       func_data[li[2]]=[]
       temp_list=[]
       temp_list.append([li[0],li[1]])
       func_data[li[2]].extend(temp_list)
   
print(func_data) 

Vulnerability Analysis with Ghidra Scripting
Craig Young
Craig Young

·

##
#
https://medium.com/@cy1337/vulnerability-analysis-with-ghidra-scripting-ccf416cfa56d
#
##



As some of you may have seen, I posted a challenge to use Ghidra to identify a vulnerability in a WarGames themed game. There has been a lot of interest in and downloads of this challenge but nobody has come back yet to let me know they solved it. What I have received are questions about where to even begin with this kind of challenge.

In this post, we’ll look at where to begin when using Ghidra to seek out vulnerabilities in a compiled program. Similar to how I approach source code analysis, I often start analyzing programs by identifying references to commonly dangerous library functions. The focus of this post is how to develop a very simple Ghidra Python script that enumerates calls to a given list of functions.

Before we get into it again, the challenge binary can be downloaded from https://secur3.us/GhidraFiles/wopr and it can be run within a Docker container by either building from my GitHub repo or pulling the built image from my DockerHub repo. Please note that you will need to run in interactive mode:

docker run -it cy1337demos/wopr:1.0.0

With that out of the way, let’s move on to the aforementioned Ghidra Python script to locate risky function calls…

Ghidra has a few options when it comes to extending functionality with custom scripts. Ghidra is written in Java and can be extended by writing Java code that will be loaded directly into the running process or, you can alternatively use a Jython interface to author scripts in Python. Beyond that, Ghidra also has multiple APIs to choose from. For the purpose of this post, we will craft a basic Python Ghidra script.

In order to kick start this process and to keep things interesting, I decided to ask ChatGPT to get us started with a list of dangerous functions.

Hey ChatGPT, could you generate a list of the top 10 most commonly exploited libc functions referenced by the most recent 3 years of CVE data you have access to? The output should be presented as a Python dictionary called DANGEROUS_FUNCTIONS where the key is the function name and the value is a comment (starting #) which reflects how it is dangerous.

DANGEROUS_FUNCTIONS = {
    'memcpy': "# Can be used for buffer overflow or arbitrary memory write",
    'strcpy': "# Can be used for buffer overflow or arbitrary memory write",
    'sprintf': "# Can be used for format string vulnerabilities",
    'strncpy': "# Can be used for buffer overflow or arbitrary memory write",
    'memset': "# Can be used for buffer overflow or arbitrary memory write",
    'read': "# Can be used for file descriptor hijacking or denial-of-service",
    'fgets': "# Can be used for buffer overflow",
    'fread': "# Can be used for buffer overflow",
    'realloc': "# Can be used for buffer overflow or arbitrary memory write",
    'fwrite': "# Can be used for buffer overflow"
}
Now we need to prepare some logic to find references to these functions within a program.

The list of functions discovered in Ghidra’s analysis can be accessed through the Function Manager:

currentProgram.getFunctionManager().getFunctions(True)
We can iterate over a filtered list of functions as follows:

for f in filter(lambda f: f.getName() in DANGEROUS_FUNCTIONS.keys(), currentProgram.getFunctionManager().getFunctions(True)):
For each function in that iteration, we can obtain an address to cross reference by calling the getEntryPoint() method. References to that address are accessed via GetReferencesTo() which can then be filtered based on reference type as follows:

filter(lambda r: r.getReferenceType() == FlowType.UNCONDITIONAL_CALL, getReferencesTo(f.getEntryPoint()))
The address of each reference is available as ref.getFromAddress(). After putting this together along and adding some lines for checking if the task was cancelled and printing the output, I have the following:

for f in filter(lambda f: f.getName() in DANGEROUS_FUNCTIONS.keys(), currentProgram.getFunctionManager().getFunctions(True)):
    new_func_name = True
    if monitor.isCancelled(): break
    for ref in filter(lambda r: r.getReferenceType() == FlowType.UNCONDITIONAL_CALL, getReferencesTo(f.getEntryPoint())):
        if monitor.isCancelled(): break
        if new_func_name:
            print(DANGEROUS_FUNCTIONS[f.getName()])
            new_func_name = False
        print("%s => %s (%s)" % (ref.getFromAddress(), f.getName(), ref.getReferenceType()))
The ideal way to use this Ghidra script is by loading it into Ghidra’s Script Manager. The complete implementation from this blog post can be downloaded from https://secur3.us/GhidraFiles/danger_check.py and is reproduced here for reference:

# Ghidra Python script to list cross-references to dangerous functions.
#
# Usage: Run the script in Ghidra's Script Manager with the target binary loaded.
# Output: Lists the cross-references to dangerous functions as hyperlinks in the Console.

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import FlowType

DANGEROUS_FUNCTIONS = {
    'memcpy': "# Can be used for buffer overflow or arbitrary memory write",
    'strcpy': "# Can be used for buffer overflow or arbitrary memory write",
    'sprintf': "# Can be used for format string vulnerabilities",
    'strncpy': "# Can be used for buffer overflow or arbitrary memory write",
    'memset': "# Can be used for buffer overflow or arbitrary memory write",
    'read': "# Can be used for file descriptor hijacking or denial-of-service",
    'fgets': "# Can be used for buffer overflow",
    'fread': "# Can be used for buffer overflow",
    'realloc': "# Can be used for buffer overflow or arbitrary memory write",
    'fwrite': "# Can be used for buffer overflow"
}

for f in filter(lambda f: f.getName() in DANGEROUS_FUNCTIONS.keys(), currentProgram.getFunctionManager().getFunctions(True)):
    new_func_name = True
    if monitor.isCancelled(): break
    for ref in filter(lambda r: r.getReferenceType() == FlowType.UNCONDITIONAL_CALL, getReferencesTo(f.getEntryPoint())):
        if monitor.isCancelled(): break
        if new_func_name:
            print(DANGEROUS_FUNCTIONS[f.getName()])
            new_func_name = False
        print("%s => %s (%s)" % (ref.getFromAddress(), f.getName(), ref.getReferenceType()))

Script output from wopr challenge
Clicking the addresses in that console output jumps the Ghidra cursor to that location for further inspection.

