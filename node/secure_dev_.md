
##
#
https://dmitrychekanov.com/posts/securing-node-js-development-environment-with-app-armor/
#
##


Dmitry Chekanov 
Full stack JavaScript developer.
Independent contractor.

Securing Node.js development environment with AppArmor
Node.js is famous for the abundance of 3rd-party modules that can be added to any project in a matter of seconds.

The ease of expanding program capabilities helps to develop complex software faster. However, the more modules you add, the more trust you put in code written by someone else. Each module has its own dependencies, which in turn have their dependencies, and so on. As a result, even fairly simple projects can easily contain thousands of lines of code written by hundreds of other developers.

While it is unavoidable to give some trust to others when it comes to using external libraries, it does not feel safe to rely on hundreds of people to ensure that their modules are impossible to compromise.

This post describes a way to configure Linux environment to make it safer to develop Node.js projects.

To get an idea of how much baggage is added by any given module, one can use https://npm.anvaka.com. The tool builds a graph of module dependencies. For example, at the time of writing, Express relied on 50 modules.
In production environment it is relatively easy to secure a Node.js process. Running it under a non-privileged user or virtualizing the whole environment are common techniques.

In development environment it gets a bit trickier. For the sake of convenience, it often makes sense to run the process on the same computer where developer runs his IDE, browser, and other tools. When application is started via plain “node index.js”, the process (and all packages used in the project) has access to user files.

Ubuntu does not allow processes running under regular users to bind to port 80. Some developers opt for a quick workaround by executing “sudo node index.js”. This allows node scripts to do anything with the system and is not a sane solution to the problem. One of the good workarounds is to proxy the app through nginx.
Similar to how it’s done in production, a separate user with restricted access can be introduced into the development environment. The solution is viable, but not without drawbacks:

It is required to switch the user to run the app. It might be required 2 times per each project - the first time to launch the main process, the second time to build assets. Constant switching quickly becomes tedious.
Some IDEs still need to run Node.js under the same user that uses the editor (for example, JetBrains needs it to enable ESLint).
Fortunately, there is another way to restrict what a program can do. Ubuntu comes preinstalled with a module called AppArmor, and its purpose is precisely what we need: confining programs.

Information below should be considered a starting point. Please consult with syntax guide and tutorials available elsewhere to customize the solution to your environment.
To restrict a program with AppArmor, a profile must be created, then the AppArmor service configuration must be reloaded.

First, create a new file in /etc/apparmor.d directory. The convention is to use file path with "/" replaced with ".", but any name can be used, especially if there are multiple Node.js versions in the system:
```
$ sudo nano /etc/apparmor.d/node
The file should have the following structure:

PATH_TO_PROGRAM {
  RULE,
  RULE,
}
Each rule must be terminated with a comma (yes, even the last one). AppArmor denies any action not explicitly permitted by rules, so you have to list everything that a program should be able to do.

Below is the profile that works for my environment.

# Variables
#include <tunables/global>

/opt/nvs/** {
  # Access to basic OS functions
  #include <abstractions/base>
  # Communicate with terminals
  #include <abstractions/consoles>
  # Work with history in CLI mode
  /home/*/.node_repl_history rw,
  # Access network
  network,
  # Read DNS resolver parameters
  /run/systemd/resolve/stub-resolv.conf r,
  # Read procfs
  /proc/** r,
  # Read OS configuration
  /etc/** r,
  # Execute OS binaries
  /bin/** ix,
  /usr/bin/** ix,
  # Work with npm and yarn
  /usr/share/yarn/** rix,
  /home/*/.npm/** rwl,
  /home/*/.yarn/** rwl,
  /home/*/.cache/yarn/ rwl,
  /home/*/.cache/yarn/** rwl,
  /home/*/.npmrc rw,
  /home/*/.yarnrc rw,
  # Work with tmp files
  /tmp/ rw,
  /tmp/** rw,
  # Work with NVS
  /opt/nvs/ r,
  /opt/nvs/** rwixlm,
  # Do anything with projects
  /srv/node/** rwixlkm,
  # Work with module configuration stored in user directory
  /home/*/.config/configstore/ rw,
  /home/*/.config/configstore/** rw,
  # Read WebStorm plugin configuration
  /home/*/.local/share/JetBrains/Toolbox/apps/WebStorm/ch-0/*/plugins/** r,
  # Enable Node.js assist in WebStorm
  /home/**/node-typings/ rwixlkm,
  /home/**/node-typings/** rwixlkm,
}
I use NVS to run multiple Node.js versions. Normally, the tool is installed in ~/.nvs, but the point was to forbid Node.js to read the home directory, so it went into /opt/nvs. AppArmor supports wildcards, so “/opt/nvs/**” allowed to assign all existing and future node/npm/global module binaries the same rules.

Reload the service to apply the profile:

$ sudo systemctl reload apparmor
Check service status:

$ sudo aa-status
/opt/nvs/** should be listed under “profiles in enforce mode”.

Verify that Node.js can only do what’s allowed:

$ node
require('fs').readdirSync('/home');
This should produce an error:

{ Error: EACCES: permission denied, scandir '/home'
at Object.readdirSync (fs.js:785:3) errno: -13, syscall: 'scandir', code: 'EACCES', path: '/home' }
Check syslog for details (it’s quite helpful when creating the profile):

$ tail -f /var/log/syslog
DATE COMPUTER_NAME kernel: [888192.041639] audit: type=1400 audit(1555433516.029:9761): apparmor="DENIED"
operation="open" profile="/opt/nvs/**" name="/home/" pid=6845 comm="node" requested_mask="r" denied_mask="r"
fsuid=1000 ouid=0

```        
Securing Node.js with AppArmor is a relatively simple solution that allows to develop applications without giving 3rd-party code unrestricted access to private files.

I hope this brief article was helpful.
