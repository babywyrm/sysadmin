#######################
##
##

We’ve all been there, you just want to hack up a quick Ansible playbook to do a quick task, and then you find yourself fighting with syntax, chopping and changing things around, wondering why this simple Ansible playbook isn’t working. Let me give you a few hints to make your life easier.
This is especially useful if you’re on a new machine that doesn't come with all your personal configuration, dotfiles and preferred editors! This happens to me quite a lot when setting up new environments.
1) shebang your playbooks! Aherm.
You’ve seen it a thousand times, looking at bash scripts, python code, etc, the comment at the top of the file that tells your shell how to execute it.

###################################

#!/usr/bin/env bash
echo “I am a funky Bash script”
…. and in python…
#!/usr/bin/env python
echo “Hello from python!”
Well, this line starting with “#!” is a “shebang”. There’s no reason you cannot use that with Ansible too, making it much quicker than typing “ansible-playbook … “ every time to execute it.
#!/usr/bin/env ansible-playbook
---
hosts: 
  - server
...
and execute like this;
./myPlaybook.yml

Much nicer! And as long as you use “env” to find ansible-playbook, you can still pass standard arguments;

./myPlaybook.yml -i myInventory -v
2) tab-stop, and smart indent (vim)
I use Vim, with quite a long .vimrc that is Git version controlled, but often this isn’t available on hosts that I ssh into into infrequently. Don’t be afraid of spending 15 seconds writing a new .vimrc file that makes writing those damned YAML files a whole lot easier — tab-stop and smart indenting.
set ts=2
set smartindent
These two lines, when added to your ~/.vimrc file will save you oodles of time. YAML is really sensitive to tab widths, and vim will default to 4 spaces — throwing all your nice YAML with syntax errors in time.
Smart intenting allows vim to follow your current tab, and when you press “Enter” for a new line, it will start at your current tab column width. This, again, makes editing yaml with Vim so much quicker.
3) Don’t be afraid to specify hosts in the playbook
Ideally, every playbook should be written so it can work with any number of hosts, but if you’re just doing a quick, simple task, then you can just use /etc/ansible/hosts as your inventory and limit your hosts statically in a playbook, see below;
example /etc/ansible/hosts
[webservers]
server1
server2
[databases]
server3
Here are two examples below — note that the “-” in Ansible indicates a list (as per the individual server name example), otherwise, it’s a single item (as per the hostgroup example).
Example quick and dirty playbook, statically set for 2x hosts;
hosts: 
  - server1
  - server2
tasks:
  - debug:
      msg: "Hello from {{ ansible_hostname }}!"
Example quick and dirty playbook, statically set for a hostgroup;
hosts: databases
tasks:
  - debug:
      msg: "Hello from {{ ansible_hostname }}!"
Summary
Those were 3 quick tips to making your life easier when writing quick Ansible playbooks! I hope that helps ;)
James Read’s Code, Containers and Cloud blog
Code inside containers that run on the cloud!


Follow
14



