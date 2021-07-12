ansible-hacking
<br>
Run Python code (without modifications) inside or outside (for debugging) the Ansible framework
<br>
<br>

The goal of this effort is to create a efficient and easy to use, and ephemeral remote development environment. I wanted to be more efficient and productive in developing code. Some considerations:

Desire to create a development host independent of the laptop OS, using an ephemeral environment (Vagrant)
Ability to run current Ansible production code (rather that installing from source for testing)
Use of effective debugging tools, (PyCharm Pro, pydevd)
Additionally, Other than adding the necessary pydevd commands, I wanted an executable which would run without modifications in either test mode or production mode.

The underlying theme is to create environments where a network engineer who is learning NetDevOps concepts can learn without the distractions of system administration.

App development in Phantom Cyber implements the approach of running Python modules from the shell (uid phantom) in test mode which reads a JSON file to pass parameters. Once the app is functional in that environment, you use their compiler to check the app and app description file, and then optionally install into the Phantom GUI framework. Co-winners of the Phantom app contest, Mauricio Velazco and Nelson Santos, highlighted how useful the remote debugging feature of PyCharm Pro was in their development efforts. I wanted to leverage that concept for my Ansible environment.

The Setup
We have created a Ubuntu Virtual Machine with Vagrant. Ansible is installed using the Latest Releases Via Apt using this Vagrantfile.

By default Ansible will look for user modules in ./library from the playbook directory, and /usr/share/ansible. I've specified these locations in my ansible.cfg file as a reminder.

$ more ansible.cfg
[defaults]
inventory      = /home/ubuntu/ansible/playbooks/hosts
library        = /home/ubuntu/ansible/playbooks/library:/usr/share/ansible
My hosts file is empty, we are only using local host. Ansible will complain, ignore it.

$ ansible --version
ansible 2.3.0.0
  config file = /home/ubuntu/ansible/playbooks/ansible.cfg
  configured module search path = [u'/home/ubuntu/ansible/playbooks/library', u'/usr/share/ansible']
  python version = 2.7.12 (default, Nov 19 2016, 06:48:10) [GCC 5.4.0 20160609]
Modules
In this example, the main module we want to test is meraki_vlan.py which imports Meraki_Connector. The ansible_hacking.py module is also present in this directory along with the associated ansible_hacking.json file containing arguments for execution. The upload feature of PyCharm can be used to upload the module(s) we are developing. Download the ansible_hacking Python and JSON with cURL or wget, dropping it in the library directory.

ubuntu@ubuntu-xenial:~/ansible/playbooks/library$ ls -lt
total 44
-rw-rw-r-- 1 ubuntu ubuntu   282 May 12 15:34 ansible_hacking.json
-rwxr-xr-x 1 ubuntu ubuntu  2055 May 12 15:31 ansible_hacking.py
-rw-rw-r-- 1 ubuntu ubuntu  4528 May 12 12:24 meraki_vlan.py
-rw-rw-r-- 1 ubuntu ubuntu 11779 May  3 12:53 Meraki_Connector.py
The meraki_vlan.py module will attempt to import the AnsibleModule class from ansible_hacking, if not found, defaults to the normal ansible import. The code snippet is as:

try:
    from ansible_hacking import AnsibleModule              # Test
except ImportError:
    from ansible.module_utils.basic import *               # Production
main()
If we were to run this module using an Ansible playbook, the task would look similar to the following:

  - name: manage vlans
    meraki_vlan:
      dashboard: "{{inventory_hostname}}"
      organization: "{{meraki.organization}}"
      api_key: "{{meraki_params.apikey}}"
      action: add                            # add, delete update
      network: "{{meraki.network}}"          # Name of the network
      id: "1492"                             # VLAN number
      name: VLAN1492                         # VLAN name
      applianceIp: "192.0.2.1"               # Default Gateway IP address
      subnet: "192.0.2.0/24"                 # Layer 3 network address of the VLAN
Input file
For our testing, create a file ansible_hacking in JSON format to present the arguments.

{
    "subnet": "203.0.113.0/24",
    "network": "KINGJOE",
    "applianceIp": "203.0.113.1",
    "dashboard": "dashboard.meraki.com",
    "action": "add",
    "organization": "WWTINC",
    "api_key": "bf89redactedfac313c87a1",
    "id": "1492",
    "name": "NET3"
}
Test execution
Execute the module by invoking python and specify meraki_vlan.py. For debugging, we output the value of argument_spec used for production execution, but we don't process it.

~/ansible/playbooks/library$ python meraki_vlan.py
Entered ansible_hacking, AnsibleModule
{
    "argument_spec": {
        "subnet": {
            "required": true
        },
        "network": {
            "required": true
        },
        "applianceIp": {
            "required": true
        },
        "dashboard": {
            "required": true
        },
        "action": {
            "default": "add",
            "required": false,
            "choices": [
                "add",
                "delete",
                "update"
            ]
        },
        "organization": {
            "required": true
        },
        "api_key": {
            "required": true
        },
        "id": {
            "required": true
        },
        "name": {
            "required": true
        }
    }
}
loading params from ansible_hacking.json
params:
{
    "subnet": "203.0.113.0/24",
    "network": "KINGJOE",
    "applianceIp": "203.0.113.1",
    "dashboard": "dashboard.meraki.com",
    "action": "add",
    "organization": "WWTINC",
    "api_key": "bf89redactedfac313c87a1",
    "id": "1492",
    "name": "NET3"
}
Exiting AnsibleModule __init__
{
    "status_code": 201,
    "changed": true,
    "result": {
        "networkId": "L_62redacted25030308",
        "subnet": "203.0.113.0/24",
        "fixedIpAssignments": {},
        "name": "NET3",
        "applianceIp": "203.0.113.1",
        "reservedIpRanges": [],
        "dnsNameservers": "upstream_dns",
        "id": 1492
    }
}
The last bit of JSON above is what the module would normally output when run in the Ansible framework.

Production
From the Meraki dashboard, delete the VLAN created, as we will now execute the same code in the Ansible framework. We also move the ansible_hacking files out of the library directory.

$ mv ansible_hacking* /tmp
What remains are the modules under development.

~/ansible/playbooks/library$ ls -salt
total 44
 4 drwxr-xr-x 2 ubuntu ubuntu  4096 May 12 18:27 .
 4 drwxr-xr-x 3 ubuntu ubuntu  4096 May 12 18:26 ..
 8 -rw-rw-r-- 1 ubuntu ubuntu  4528 May 12 12:24 meraki_vlan.py
16 -rw-rw-r-- 1 ubuntu ubuntu 12583 May 12 01:33 Meraki_Connector.pyc
12 -rw-rw-r-- 1 ubuntu ubuntu 11779 May  3 12:53 Meraki_Connector.py
Go up to the playbook directory. I normally run and store playbooks in this directory.

$ cd ~/ansible/playbooks
Run the same code, this time using Ansible.

~/ansible/playbooks$ ansible localhost -m meraki_vlan  -a "network=KINGJOE id=1492 name=NET3 organization=WWTINC applianceIp=203.0.113.1 subnet=203.0.113.0/24 api_key=bf89redactedfac313c87a1 dashboard=dashboard.meraki.com"
 [WARNING]: Host file not found: /home/ubuntu/ansible/playbooks/hosts

 [WARNING]: provided hosts list is empty, only localhost is available

localhost | SUCCESS => {
    "changed": true,
    "result": {
        "applianceIp": "203.0.113.1",
        "dnsNameservers": "upstream_dns",
        "fixedIpAssignments": {},
        "id": 1492,
        "name": "NET3",
        "networkId": "L_62redacted25030308",
        "reservedIpRanges": [],
        "subnet": "203.0.113.0/24"
    },
    "status_code": 201
}
From the above, you can see that we have successfully executed the same module inside the Ansible production environment without modifications.

Module Documentation
Additionally, we can successfully run ansible-doc.

~/ansible/playbooks$ ansible-doc meraki_vlan
> MERAKI_VLAN    (/home/ubuntu/ansible/playbooks/library/meraki_vlan.py)

  Manage VLANs on Meraki Networks

            [lines removed for breviety]

MAINTAINERS: Joel W. King, (@joelwking) World Wide Technology

METADATA:
        Status: ['preview']
        Supported_by: community
Invoking with PyCharm Professional
At this point, the only use of PyCharm was to upload the module(s) under development. Move the ansible_hacking module back to the library directory, and run the meraki_vlan using the remote Python interpreter feature. More on that configuration in a separate post.

~/ansible/playbooks/library$ mv /tmp/ansible_hacking.* ./
ubuntu@ubuntu-xenial:~/ansible/playbooks/library$ ls
ansible_hacking.json  ansible_hacking.py  ansible_hacking.pyc  Meraki_Connector.py  Meraki_Connector.pyc  meraki_vlan.py
The output from the first little bit of the PyCharm output window looks as follows:

ssh://ubuntu@192.168.56.200:22/usr/bin/python -u /home/ubuntu/ansible/playbooks/library/meraki_vlan.py
Entered ansible_hacking, AnsibleModule 
{
    "argument_spec": {
        "subnet": {
            "required": true
        }, 
Remote Debugging
Remote debugging can be enabled in PyCharm Pro and has been tested with the ansible-hacking module.

References:
Debug Ansible Modules remotely in PyCharm on windows
Work remotely with PyCharm, TensorFlow and SSH
Phantom Developer Resources
Getting Ansible
Building A Simple Module
