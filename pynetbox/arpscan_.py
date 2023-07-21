##
## https://gist.github.com/jsenecal/204e86e5f8ca0f2c8bc0a5891ba22570
##
##

import requests
import pynetbox

from termcolor import colored
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_napalm.plugins.tasks import napalm_get
from nornir.core.filter import F

# NetBox Layer 3 switches (Base Inventory Group Defined in the config file below)
nr = InitNornir(config_file="../inventory/nornir_nb_bench.yaml")

# Setup NetBox API session handler with info from nornir config file
session = requests.Session()
session.verify = nr.config.inventory.options['ssl_verify']
nb = pynetbox.api(nr.config.inventory.options['nb_url'], nr.config.inventory.options['nb_token'])

# Create the netbox object
nb.http_session = session

nr = nr.filter(F(device_role__name__contains="Switch-Layer-3") & ~F(platform='linux') &
               F(status__value__contains='active') & F(name__contains="-RA"))

nr.inventory.hosts

print(nr.inventory.hosts)


arp_table = nr.run(task=napalm_get, getters=["get_arp_table"])

for i in arp_table:
    arps = arp_table[i][0].result['get_arp_table']
    print("*" * 40)
    print(i)
    print("*" * 40)

    j = 0
    for k in arps:
        nb_ip = nb.ipam.ip_addresses.get(address=arps[j]['ip'])
        if not nb_ip:
            if nb_ip is not None:
                if '128.0.0.16' in nb_ip.address or '192.168.1.1' in nb_ip.address:
                    print(f"{arps[j]['ip']} --> NOT FOUND IN NETBOX!!!")
                    j += 1
        else:
            nb_ip = nb.ipam.ip_addresses.get(address=arps[j]['ip'])
            if nb_ip.assigned_object is None:
                print(colored(f"{arps[j]['mac']} | {arps[j]['interface'].ljust(22)} | {nb_ip.address.ljust(18)} {nb_ip.status.value.ljust(66)}  NO DEVICE IN NETBOX", 'red', attrs=['bold']))
            else:
                if '/31' in nb_ip.address or 'Management1' in arps[j]['interface'] or 'em0.0' in arps[j]['interface']:
                    pass
                else:
                    print(f"{arps[j]['mac']} | {arps[j]['interface'].ljust(22)} | {nb_ip.address.ljust(16)}  {nb_ip.status.value.ljust(10)} {nb_ip.tenant.name.ljust(15)} DNS: {nb_ip.dns_name.ljust(35)} {nb_ip.assigned_object.device.name} ")

            j += 1
