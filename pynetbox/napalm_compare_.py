import napalm
from netaddr import IPNetwork
import pynetbox
import yaml
import difflib

try:
    from colorama import Fore, Back, Style, init
    init()
except ImportError:  # fallback so that the imported classes always exist
    class ColorFallback():
        __getattr__ = lambda self, name: ''
    Fore = Back = Style = ColorFallback()

def color_diff(diff):
    for line in diff:
        if line.startswith('+'):
            yield Fore.GREEN + line + Fore.RESET
        elif line.startswith('-'):
            yield Fore.RED + line + Fore.RESET
        elif line.startswith('^'):
            yield Fore.BLUE + line + Fore.RESET
        else:
            yield line

nb = pynetbox.api(
    'http://netbox.lab',
    token='8f0c6b37619e23dd6223e4df3efc76bb1cd18da4')


d = "devicename"
nb_device = nb.dcim.devices.get(name=d)
nb_interfaces = nb.dcim.interfaces.filter(device=d)
nb_ips = nb.ipam.ip_addresses.filter(device=d)

primary_ip4 = IPNetwork(str(nb_device.primary_ip4))
platform = str(nb_device.platform)

driver = napalm.get_network_driver(platform)
device = driver(
        hostname=str(primary_ip4.ip),
        username="orion-ncm",
        password="passsword",
)

device.open()

interfaces = device.get_interfaces()
l_interfaces = list(interfaces.keys())
interface_ips = device.get_interfaces_ip()

nb_dict = {}
for ip in nb_ips:
    ipn = IPNetwork(str(ip))
    iface = ip.interface
    description = iface.description
    family = "ipv" + str(ipn.version)
    nb_dict[str(iface)] = {"description": description, family: { str(ipn.ip): { "prefix_length" : ipn.prefixlen}}}

a = yaml.dump(nb_dict)
b = yaml.dump(interface_ips)

al = a.splitlines()
bl = b.splitlines()

diff = difflib.ndiff(al,bl)
adiff = color_diff(diff)
al1 = '\n'.join(adiff).splitlines()

diff = difflib.ndiff(bl,al)
bdiff = color_diff(diff)
bl1 = '\n'.join(bdiff).splitlines()

fmt = '{:<80}{:50}'

print(fmt.format('device', 'netbox'))
for i, (dev, netbox) in enumerate(zip(al1, bl1)):
    if netbox.startswith("\x1b"): netbox = "          " + netbox
    print(fmt.format(dev, netbox))

##
##
