# pynetbox examples

##
##

Long time network engineer, did some perl a long time ago and am liking python pretty well but the pynetbox documentation is badly lacking IMO.  If I were a python wizard I'm sure it would all be obvious but I'm not and it's really frustrating that more example weren't provided.

Many of the following examples were cadged from various places on the interwebs and HAVE NOT BEEN TESTED. 

## Prereqs
```
import pynetbox
NETBOX = 'https://netbox.fq.dn/'
nb = pynetbox.api(NETBOX, get_token('nb'))
```
get_token() is function that fetches the token from a hidden file in the home dir (~) that's named `token_nb`.  I've added it here as a separate file. 

## getting things
### get all the things
```
response = nb.dcim.devices.all()
response = nb.ipam.prefixes.all()
response = nb.ipam.ip_addresses.all()
response = nb.ipam.vlans.get(vlanid)
response = nb.dcim.devices.get(serial=tgt_sn)
```

### get list of things that match your query
```
response_list = nb.dcim.devices.filter(query)
response_list = nb.ipam.prefixes.filter(query)
response_list = nb.ipam.vlans.filter(query)
response_list = nb.tenancy.tenants.filter(query)
response_list = nb.dcim.interfaces.filter(device='DEV_NAME')
```

## deleting things
```
response = nb.ipam.ip_addresses.get(name=line)
response.delete
```

## renaming things
```
response = nb.dcim.devices.get(name=old_name)
response.name = new_name
response.save()
```

## adding interface connection
```
int_a = nb.dcim.interfaces.get(name='xe-4/0/16', device='BLAHSWITCH')
int_b = nb.dcim.interfaces.get(name='eth3', device='BLAHHOST')
nb.dcim.interface_connections.create(
     interface_a=int_a.id,
     interface_b=int_b.id
)
```

## creating things
### create a device
```
netbox.dcim.devices.create(
  name='test',
  device_role=1,
)
```
### create an interface (verified!)
```
response = nb.dcim.interfaces.create(
    device=721,
    name="Eth1/3",
    form_factor=1200,
    enabled=True,
    )
```
# response is...
```
{ 'id': 13131, 
  'device': {'id': 721, 'url': 'https://netbox/api/dcim/devices/721/', 
    'name': 'TEST01', 'display_name': 'TEST01'
  }, 
  'name': 'Eth1/3', 
  'form_factor': {'value': 1200, 'label': 'SFP+ (10GE)'}, 
  'enabled': True, 'lag': None, 'mtu': None, 'mac_address': None, 
  'mgmt_only': False, 'description': '', 'is_connected': False, 
  'interface_connection': None, 'circuit_termination': None, 
  'mode': None, 'untagged_vlan': None, 'tagged_vlans': [], 'tags': []
}
```

##
##
