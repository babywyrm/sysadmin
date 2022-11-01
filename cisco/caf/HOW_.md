# How to Cisco

## Password Recovery Procedure

### ROMmon

```
confreg 0x2142 (at the rommon 1> prompt)
reset

Ctrl-c
enable
copy startup-config running-config
```

Issue the show running-config command. This procedure is likely to leave your switch virtual interface in a shutdown state.

```
configure terminal
config-register 0x2102
do show version
enable secret cisco
Ctrl-z or end
write memory
reload
```

[Source](http://www.cisco.com/en/US/products/ps5854/products_password_recovery09186a0080b34901.shtml)

### Catalyst

```
flash_init
load_helper
dir flash:
rename flash:config.text flash:config.text.old
boot

Ctrl-c
enable
rename flash:config.text.old flash:config.text
copy flash:config.text running-config
```

Issue the show running-config command. This procedure is likely to leave your switch virtual interface in a shutdown state.

```
configure terminal
enable secret cisco
Ctrl-z or end
write memory
reload
```

[Source](http://www.cisco.com/en/US/docs/switches/lan/catalyst2960/software/release/12.2_53_se/configuration/guide/swtrbl.html#wp1021182)

## Upgrade Secondary ROMmon CLI

```
enable
upgrade rom-monitor file flash:/<file>
```

[Source](http://www.cisco.com/en/US/docs/ios/12_0s/feature/guide/12S28FUR.html)

## Upgrade IOS tar file

```
dir flash:
delete flash:c2950-i6q4l2-mz.121-22.EA1.bin
delete /force /recursive flash:<directory name>

archive tar /xtract tftp://10.10.10.3/c2950-i6q4l2-tar.121-22.EA1.tar flash:
verify flash:c2950-i6q4l2-mz.121-22.EA1.bin

wr mem
reload
```

## SSH

Change SSH port

```
R1(config)# ip ssh port 2009 rotary 1
R1(config)# line vty 0 4
R1(config-line)# rotary 1
```

Set SSH

```
ip domain-name rtp.cisco.com

show crypto key mypubkey rsa
crypto key generate rsa

ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 2
```

## VPN

### Debugging

```
debug crypto isakmp
show crypto isakmp sa <vrf> [detail]
show crypto isakmp peer <ip-addr>
sh crypto isakmp peers detail
sh crypto isakmp sa detail
sh crypto ipsec sa detail
sh crypto ipsec sa peer x.x.x.x
```

* https://supportforums.cisco.com/community/netpro/security/vpn/blog/2011/05/02/ipsec-important-debugging-and-logging

### crypto isakmp

* http://www.cisco.com/en/US/products/ps6017/products_command_reference_chapter09186a00808ab59a.html

### Site to Site

#### Reset VPN

```
clear crypto sa peer x.x.x.x
show crypto isakmp sa
clear crypto isakmp 1338
```

#### Debug

```
terminal monitor
debug crypto isakmp error
debug crypto ipsec error
debug crypto engine error
debug crypto routing 
```

### SSL VPN

* [VPN modul](http://www.cisco.com/en/US/prod/collateral/routers/ps5853/data_sheet_vpn_aim_for_18128003800routers_ps5853_Products_Data_Sheet.html)
* Tutorials
 * http://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/904-cisco-router-anyconnect-webvpn.html


## QoS

### Legacy QoS Command Deprecation

[Source](http://www.cisco.com/en/US/docs/ios/ios_xe/qos/configuration/guide/legacy_qos_cli_deprecation_xe.html)

## IOS 15

### Radius server

```
aaa group server radius RADIUS_SERVERS
 server name RADIUS01
 server name RADIUS02

aaa authentication login VTY local group RADIUS_SERVERS
aaa authorization exec VTY local group RADIUS_SERVERS

radius server RADIUS01
 address ipv4 x.x.x.x auth-port 1645 acct-port 1646
 key 0 radiuskey
```

## Switch

```
show interface switchport
show interface brief
```

## Resources

* http://www.eduroam.cz/cs/spravce/ap/ciscoap1230
