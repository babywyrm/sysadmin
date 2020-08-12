# Cisco Router Command Cheatsheet
## Getting Started!
After making a phsyical connection to the Router, connect to it through a serial connection. Once connected, press `ENTER`:
```
-- System Configuration Dialog --
Press RETURN to get started!
Router>
```
You are currently in User EXEC mode.
### eable privileged EXEC mode
In order to run useful commands, you need to get enable priviledged mode.
```
Router> enable
Router#
```
Note: When you are in *Priviledged EXEC* mode, the host name of the device will be suffixed with `#`

### enter global configuration mode
From priviledged mode, you can configure the global options of the router by entering *Global Configuration* mode.
```
Router# configure terminal
Router(config)#
```
Note: You can tell you're in *Global Configuration* mode because the hostname of the device is suffixed with `(config)#`

### setting the hostname of the device
You can set the device name using the `hostname` command:
```
Router(config)# hostname BennysRouter
BennysRouter(config)#
```

### enter interface configuration mode
Once in *Global Configuration* mode, you can choose to configure a [certain interface][cisco-router-interface-types] by entering into the interface configuration mode for that device. You can view the routers interfaces by using the `show` command.
```
BennysRouter(config)# show interface description brief
```
When you're ready to configure an interface, issue the `interface` command.
```
BennysRouter(config)# interface G/0/0
BennysRouter(config-if)#
```
Note: When you've entered interface configuration mode, the hostname of your router will be suffixed by `(config-if)#`

## IPv4
### configure an interface for IPv4

## IPv6
### configure an interface for IPv6

### remove ipv6 addresses
```
Router(config-if)# no ipv6 address
```

[cisco-router-interface-types]: http://www.omnisecu.com/cisco-certified-network-associate-ccna/different-types-of-interfaces-in-a-cisco-router.php
