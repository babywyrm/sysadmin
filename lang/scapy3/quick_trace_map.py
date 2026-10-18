#!/usr/bin/python3
##
##
##   _this_is_actually_pretty_uh_pretty_nice__
##   _make_a_simple_networking_traceroute_chart__
##
#############################

from scapy.layers.inet import traceroute

res4,unans=traceroute(["feanor.net", "4.2.2.2", "192.168.110.105"])
res4.show( )
res4.graph()

#############################
##
##
