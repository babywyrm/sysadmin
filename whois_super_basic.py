#!/usr/bin/python3
#########
###############################


import whois

w = whois.query('feanor.net')
print(w.name)
print(w.creation_date)
print(w.name_servers)
print(w.last_updated)

x = whois.query('thewormhole.us')
print(x.name)
print(x.creation_date)
print(x.name_servers)
print(w.last_updated)


############################
#########################################################
