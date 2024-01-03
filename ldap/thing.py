#!/usr/bin/env python3

##
##

import ldap3

server = ldap3.Server("ldaps://ldap.nope.edu", port=636, use_ssl=True)
connection = ldap3.Connection(
	server,
	"uid=dancer.jones,ou=Users,dc=nope,dc=edu",
	"defaultPASS",
	auto_bind=True,
)
connection.modify(
	"uid=dancer.jones,ou=Users,dc=nope,dc=edu",
	{"gidNumber": [(ldap3.MODIFY_REPLACE, ["27"])]},
)

##
##
