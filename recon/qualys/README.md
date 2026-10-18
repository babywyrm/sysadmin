## https://qualys-secure.force.com/discussions/s/article/000005887
##

qualysapi, Python Qualys API package
Document created by Parag Baxi2 on Jul 19, 2013. Last modified by Parag Baxi2 on Aug 22, 2015.
Description
Note: This is unsupported code.
Updates
Looking for a new owner! Any volunteers?

Summary
Python package, qualysapi, that makes calling any QualysGuard API very simple. QualysGuard API versions v1, v2, & WAS & AM (asset management) are all supported.

My focus was making the API super easy to use. The only parameters the user needs to provide is the call, and data (optional). It automates the following:
Automatically identifies API version through the call requested.
Automatically identifies url from the above step.
Automatically identifies http method as POST or GET for the request per Qualys documentation.

Links
Source code @ Github (open source)
PyPI package

Examples
The way to call the QualysGuard API is simple with qualysapi. Basic format follows for the request method, which returns the request XML output:

request(string CALL, string/dictionary PARAMETERS_OR_POST_DATA)



Here's a more thorough example:

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__license__ = 'Apache License 2.0'

import lxml.objectify
from lxml.builder import E
import qualysapi


# Setup connection to QualysGuard API.
qgc = qualysapi.connect()
#
# API v1 call: Scan the New York & Las Vegas asset groups
# The call is our request's first parameter.
call = 'scan'
# The parameters to append to the url is our request's second parameter.
parameters = {'scan_title': 'Go big or go home', 'asset_groups': 'New York&Las Vegas', 'option': 'Initial+Options'}
# Note qualysapi will automatically convert spaces into plus signs for API v1 & v2.
# Let's call the API and store the result in xml_output.
xml_output = qgc.request(call, parameters)
#
# API v1 call: Print out all IPs associated with asset group "Looneyville Texas".
# Note that the question mark at the end is optional.
call = 'asset_group_list.php?'
# We can still use strings for the data (not recommended).
parameters = 'title=Looneyville Texas'
# Let's objectify the xml_output string.
root = lxml.objectify.fromstring(xml_output)
# Print out the IPs.
print root.ASSET_GROUP.SCANIPS.IP.text
# Prints out:
# 10.0.0.102
#
# API v2 call: Print out DNS name for a range of IPs.
call = '/api/2.0/fo/asset/host/'
parameters = {'action': 'list', 'ips': '10.0.0.10-10.0.0.11'}
xml_output = qgc.request(call, parameters)
root = lxml.objectify.fromstring(xml_output)
# Iterate hosts and print out DNS name.
for host in root.RESPONSE.HOST_LIST.HOST:
    print host.IP.text, host.DNS.text
# Prints out:
# 10.0.0.10 mydns1.qualys.com
# 10.0.0.11 mydns2.qualys.com
#
# API v3 WAS call: Print out number of webapps.
call = '/count/was/webapp'
# Note that this call does not have a payload so we don't send any data parameters.
xml_output = qgc.request(call)
root = lxml.objectify.fromstring(xml_output)
# Print out count of webapps.
print root.count.text
# Prints out:
# 89
#
# API v3 WAS call: Print out number of webapps containing title 'Supafly'.
call = '/count/was/webapp'
# We can send a string XML for the data.
parameters = '<ServiceRequest><filters><Criteria operator="CONTAINS" field="name">Supafly</Criteria></filters></ServiceRequest>'
xml_output = qgc.request(call, parameters)
root = lxml.objectify.fromstring(xml_output)
# Print out count of webapps.
print root.count.text
# Prints out:
# 3
#
# API v3 WAS call: Print out number of webapps containing title 'Lightsabertooth Tiger'.
call = '/count/was/webapp'
# We can also send an lxml.builder E object.
parameters = (
    E.ServiceRequest(
        E.filters(
            E.Criteria('Lightsabertooth Tiger', field='name',operator='CONTAINS'))))
xml_output = qgc.request(call, parameters)
root = lxml.objectify.fromstring(xml_output)
# Print out count of webapps.
print root.count.text
# Prints out:
# 0
# Too bad, because that is an awesome webapp name!
#
# API v3 Asset Management call: Count tags.
call = '/count/am/tag'
xml_output = qgc.request(call)
root = lxml.objectify.fromstring(xml_output)
# We can use XPATH to find the count.
print root.xpath('count')[0].text
# Prints out:
# 840
#
# API v3 Asset Management call: Find asset by name.
call = '/search/am/tag'
parameters = '''<ServiceRequest>
        <preferences>
            <limitResults>10</limitResults>
        </preferences>
        <filters>
            <Criteria field="name" operator="CONTAINS">PB</Criteria>
        </filters>
    </ServiceRequest>'''
xml_output = qgc.request(call, parameters)




Install
First, install Python 2.x.

Then install pip.

Then install qualysapi:

pip install qualysapi



If you are not installing this using virtualenv or virtualenvwrapper (links to learn), you will likely need sudo.

sudo pip install qualysapi



Configuration
By default, the package will ask at the command prompt for username and password. By default, the package connects to the Qualys documented host (qualysapi.qualys.com).

You can override these settings and prevent yourself from typing credentials by doing any of the following:

By running the following Python:
qualysapi.connect(remember_me=True)

This automatically generates a .qcrc file in your current working directory, scoping the configuration to that directory.
By running the following Python:
qualysapi.connect(remember_me_always=True)

This automatically generates a .qcrc file in your home directory, scoping the configuratoin to all calls to qualysapi, regardless of the directory.
By creating a file called '.qcrc' in your home directory or directory of the Python script.


Example .qcrc:

; Note, it should be possible to omit any of these entries.

[info]
hostname = qualysapi.serviceprovider.com
username = jerry
password = I<3Elaine

[proxy]

; proxy_protocol set to https, if not specified.
proxy_url = proxy.mycorp.com

; proxy_port will override any port specified in proxy_url
proxy_port = 8080

; proxy authentication
proxy_username = kramer
proxy_password = giddy up!

