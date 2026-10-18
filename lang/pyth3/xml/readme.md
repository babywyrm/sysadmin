To parse an XML document containing open TCP ports for each hostname and print the open ports in a clean JSON format using Python, 
you can utilize the xml.etree.ElementTree module and the json module. Here's an example code that demonstrates this:


```
import xml.etree.ElementTree as ET
import json

# XML document example
xml_doc = '''
<nodes>
    <node>
        <hostname>host1</hostname>
        <ports>
            <port>80</port>
            <port>443</port>
        </ports>
    </node>
    <node>
        <hostname>host2</hostname>
        <ports>
            <port>22</port>
            <port>8080</port>
            <port>3306</port>
        </ports>
    </node>
    <node>
        <hostname>host3</hostname>
        <ports>
            <port>443</port>
            <port>3389</port>
            <port>8080</port>
        </ports>
    </node>
</nodes>
'''

# Parse the XML document
root = ET.fromstring(xml_doc)

# Store the open ports for each host
hosts = []

# Iterate over each node
for node in root.findall('node'):
    host = {}
    host['hostname'] = node.find('hostname').text
    host['ports'] = [port.text for port in node.find('ports').findall('port')]
    hosts.append(host)

# Convert the data to JSON
json_data = json.dumps(hosts, indent=4)

# Print the JSON data
print(json_data)
```


Output:

```
[
    {
        "hostname": "host1",
        "ports": [
            "80",
            "443"
        ]
    },
    {
        "hostname": "host2",
        "ports": [
            "22",
            "8080",
            "3306"
        ]
    },
    {
        "hostname": "host3",
        "ports": [
            "443",
            "3389",
            "8080"
        ]
    }
]

```
