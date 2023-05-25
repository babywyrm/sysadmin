
##
##

import requests
from tabulate import tabulate

api_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/host"
api_key = "<YOUR_API_KEY>"
headers = {
    "X-Requested-With": "Python Requests",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

def get_available_ports(hosts):
    payload = {
        "action": "list",
        "ips": hosts,
        "details": "All",
    }
    response = requests.post(api_url, auth=(api_key, ''), headers=headers, data=payload)
    response_json = response.json()

    available_ports = []
    if 'Service' in response_json:
        for host in response_json['Service']:
            host_ip = host['IP']
            tcp_ports = []
            udp_ports = []

            if 'tcp' in host:
                tcp_ports = [port['port'] for port in host['tcp']]
            if 'udp' in host:
                udp_ports = [port['port'] for port in host['udp']]

            available_ports.append({'Host': host_ip, 'TCP Ports': tcp_ports, 'UDP Ports': udp_ports})

    return available_ports

def print_available_ports_table(available_ports):
    table_data = []
    for host in available_ports:
        host_ip = host['Host']
        tcp_ports = ", ".join(map(str, host['TCP Ports']))
        udp_ports = ", ".join(map(str, host['UDP Ports']))
        table_data.append([host_ip, tcp_ports, udp_ports])

    headers = ['Host', 'TCP Ports', 'UDP Ports']
    print(tabulate(table_data, headers, tablefmt='fancy_grid'))

hosts = ["<HOST_1>", "<HOST_2>", "<HOST_3>"]

available_ports = get_available_ports(hosts)
print_available_ports_table(available_ports)

###
###



### add-mysql-support

import requests
import mysql.connector
from tabulate import tabulate

api_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/host"
api_key = "<YOUR_API_KEY>"
headers = {
    "X-Requested-With": "Python Requests",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

mysql_config = {
    "host": "<MYSQL_HOST>",
    "user": "<MYSQL_USER>",
    "password": "<MYSQL_PASSWORD>",
    "database": "<MYSQL_DATABASE>",
}

def get_available_ports(hosts):
    payload = {
        "action": "list",
        "ips": hosts,
        "details": "All",
    }
    response = requests.post(api_url, auth=(api_key, ''), headers=headers, data=payload)
    response_json = response.json()

    available_ports = []
    if 'Service' in response_json:
        for host in response_json['Service']:
            host_ip = host['IP']
            tcp_ports = []
            udp_ports = []

            if 'tcp' in host:
                tcp_ports = [port['port'] for port in host['tcp']]
            if 'udp' in host:
                udp_ports = [port['port'] for port in host['udp']]

            available_ports.append({'Host': host_ip, 'TCP Ports': tcp_ports, 'UDP Ports': udp_ports})

    return available_ports

def print_available_ports_table(available_ports):
    table_data = []
    for host in available_ports:
        host_ip = host['Host']
        tcp_ports = ", ".join(map(str, host['TCP Ports']))
        udp_ports = ", ".join(map(str, host['UDP Ports']))
        table_data.append([host_ip, tcp_ports, udp_ports])

    headers = ['Host', 'TCP Ports', 'UDP Ports']
    print(tabulate(table_data, headers, tablefmt='fancy_grid'))

def post_available_ports_to_mysql(available_ports):
    cnx = mysql.connector.connect(**mysql_config)
    cursor = cnx.cursor()

    insert_query = "INSERT INTO available_ports (host, tcp_ports, udp_ports) VALUES (%s, %s, %s)"
    values = [(host['Host'], ",".join(map(str, host['TCP Ports'])), ",".join(map(str, host['UDP Ports']))) for host in available_ports]

    cursor.executemany(insert_query, values)
    cnx.commit()

    cursor.close()
    cnx.close()

    print("Data posted to MySQL database successfully.")

hosts = ["<HOST_1>", "<HOST_2>", "<HOST_3>"]

available_ports = get_available_ports(hosts)
print_available_ports_table(available_ports)
post_available_ports_to_mysql(available_ports)

###
###
