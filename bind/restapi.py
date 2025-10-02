#!/usr/bin/env python3
"""
Tornado REST API for managing DNS records with nsupdate... (..beta..)

Endpoints:
    POST /dns   -> create a DNS record
    DELETE /dns -> delete a DNS record

Authentication:
    Requires header X-Api-Key: <secret>

Examples:
    curl -X POST -H "Content-Type: application/json" -H "X-Api-Key: secret" \
         -d '{"hostname": "host.example.com", "ip": "1.1.1.10", "ptr": "yes"}' \
         http://localhost:9999/dns

    curl -X DELETE -H "Content-Type: application/json" -H "X-Api-Key: secret" \
         -d '{"hostname": "host.example.com"}' \
         http://localhost:9999/dns
"""

import json
import os
import shlex
import sys
from subprocess import Popen, PIPE, STDOUT

import tornado.ioloop
import tornado.web
from tornado.options import define, options

from daemon import Daemon


# --- Configuration ---
cwd = os.path.dirname(os.path.realpath(__file__))

define("address", default="0.0.0.0", type=str, help="Listen on interface")
define("port", default=9999, type=int, help="Listen on port")
define("pidfile", default=os.path.join(cwd, "bind-restapi.pid"), type=str, help="PID location")
define("logfile", default=os.path.join(cwd, "bind-restapi.log"), type=str, help="Log file")
define("ttl", default=86400, type=int, help="Default TTL")
define("nameserver", default="127.0.0.1", type=str, help="Master DNS")
define("sig_key", default=os.path.join(cwd, "dnssec_key.private"), type=str, help="DNSSEC Key")
define("secret", default="secret", type=str, help="Protection Header")
define("nsupdate_command", default="nsupdate", type=str, help="nsupdate command")

mandatory_create_parameters = ["ip", "hostname"]
mandatory_delete_parameters = ["hostname"]

nsupdate_create_template = """\
server {0}
update add {1} {2} A {3}
send"""

nsupdate_create_ptr = """\
update add {0} {1} PTR {2}
send"""

nsupdate_delete_template = """\
server {0}
update delete {1} A
send
update delete {1} PTR
send"""


# --- Helpers ---
def auth(method):
    """Decorator for verifying X-Api-Key header."""

    def wrapper(self, *args, **kwargs):
        secret_header = self.request.headers.get("X-Api-Key")
        if not secret_header or options.secret != secret_header:
            self.set_status(401)
            self.finish(json.dumps({"code": 401, "message": "Invalid X-Api-Key"}))
            return
        return method(self, *args, **kwargs)

    return wrapper


def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


# --- Handlers ---
class JsonHandler(tornado.web.RequestHandler):
    """Request handler for JSON input/output."""

    def prepare(self):
        if self.request.body:
            try:
                self.json_args = json.loads(self.request.body.decode())
            except ValueError:
                self.set_status(400)
                self.finish(json.dumps({"code": 400, "message": "Invalid JSON"}))
        else:
            self.json_args = {}

    def set_default_headers(self):
        self.set_header("Content-Type", "application/json")

    def write_error(self, status_code, **kwargs):
        message = kwargs.get("message", self._reason)
        self.finish(json.dumps({"code": status_code, "message": message}))

    def json_response(self, code, message, **extra):
        self.set_status(code)
        payload = {"code": code, "message": message}
        payload.update(extra)
        self.finish(json.dumps(payload))


class ValidationMixin:
    def validate_params(self, params):
        for parameter in params:
            if parameter not in self.json_args:
                self.send_error(400, message=f"Parameter '{parameter}' not found")


class MainHandler(ValidationMixin, JsonHandler):
    def _nsupdate(self, update: str):
        cmd = f"{options.nsupdate_command} -k {options.sig_key}"
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout, _ = p.communicate(input=update.encode())
        return p.returncode, stdout.decode()

    @auth
    def post(self):
        self.validate_params(mandatory_create_parameters)
        ip = self.json_args["ip"]
        hostname = self.json_args["hostname"]

        ttl = self.json_args.get("ttl", options.ttl)

        update = nsupdate_create_template.format(options.nameserver, hostname, ttl, ip)

        if self.json_args.get("ptr") == "yes":
            reverse_name = reverse_ip(ip)
            ptr_update = nsupdate_create_ptr.format(reverse_name, ttl, hostname)
            update += "\n" + ptr_update

        code, output = self._nsupdate(update)
        if code != 0:
            self.send_error(500, message=output)
        else:
            self.json_response(200, "Record created")

    @auth
    def delete(self):
        self.validate_params(mandatory_delete_parameters)
        hostname = self.json_args["hostname"]

        update = nsupdate_delete_template.format(options.nameserver, hostname)
        code, output = self._nsupdate(update)
        if code != 0:
            self.send_error(500, message=output)
        else:
            self.json_response(200, "Record deleted")


# --- Tornado Application ---
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [(r"/dns", MainHandler)]
        super().__init__(handlers)


class TornadoDaemon(Daemon):
    def run(self):
        app = Application()
        app.listen(options.port, options.address)
        tornado.ioloop.IOLoop.current().start()


# --- CLI Entrypoint ---
if __name__ == "__main__":
    daemon = TornadoDaemon(
        options.pidfile, stdout=options.logfile, stderr=options.logfile
    )

    if len(sys.argv) == 2:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            print("Starting Tornado...")
            daemon.start()
        elif cmd == "stop":
            print("Stopping Tornado...")
            daemon.stop()
        elif cmd == "restart":
            print("Restarting Tornado...")
            daemon.restart()
        elif cmd == "status":
            print("Running" if daemon.status() else "Not running")
        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit()
    else:
        print(f"Usage: {sys.argv[0]} start|stop|restart|status")
        sys.exit(2)

##
##
