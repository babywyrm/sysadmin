# -*- coding: utf-8 -*-
    
from flask import Flask
from flask import Response
from flask import stream_with_context
from flask import request
import json
import requests
import urllib

app = Flask(__name__)


@app.route('/<path:url>', methods=["GET", "POST"])
def proxy(url):
    """
    Restriction:
      Don't forward headers. If you want to do, use dict(request.headers).
    """
    
    print(f'URL: {url}')
    http_method = requests.post if request.method == 'POST' else requests.get
    if request.json:
        data = request.json
        print(f'{http_method.__name__} json: {data}')
    
        req = http_method(url, json=data)

    if request.form:
        data = request.form.to_dict()
        print(f'{http_method.__name__} form: {data}')
    
        req = http_method(url, data=data)        
    return Response(stream_with_context(req.iter_content()), content_type=request.content_type)

if __name__ == '__main__':
    app.run(debug=True)

"""
# Run 
pip install requests flask
python simple_proxy.py
# Test
curl --location --request POST 'http://127.0.0.1:5000/https://postb.in/1590933774850-8074143861886' \
--header 'X-Status: Awesome' \
--header 'Content-Type: application/json' \
--data-raw '{
    "search": "test",
    "dict": [
        {
            "a": "b",
            "c": "d"
        },
        "abcd"
    ]
}'
curl --location --request GET 'http://127.0.0.1:5000/https://postb.in/1590933774850-8074143861886' \
--header 'X-Status: Awesome' \
--header 'Content-Type: application/json' \
--data-raw '{
    "search": "test",
    "dict": [
        {
            "a": "b",
            "c": "d"
        },
        "abcd"
    ]
}'


"""
"""
# Test log
URL: https://postb.in/1590931882647-8878440114203
post form: {'a': 'bc', 'list': '[a, b, c]'}
127.0.0.1 - - [31/May/2020 23:02:34] "[37mPOST /https://postb.in/1590931882647-8878440114203 HTTP/1.1[0m" 200 -
URL: https://postb.in/1590931882647-8878440114203
get form: {'a': 'bc', 'list': '[a, b, c]'}
127.0.0.1 - - [31/May/2020 23:02:44] "[37mGET /https://postb.in/1590931882647-8878440114203 HTTP/1.1[0m" 200 -
"""

You can simplify this by replacing the iterform stuff with:

form_data = request.form.to_dict(flat=false)
Requests can take a dict with a list of values, and the Flask request form can return a dict with a list of values, so win win.
"""
"""
