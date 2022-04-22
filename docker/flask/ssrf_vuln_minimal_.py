###################
###################

from flask import *
import requests

app = Flask(__name__)

@app.route('/follow')
def follow_url():
    url = request.args.get('url', '')
    if url:
        return (requests.get(url).text)

    return "no url parameter provided"

@app.route('/')
def home():
    return '''<h1>SSRF</h1>
                <br>
                usage:
                    <br><code>http://127.0.0.1:80/follow?url=https://api.github.com/events</code><br>
                running:
                <br><code>
                    sudo apt install -y python3-pip
                    sudo pip3 install flask requests;
                    sudo FLASK_ENV=development FLASK_APP=ssrf.py python3 -m flask run --host=0.0.0.0 --port=80
                </code></br>
    '''
  
  
###################
##
##
