# Run this with the following command
# FLASK_APP=flaskCorsExample.py FLASK_DEBUG=1 flask run --host 0.0.0.0
#
# https://gist.github.com/calderov/be558d7e37bbd0df536f2c47dd8d0446
#

from flask import Flask
from flask import json
from flask import jsonify
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

numbers = {
    "uno": "one",
    "dos": "two",
    "tres": "three",
    "cuatro": "four"
    }

@app.route("/")
def index():
    return "INDEX"

@app.route("/api/v1/numbers", methods=['GET', 'POST'])
def list_numbers():
    response = app.response_class(
        response=json.dumps(numbers),
        status=200,
        mimetype='application/json'
    )
    return response

@app.route("/api/v1/number/<numbername>")
def list_number(numbername):
    data = json.dumps({})
    status = 404

    if numbername in numbers:
        data = json.dumps({numbername: numbers[numbername]})
        status = 200

    response = app.response_class(
        response=data,
        status=status,
        mimetype='application/json'
    )
    return response

##
##
##
##

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://username.github.io"}})

@app.route('/api/datagetter')
def get_data():
    my_list = [
        {
            'id': 1,
            'userid': 0,
            'amount': 3
        }
    ]

    return jsonify({'list': my_list})

if __name__ == '__main__':
    app.run(debug=True)

And this is the JavaScript:

function fetchData() {
    fetch('http://username.pythonanywhere.com/api/datagetter')
        .then(response => response.json())
        .then(data => {
            console.log('Fetched data:', data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}



As I mentioned if I call the url from the browser, I get the answer, the error is only comes up from the GitHub Pages website.
(http://username.pythonanywhere.com/api/datagetter)


What CORS error are you getting? Edit your question and add the error message there. – 
jub0bs
 CommentedDec 21, 2023 at 19:04
    
