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


##
##
##

As I mentioned if I call the url from the browser, I get the answer, the error is only comes up from the GitHub Pages website.
(http://username.pythonanywhere.com/api/datagetter)


What CORS error are you getting? Edit your question and add the error message there. – 
jub0bs
 CommentedDec 21, 2023 at 19:04
    

What is CORS (Cross-origin Resource Sharing)
CORS is the way to share resources between different domains. while avoiding potential cross site scripting attacks. If you do not understand what CORS is or just want to learn more on it, I suggest you read one of the following or all if you're awesome:

HTTP access control (CORS)
Using CORS
W3C Cross-Origin Resource Sharing
Wikipedia- Cross-origin resource sharing
An understanding of this will definitely help you in future projets.

How to run the files
Make virtualenv environment

With virtualenv-wrapper

 $> mkdir cors-test && cd cors-test
 $> mkvirtualenv cors-test
With virtualenv

 $> mkdir cors-test && cd cors-test
 $> virtualenv env && source env/bin/activate
Install requirements

$> pip install -r requirements.txt
To execute the Flask app just run

$> python app.py
This will use Flask's default port 5000

You can use Python's development server to serve your html

$> python-m SimpleHTTPServer 8000
The port doesn't need to be 8000 just a high value port that isn't in use.

Open your browser to http://localhost:5000/. You should get {'hello': 'world'} in your browser's JS console.

Now that that's working open http://localhost:8000/give_me_data in your browser. Enter any value in the input text field and click the button below it. You should see {'name': <your_input_val>} in the browser's JS console and the terminal where the Flask app is running.

app.py
from flask import Flask
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app, resorces={r'/give_me_data': {"origins": '*'}})
api = Api(app)

parser = reqparse.RequestParser()
parser.add_argument('name', type=str)

class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

class GiveMeData(Resource):
    def post(self):
        args = parser.parse_args()
        print args
        result = {'name': args['name']}

        return result, 200

api.add_resource(HelloWorld, '/')
api.add_resource(GiveMeData, '/give_me_data')

if __name__ == '__main__':
    app.run(debug=True)
cors-test.html
<!DOCTYPE html>
<html>
    <head>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
        <script type="text/javascript" charset="utf-8" async defer>
            $('document').ready(function() {
                var button = $('#test-btn'),
                    results = $('#results');

                button.click(function(){
                    $.ajax({
                        url: 'http://localhost:5000/give_me_data',
                        type: 'POST',
                        crossDomain: true,
                        // contentType: 'application/json',
                        data: {name:$('#test-input').val()},
                        success: function(data) {
                            console.log('success')
                            console.log(data);
                        },
                        fail: function(data) {
                            console.log('fail')
                            console.log(data);
                        },
                        error: function(data) {
                            console.log('error')
                            console.log(data)
                        }
                    });
                });
            });
        </script>
    </head>
    <body>
        <div id='container'>
            <input type="text" id="test-input" name="test-inpout" placeholder=""> <br />
            <button id="test-btn">Click</button>
        </div>
        <div id="results"></div>
    </body>
</html>
requirements.txt
aniso8601==0.92
Flask==0.10.1
Flask-Cors==1.10.2
Flask-RESTful==0.3.1
itsdangerous==0.24
Jinja2==2.7.3
MarkupSafe==0.23
pytz==2014.10
six==1.9.0
Werkzeug==0.10.1
@Atarity
Atarity commented on Feb 13, 2020
This simple example saves me tons of time. The only notice: since Flask-Cors and Flask-RESTful updated it should be imported like:

from flask_cors import CORS
from flask_restful import Resource, Api, reqparse

