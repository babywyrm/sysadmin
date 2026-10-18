Simple Reverse Proxy Server Using Flask
Welcome to the series on building your own orchestration unit on your cloud management server. Let us start with a simple implementation of building a reverse proxy for your server. While we go on to do that, we can revisit some of the terms that are going to be used here, and make sure that we know what we are exactly achieving.

Container Orchestration : In plain words, it is the management of containers — looking after the health, usage, etc of the containers that you have deployed as part of your application. It can include many features, out of which these three are very important -

Load Balancing : Any orchestration engine must be able to balance the load on all the backend servers ( here containers ) . This means that the number of API calls made to these containers are equally balanced and distributed amongst the containers based on any algorithm of choice. Most popular algorithm is the Round Robin Algorithm , which is a simple circular queue based process, where the queue rotates upon each request, sending the new request to the next server on queue. Amongst other popular algorithms is Least Connections Algorithm , which serves the new request to the server with the least number of connections ( or least loaded server ) .
Fault Tolerance : Fault Tolerant systems are very important in the cloud architecture while managing hundreds of servers together. A master needs to keep poling every server or container to send itself heartbeats to ensure that every container is up and running healthily. Our flask server will poll every container on a particular API (called the health check API) and make sure every container is running and can be served requests.
Auto Scaling : Auto scaling is the process of scaling up or down resources for your application. A flood of requests can call for increasing the number of servers that you require , so that they can all be served . And a day without much requests can be handled by just a few servers, hence benefiting from the cost. Auto scaling always calls for “rules” to be written as to how much the scale factor should be. This rule is evaluated for a fixed time period, and the servers are either scaled up or down periodically based on the outcome of these rules.
Reverse Proxy : Let us clarify what a reverse proxy server does that a forward proxy doesn’t. Reverse proxy is a server that sits on the server side of applications to accomplish the above three tasks mentioned in a smooth and efficient way. It is responsible for receiving all the requests from the clients, and rerouting it and redirecting it to the many servers that are present. A forward proxy on the other hand is in front of clients and is used to communicate with other servers often as a middleman used often to protect identity online, or to access blocked content.


Let’s start by writing a simple app server using Flask(a micro web framework written in Python.) and Python. This will help you spin up a server in seconds. We will use this later to start proxying requests to your actual application server.

Setting up and starting with flask

sudo apt-get install -y python python-pip python-virtualenv
Install required packages and activate a virtual environment.

sudo virtualenv env
source env/bin/activate
sudo pip install Flask==0.10.1
Set up your project

mkdir flaskproject && cd flaskproject
sudo vim app.py
And add the following code to app.py

from flask import Flask
app = Flask(__name__)
@app.route('/')
def index():
    return 'Flask is running!'
if __name__ == '__main__':
    app.run()
This is a simple app.py which when executed should run the flask server at 5000 as the default port. So, if you curl or check via Postman or browser “localhost:5000/” it should respond saying “Flask is running!”

For making your app further you can add routed using @app.route(‘<the-path>’) and define the action in function after it.

Since we are designing a proxy server its function is to just re channel the requests to the desired servers and return the response received to the requesting server. We use the flask request and Response formats. Python requests library is used to make requests to the application servers.

The function to redirect a GET request would be something like this :

@app.route('/<path:path>',methods=['GET'])
def proxy(path):
    if request.method=='GET':
        resp = requests.get(f'{SITE_NAME}{path}')
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in     resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
    return response
Where SITE_NAME is the path to the application server and path is the url of the api.

path is a string Flask variable which helps define the url dynamically. There are other flask variables you can implement, such as int and float flask variables.

Response class is a neat little class can be used to build a http response objects with the required body, headers and status codes. These are passed to the response object and returned by the proxy method for any request.

Any API call made by the client hits the flask server, which redirects it to your application server, which sends a response to your flask server, which is sent back to the client. You have to make sure through flask that the request and response packets are not changed or messed in this process.

For example:

@app.route('/blog/<int:postID>')
def show_blog(postID):
   return 'Blog Number %d' % postID
@app.route('/rev/<float:revNo>')
def revision(revNo):
   return 'Revision Number %f' % revNo
For POST requests, we need to pass on the body of the request as well. We read and pass on a json. The function to redirect a POST request will be :

@app.route(‘/<path:path>’,methods=[‘POST’])
def proxy(path):
    if request.method==’POST’:
       resp = requests.post(f’{SITE_NAME}{path}’,json=request.get_json())
        SITE_NAME = “http://localhost:"
        excluded_headers = [‘content-encoding’, ‘content-length’, ‘transfer-encoding’, ‘connection’]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
POST is not by default present as a valid method in Flask and hence has to be added in the methods param of the app route, else you will receive an error code of 405. To make sure the body of the request is passed on we use request.get_json() and to pass it as a valid json we pass it as a parameter json=request.get_json(). This ensures that the json is not tampered with in the process of getting redirected to the desired application server.

Similarly, we can write the actions for other methods in the function.

We can combine the requests into one function which directs your requests just like a proxy server. Generalising for GET,POST and DELETE ( you can be fancy and add other methods too , but this is fine for now ).

Adding it all up :

from flask import Flask,request,redirect,Response
import requests
app = Flask(__name__)
SITE_NAME = ‘http://localhost:8000’
@app.route(‘/’)
def index():
    return ‘Flask is running!’
@app.route(‘/<path:path>’,methods=[‘GET’,’POST’,”DELETE”])
def proxy(path):
    global SITE_NAME
    if request.method==’GET’:
        resp = requests.get(f’{SITE_NAME}{path}’)
        excluded_headers = [‘content-encoding’, ‘content-length’, ‘transfer-encoding’, ‘connection’]
        headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method==’POST’:
        resp = requests.post(f’{SITE_NAME}{path}’,json=request.get_json())
        excluded_headers = [‘content-encoding’, ‘content-length’, ‘transfer-encoding’, ‘connection’]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method==’DELETE’:
        resp = requests.delete(f’{SITE_NAME}{path}’).content
        response = Response(resp.content, resp.status_code, headers)
         return response
if __name__ == ‘__main__’:
    app.run(debug = False,port=80)
This wraps up writing a simple proxy server in Flask on port 80 re-directing to port 8000 of localhost (We will complicate and simplify this in the upcoming parts). Please note that debug is set to False here. If debug is set to True, Flask runs every command twice which is undesirable.

