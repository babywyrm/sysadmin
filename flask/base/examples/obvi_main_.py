#!/usr/bin/env python
############
############
###################################

from __future__ import print_function

from functools import wraps

from flask import Flask, send_from_directory, redirect, g
app = Flask(__name__, static_folder=None) # disable default static file serving
app.debug = True


def logged_in():
    return True # change this to False to emulate non-logged-in users


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not logged_in():
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route("/api/v1/hello")
@login_required
def hello():
    return "Hello World!"


# in production, these are served by nginx
if app.debug:
    @app.route('/login')
    def login_page():
        return send_from_directory('static', 'login.html')

    @app.route('/', defaults={'path': 'index.html'})
    @app.route("/<path:path>")
    @login_required
    def static_file(path):
        return send_from_directory('static', path)

    @app.errorhandler(404)
    @login_required
    def send_index(path):
        return send_from_directory('static', 'index.html')


if __name__ == "__main__":
    app.run()

    
###################################
##
##    
