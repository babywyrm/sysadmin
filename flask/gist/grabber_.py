#!/usr/bin/python3

##################################
##
##

import os
import requests
import json
from flask import Flask, render_template, url_for, redirect, request
app = Flask(__name__)

@app.route('/')
def hello():
	return render_template('template.html')

@app.route('/user/<username>/')
# Show the gists for an user
def showUserGists(username):
	gists = []
	r = requests.get('http://gist.github.com/api/v1/json/gists/%s' % username)
	decoded = json.loads(r.text)
	for gist in decoded['gists']:
		gists.append(gist)
	return render_template('results.html', username=username, gists=gists)

@app.route('/search', methods=['POST'])
# Redirect to the correct URL
def redirectToUser():
	if request.form['username']:
		return redirect(url_for('showUserGists', username=request.form['username']))
	else:
		return 'Error'

if __name__ == "__main__":
	port = int(os.environ.get('PORT', 5000))
	app.debug = True
	app.run(host='0.0.0.0', port=port)
  
#############################
##
##
