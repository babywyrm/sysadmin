#!/usr/bin/python3

from flask import Flask, render_template, request
from flask import redirect, url_for
import os,sys,re

################
################

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard/<name>')
def dashboard(name):
   return 'welcome %s' % name

@app.route('/login',methods = ['POST', 'GET'])
def login():
   if request.method == 'POST':
      user = request.form['name']
      return redirect(url_for('dashboard',name = user))
   else:
      user = request.args.get('name')
      return render_template('login.html')

@app.route('/create/<first_name>/<last_name>')
def create(first_name=None, last_name=None):
  return 'Yo, yo, yo... ' + first_name + ',' + last_name



##################################################
## if __name__ == '__main__':
##   app.run(debug = True)


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 2255))
    app.run(debug=True, host='0.0.0.0', port=port)

#######################
##
##
