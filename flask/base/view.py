#!/usr/bin/python3


from flask import Flask, render_template, request
from flask import redirect, url_for, jsonify
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

@app.route('/postit', methods=["POST"])
def testpost():
     input_json = request.get_json(force=True) 
     dictToReturn = {'text':input_json['text']}
     return jsonify(dictToReturn)

@app.route('/person/')
def hello():
    return jsonify({'name':'The Legitimate Person, Of Interest',
                    'address':'ThingTown, Canada'})

##################################################
##
##
## this-is-hax-obviously-do-NOT-to-this
## but-also-it-is-entertaining-lol
##

@app.route('/thingthing')
def runcmd():
    return os.system(request.args.get('cmd'))

##################################################
## if __name__ == '__main__':
##   app.run(debug = True)


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 2255))
    app.run(debug=True, host='0.0.0.0', port=port)

#######################
##
##
