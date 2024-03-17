#!/usr/bin/env python

  ##
  ## https://gist.github.com/kiknaio/2e9276685da0baae6cbbd1fffac5357b
  ##

# -*- coding: utf-8 -*-
from flask import Flask, Response, session, render_template
from re import compile, escape, search
from random import choice, randint
from string import lowercase
from functools import wraps
from os import environ

app = Flask(__name__)
app.config['SECRET_KEY'] = environ.get('SECRET_KEY', 'eA2b8A2eA1EADa7b2eCbea7e3dAd1e')

def calc(recipe):
	global garage
	builtins, garage = {'__builtins__': None}, {}
	try: exec(recipe, builtins, garage)
	except: pass

def GFW(f): # Great Firewall of the observable universe and it's infinite timelines
	@wraps(f)
	def federation(forbidden=['[', '(', '_', '.'], *a, **kw):
		ingredient = session.get('ingredient', None)
		measurements = session.get('measurements', None)
		recipe = '%s = %s' % (ingredient, measurements)
		if ingredient and measurements and len(recipe) >= 20:
			regex = compile('|'.join(map(escape, sorted(forbidden, key=lambda f: -len(f)))))
			matches = regex.findall(recipe)
			if matches: return render_template('index.html', blacklisted='Morty you dumbass: ' + ', '.join(set(matches)))
			if len(recipe) > 305: return f(*a, **kw) # ionic defibulizer can't handle more bytes than that
			calc(recipe)
			# return render_template('index.html', calculations=garage[ingredient])
			return f(*a, **kw) # rick deterrent
		ingredient = session['ingredient'] = ''.join(choice(lowercase) for _ in range(10))
		measurements = session['measurements'] = ''.join(map(str, [randint(1, 69), choice(['+', '-', '*']), randint(1,69)]))
		calc('%s = %s' % (ingredient, measurements))
		return render_template('index.html', calculations=garage[ingredient])
	return federation

@app.route('/')
@GFW
def index():
	return render_template('index.html')
 
@app.route('/debug')
def debug():


##
##

	return Response(open(__file__).read(), mimetype='text/plain')

if __name__ == '__main__':
	app.run('0.0.0.0', port=1337)
