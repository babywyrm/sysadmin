###########################################################
# How to NEVER use lambdas. An inneficient and yet educa- #
# tonal [sic] guide to the proper misuse of the lambda    #
# construct in Python 3.x.  [DO NOT USE ANY OF THIS EVER] #
#          original by (and apologies to): e000 (13/6/11) #
#           now in Python 3 courtesy of: khuxkm (17/9/20) #
###########################################################

## Part 1. Basic LAMBDA Introduction ##
# If you're reading this, you've probably already read e000's
# original, but in case you didn't read that one back when it
# was big, I should explain what lambdas are. As per e000:
# (quote)
# Lambdas are pretty much anonymous "one line" functions
# that are able to be constructed at runtime. Typical usage
# would be to plug it into `filter()` or `map()`, but that's
# boring. Let's start with the most basic of basic examples.
# (endquote)

def pow(x, power):
    return x**power

# Simple enough, just a function that raises `x` to the `power`
# power. Now let's do it in lambda form:

pow = lambda x, power: x**power

# Easy.

## Part 2. Scoping within Lambdas ##
# Again, this part should be familiar to you if you read the
# original by e000. Nothing changed in Python 3, so I'll just
# quote the explanation here: (quote)
# Let's try something a bit more complicated. A random
# string or password generator? Sure.

import random, string
characters = string.digits + string.letters

def randomPasswordGenerator(length):
    return ''.join(random.choice(characters) for i in range(length))

# >>> randomPasswordGenerator(8)
# 'bDpHVxiO'

# Haah! That was cake! Now in this terrible tutorial, we're going to
# prohibit the use of defining ANYTHING outside of the lambda function,
# including any kind of variable, or import. So, how are we going to get
# `random` and `string`. Well the answer is obvious, we're going to make
# a lambda inside of a lambda inside of a lambda. We're also going to use
# a bit of `__import__` trickery.
# (endquote)
# The import trickery remains the same. Like I said, nothing really
# changed in Python 3 to break this example. As such, I even copied the
# source directly from donotuse.py (changing `xrange` to `range` as the
# former no longer exists).

randomPasswordGenerator = \
(lambda random, string: # level 1
    (lambda characters: # level 2
        lambda length: ''.join(random.choice(characters) for i in range(length)) # level 3
    )(string.digits + string.letters) # level 2 args
)(
    __import__('random'), # level 1 args
    __import__('string')
)

# That's... unpythonic, disgusting, an abomination, and some might even
# call it ungodly. Why would anyone do that to themselves?
# One word: masochists.

## Part 3. Giving lambdas function names ##
# This is the first semi-new part. I'll quote e000 until there's new info.
# (quote)
# In a world where absurdity peaks, and somehow we NEED a
# function name, for what ever reason. Here's how to do it.
#           THIS IS NOT FOR THE WEAK HEARTED.

# First, let's start with some regular code.

def myFunc(a, b):
    return a + b

# >>> myFunc
# <function myFunc at 0x...>

myLambda = lambda a, b: a + b

# >>> myLambda
# <function <lambda> at 0x...>
# Uh'oh! How are we going to give this function a name?
# (endquote)
# In Python 2, we could use `new.function`. But in Python 3, `new` was
# replaced with `types`. Somehow, the new way to do it is even worse.

myFunc = (lambda types:
    types.FunctionType((lambda a, b: a + b).__code__.replace(co_name="myFunc"),{},"myFunc")
)(__import__("types"))

# >>> myFunc
# <function myFunc at 0x...>
# In the immortal words of e000, "LOL! It works! Isn't that disgusting?"

## Part 4. A class? In my lambda? It's more likely than you may think. ##
# Let's start with a simple class. I'll write my own example this time. How
# about a simple namespace?

class Namespace:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)
    def __repr__(self):
        keys = sorted(self.__dict__)
        items = ("{}={!r}".format(k,self.__dict__[k]) for k in keys)
        return "{}({})".format(type(self).__name__,", ".join(items))
    def __eq__(self,other):
        return other.__dict__==self.__dict__

# Yes, I know that's basically just types.SimpleNamespace, but shush. Let's
# lambda-ify it. Instead of `new.classobj`, we have `types.new_class`.

Namespace = (lambda types:
    types.new_class("Namespace",(),exec_body=(lambda ns: ns.update(
        dict(
            __init__=(lambda self,**kwargs: self.__dict__.update(kwargs)),
            __repr__=(lambda self: "{}({})".format(type(self).__name__,", ".join("{}={!r}".format(k,self.__dict__[k]) for k in sorted(self.__dict__)))),
            __eq__=(lambda self, other: self.__dict__==other.__dict__)
        )
    )))
)(__import__("types"))

# >>> Namespace(x=3,s="Hello world!")
# Namespace(s='Hello world!', x=3)

# Holy mother of pearl, that is an abomination.

## Part 5. Flask + Lambdas = Even More of An Abomination ##
# This is as far as I'll go (mainly because I don't know how to Twisted).
# If you want to go even deeper, use the dark arts I've already taught you
# to convert Parts 6a and 6b into Python 3.

from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, world!"

app.run()

# And that becomes...

(lambda flask:
    (lambda app:
        (app,
        app.route('/')(lambda: 'Hello, world!')
        )[0]
    )(flask.Flask(__name__)).run()
)(__import__("flask"))

# What a disaster.

## Part 5b. I Lied, This Is Worse ##
# No comment.

from flask import Flask, redirect

shortnames = {"google":"https://google.com/","khuxkm":"https://khuxkm.tilde.team","*":"https://example.com"}

app = Flask(__name__)

@app.route('/')
def index():
    return redirect(shortnames.get("default","https://example.com"),code=307)

@app.route('/<path:short>')
def route(short):
    return redirect(shortnames.get(short,shortnames.get("default","https://example.com")),code=307)

app.run()

# Pulling out all of the stops here...

(lambda flask, flaskviews, types, shortnames:
    (lambda lmb2view:
        (lambda app, index, route:
            (app,
            app.route("/")(index),
            app.route("/<path:short>")(route)
            )[0]
        )(flask.Flask(__name__),
        lmb2view(lambda s: flask.redirect(shortnames.get("default","https://example.com"),code=307),"index"),
        lmb2view(lambda s,short: flask.redirect(shortnames.get(short,shortnames.get("default","https://example.com")),code=307),"route")).run()
    )(lambda lmb,name: types.new_class(name,(flaskviews.views.View,),{},(lambda ns: ns.update(dict(dispatch_request=lmb)))).as_view(name))
)(__import__("flask"),__import__("flask.views"),__import__("types"),
{
    "google":"https://google.com/",
    "khuxkm":"https://khuxkm.tilde.team",
    "*":"https://example.com"
})

# What? Just... what? It's so goddamn big it barely fits on my 151-column monitor, it breaks all
# sorts of Zen, and I should probably be executed for crimes against humanity, but it's a URL
# shortener implemented entirely in lambdas.

# You ever write completely morally sound code that still leaves you feeling dirty afterwards?

# Me too.

##
##
