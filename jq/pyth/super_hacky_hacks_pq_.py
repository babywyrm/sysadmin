#!/usr/bin/env python
"""
pq.  its like jq, you know, but for python.
caution: super hackey.
"""

import json
import sys
import atexit
import time
import traceback
from pprint import pprint

class Map(dict):
    """
    Example:
    m = Map({'first_name': 'Eduardo'}, last_name='Pool', age=24, sports=['Soccer'])
    """
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
#        for arg in args:
#            if isinstance(arg, dict):
#                for k, v in arg.iteritems():
#                    self[k] = v
#
#        if kwargs:
#            for k, v in kwargs.iteritems():
#                self[k] = v
#
    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]

def fixup(d):
    """ Take what is presumably a json struct and fix it up so
	dicts are Maps """
    if type(d) == dict:
        n = Map()
        for k, v in d.items():
            n[k] = fixup(v)
        return n
    if type(d) == list:
        return [fixup(i) for i in d]
    return d

def out_handler():
    g = globals()

    if g['bombed']:
        return
    else:
        if "out" in g:
            sys.stdout.write(json.dumps(g['out'], indent=1))
        else:
            if "_" in g:
                sys.stdout.write(json.dumps(g["_"], indent=1))

globals()['_'] = fixup(json.loads(sys.stdin.read()))

atexit.register(out_handler)

bombed = False
try:
    out = eval(sys.argv[1])
except:
    traceback.print_exc()
    bombed = True
    
##########################
##
##    
