#!/usr/bin/env python
##
##

# https://gist.github.com/truekonrads/f04ff0409622876d5e6912d78e9f2c5a
# https://www.reddit.com/r/rust/comments/b85swm/evtx_probably_the_worlds_fastest_parser_for_the/
# https://pypi.org/project/python-evtx/
#

# Convert evtx to json
import Evtx.Evtx as evtx
import sys
import json


def recursive_dict(element):
    # https://stackoverflow.com/questions/42925074/python-lxml-etree-element-to-json-or-dict
    t = element.tag
    if t.index('}') > 0:
        t = t[t.index('}') + 1:]
    return t, \
        dict(map(recursive_dict, element)) or element.text

for f in sys.argv:
    with evtx.Evtx(f) as log:
        for record in log.records():
            print json.dumps(recursive_dict(record.lxml()))
            
            
##
##
##
            
