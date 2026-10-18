https://gist.github.com/simonw/7000493
https://gist.github.com/bbengfort/2d59f2150f6f29ee8cdf

##############
##############

import json, datetime

class RoundTripEncoder(json.JSONEncoder):
    DATE_FORMAT = "%Y-%m-%d"
    TIME_FORMAT = "%H:%M:%S"
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return {
                "_type": "datetime",
                "value": obj.strftime("%s %s" % (
                    self.DATE_FORMAT, self.TIME_FORMAT
                ))
            }
        return super(RoundTripEncoder, self).default(obj)

data = {
    "name": "Silent Bob",
    "dt": datetime.datetime(2013, 11, 11, 10, 40, 32)
}

print json.dumps(data, cls=RoundTripEncoder, indent=2)

import json, datetime
from dateutil import parser

class RoundTripDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if '_type' not in obj:
            return obj
        type = obj['_type']
        if type == 'datetime':
            return parser.parse(obj['value'])
        return obj

print json.loads(s, cls=RoundTripDecoder)

####
####

#!/usr/bin/env python
# jsonexplorer
# An interactive interface to explore JSON documents
#
# Author:   Benjamin Bengfort <benjamin@bengfort.com>
# Created:  Wed Jun 17 12:15:23 2015 -0400
#
# Copyright (C) 2015 Bengfort.com
# Licensed under the OSI Approved MIT License
#
# ID: jsonexplorer.py [] benjamin@bengfort.com $

"""
An interactive interface to explore JSON documents
"""

##########################################################################
## Imports
##########################################################################

import os
import sys
import cmd
import json
import argparse

##########################################################################
## Program Definition
##########################################################################

PROGRAM = {
    'description': 'An interactive interface to explore JSON documents',
    'epilog': 'Send any comments or bugs to Ben, since he hacked this thing',
    'version': '1.0',
}

##########################################################################
## The JSON Explorer Interactive Command
##########################################################################

class JSONExplorer(cmd.Cmd, object):

    prompt = '{}: '
    intro  = 'An interactive interface to explore JSON documents'

    def __init__(self, args, *pargs, **kwargs):
        self.args   = args
        self.data   = json.load(args.json[0])
        self.loc    = []
        self.indent = args.indent
        super(JSONExplorer, self).__init__(*pargs, **kwargs)

    def preloop(self):
        super(JSONExplorer, self).preloop()
        print "Opened JSON data file at '{}'".format(self.args.json[0].name)

    def get_current_loc(self):
        if not self.loc:
            return self.data

        current = self.data
        for key in self.loc:
            current = current[key]
        return current

    def dumps(self, data):
        print json.dumps(data, indent=self.indent)

    def do_keys(self, s):
        loc = self.get_current_loc()
        if isinstance(loc, dict):
            print ", ".join(loc.keys())
        elif isinstance(loc, list):
            print "0 to {}".format(len(self.get_current_loc())-1)
        else:
            print "type: {}, value: {}".format(type(loc), loc)

    do_ls = do_keys

    def help_keys(self):
        print "Shows the keys or indices of the current json subdocument"
        print "If subdocument is an object, prints the keys"
        print "If subdocument is a list, prints the range of indices"
        print "Otherwise, prints the type of the subdocument"

    help_ls = help_keys

    def do_cd(self, key):
        if key.startswith(".."):
            for up in key.split("/"):
                if key == "..":
                    del self.loc[-1]
                else:
                    self.do_cd(up)

            return

        loc = self.get_current_loc()
        # Is this an int?
        try:
            key = int(key)
            if not isinstance(loc, list):
                print "Integer keys don't work on lists!"
                return

            if key < 0 or key >= len(loc):
                print "Key must be in the range:"
                self.do_keys(key)
                return
        except ValueError:
            pass

        if isinstance(key, basestring):
            if isinstance(loc, list):
                print "Must use integer key on lists!"
                return

            if key not in loc:
                print "No key by that name. Use key from:"
                self.do_keys(key)
                return

        self.loc.append(key)

    def help_cd(self):
        print "Changes the current subdocument to provided key or index"
        print "Navigate the JSON document by changing to keys or indices of"
        print "inner lists or objects (called subdocuments)."

    def complete_cd(self, text, line, begidx, endidx):
        completions = []
        loc = self.get_current_loc()

        if isinstance(loc, dict):
            completions = loc.keys()
        elif isinstance(loc, list):
            completions = list(str(idx) for idx in xrange(len(loc)))

        if text:
            completions = [
                key
                for key in completions
                if key.startswith(text)
            ]

        return completions

    def do_path(self, s):
        print self.args.json[0].name

    def help_path(self):
        print "Show the path of the JSON document"

    def do_pwd(self, s):
        print self.loc

    def help_pwd(self):
        print "Show the path to the current subdocument"

    def get_current_schema(self, obj=None):
        loc = obj or self.get_current_loc()

        if isinstance(loc, dict):
            return {
                key: str(type(val)) for (key, val) in loc.items()
            }
        elif isinstance(loc, list):
            return [self.get_current_schema(loc[0])]
        else:
            return str(type(obj))

    def do_schema(self, s):
        loc = self.get_current_loc()
        schema = self.get_current_schema()
        print json.dumps(schema, indent=self.indent)

    def help_schema(self):
        print "Print out the schema of the current subdocument"

    def do_print(self, key):
        if key:
            print self.dumps(self.get_current_loc()[key])
        else:
            print self.dumps(self.get_current_loc())

    def help_print(self):
        print "Print out the data of the current subdocument"

    def do_exit(self, s):
        self.args.json[0].close()
        return True

    do_EOF = do_exit

    def help_exit(self):
        print "Close the open JSON document and exit"

    help_EOF = help_exit

##########################################################################
## Main Method
##########################################################################

def main(*argv):
    """
    Opens up a JSON document and allows the interactive exploration
    """

    parser = argparse.ArgumentParser(**PROGRAM)
    parser.add_argument('-i', '--indent', type=int, default=2, help='Number of spaces to indent by.')
    parser.add_argument('json', nargs=1, type=argparse.FileType('r'), help='Path to the json file to explore.')

    args = parser.parse_args()
    JSONExplorer(args).cmdloop()

##########################################################################
## Argument parsing
##########################################################################

if __name__ == '__main__':
    main(*sys.argv)

####
####
