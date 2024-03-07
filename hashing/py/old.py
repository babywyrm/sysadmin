
##
## https://gist.github.com/starenka/761778
##


#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# simple wl generator
# 
# @author:     starenka
# @email:      'moc]tod[liamg].T.E[0aknerats'[::-1]
# @version:    1.0
# @since       1/1/11
# @requires    python 2.6

import itertools,string,datetime
from optparse import OptionParser

usage = '\nNo args passed. See -h for arg list.\n'
parser = OptionParser(usage)
parser.add_option('-l','--length',action='store',dest='length',default='6',help='pass length')
parser.add_option('-d','--digits',action='store_true',dest='digits',default=False,help='digits')
parser.add_option('-t','--letters',action='store_true',dest='letters',default=False,help='letters')
parser.add_option('-a','--alnum',action='store_true',dest='alnum',default=False,help='alnum')
parser.add_option('-c','--chars',action='store',dest='chars',default='',help='chars')
parser.add_option('-o','--output-dir',action='store',dest='output',default='/tmp',help='output directory')
(options,args) = parser.parse_args()

chars = ''
if options.digits: chars += string.digits
if options.letters: chars += string.letters
if options.alnum: chars += string.digits+string.letters
if options.chars: chars += options.chars
chars = str(''.join(set(chars)))

FILE = '%s/wl%s_%s'%(options.output.rstrip('/'),options.length,chars)
print '\nUsing %s for %s char long password. Writing to %s'%(chars,options.length,FILE)

start = datetime.datetime.now()
if len(chars)>0:
    f = open(FILE,'w+')
    words = ("".join(l)+'\n' for l in itertools.product(chars,repeat=int(options.length)))
    f.writelines(words)
    f.close()
print 'Finished in %s. KTHXBYE'%(datetime.datetime.now()-start)


##
##
