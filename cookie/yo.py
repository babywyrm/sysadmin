
#!/usr/bin/env python
# Firefox3 cookies converter.
# This script based on another one, from post
# http://blog.schlunzen.org/2008/06/19/firefox-3-und-cookiestxt/
# and expanded from:
# http://gist.github.com/157109

##
## https://gist.github.com/dvj/185625
##

import optparse
import os
import shutil
import sqlite3
import sys 
import warnings

parser = optparse.OptionParser()
parser.add_option('--database', dest = 'database',
                  help = 'FF3 sqlite database with cookies.')
parser.add_option('--output', dest = 'output',
                  help = 'Output filename for cookies in NETSCAPE format.')
parser.add_option('--host', dest = 'host',
                  help = 'Hostname, to filter cookies, can contain % sign at the beginning or at the end.')

(options, args) = parser.parse_args()

if options.database is None:
    sys.stderr.write('Option --database is required\n')
    sys.exit(1)

if options.output is None:
    sys.stderr.write('Option --output is required\n')
    sys.exit(1)

warnings.simplefilter('ignore', RuntimeWarning)
filename = os.tmpnam()
shutil.copyfile(options.database, filename)
try:
    connection = sqlite3.connect(filename)
    cursor = connection.cursor()
except:
    print "Could not open file " + filename + ". Check your path and try again"
    sys.exit(1)

table = "moz_cookies"
contents = "host, path, isSecure, expiry, name, value"

try:
    outfile = open(options.output, 'w')
except:
    print "Could not open output file: " + options.output + ". Make sure location is writable."
    sys.exit(1)

try: #let's assume we're using firefox style first...
    query = 'SELECT ' + contents +' FROM ' + table;
    query_args = []
    if options.host:
        query += ' WHERE host LIKE ?'
        query_args.append(options.host)

    cursor.execute(query, query_args)

except: #this failed, lets try chrome stlye...
    print "Trying Chrome..."
    table = "cookies"
    contents = "host_key, path, secure, expires_utc, name, value"
    query = 'SELECT ' + contents +' FROM cookies';
    query_args = []
    if options.host:
        query += ' WHERE host_key LIKE ?'
        query_args.append(options.host)

    cursor.execute(query, query_args)

try:
    count = 0
    for row in cursor.fetchall():
        outfile.write("%s\tTRUE\t%s\t%s\t%d\t%s\t%s\n" % (row[0], row[1],
                  str(bool(row[2])).upper(), row[3], str(row[4]), str(row[5])))
        count += 1


    outfile.close()
    connection.close()

    print '%d cookies were exported to "%s"' % (count, options.output)
finally:
    os.remove(filename)

##
##
