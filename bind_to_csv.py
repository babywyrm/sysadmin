#!/usr/bin/env python

#########
######### some_editing_required
##
##
##
###
"""
export DNS zone files into csv
"""
import os
import shutil
import fileinput
import re

## Do not change anything below this line
# The chroot directory for the named process
NAMEDCHROOTDIR = "/var/named/chroot"

OUTPUTFILEN = "dnsexport.csv"

RE_MX = re.compile('(^MX\s+.*$)|(^.*\s+MX\s.+$)')
RE_A = re.compile('(^A\s+.*$)|(^.*\s+A\s.+$)')
RE_CNAME = re.compile('(^CNAME\s+.*$)|(^.*\s+CNAME\s.+$)')
RE_NS = re.compile('(^NS\s+.*$)|(^.*\s+NS\s.+$)')

GREEN = '\033[1;32;40m'
RED = '\033[1;31;40m'
RESET = '\033[0m'

def parseconfig(chrootdir):
  """
  parse the zone config file
  """
  tfile = open(config)
  filelist = {}
  fdatadir = None
  inoptions = False
  zone = None
  for line in tfile:
    if 'options' in line:
      inoptions = True
      continue
    elif 'zone' in line and '{' in line:
      zone = line.split('"')[1]
      if zone != '.':
        filelist[zone] = {}
        filelist[zone]['name'] = zone
      continue
    if inoptions:
      tlist = line.split()
      if tlist[0] == 'directory':
        # get the data directory from the config
        # will be relative to chrootdir
        fdatadir = tlist[1].strip(';').strip('"')

        inoptions = False
        continue
    elif zone and zone != '.' and 'file' in line:
      filename = line.split('"')[1]
      filelist[zone]['name'] = zone # name of the zone in the named config file
      filelist[zone]['filename'] = filename # the filename of the zone
      filelist[zone]['relativepath'] = os.path.join(fdatadir, filename) # the relative path of the zone when chrooted
      filelist[zone]['absolutepath'] = os.path.join(chrootdir, fdatadir[1:], filename) # the absolute path of the zone when not chrooted
      zone = None
      continue

  tfile.close()

  return fdatadir, filelist

def exportzone(zone, outputfile):
  if 'in-addr' in zone['filename']:
    print('%-45s: Not exporting reverse zone' % zone['filename'])
    return False

  # open the original file
  origfile = open(zone['absolutepath'])

  lastmx = None
  lasta = None
  lastns = None
  for line in origfile:
    line = line.strip()
    if not line or line[0] == ';':
      continue
    host = 'Unknown\Root'
    ttype = 'None'
    if RE_MX.match(line):
      tlist = line.split()
      ttype = 'MX'
      mailserver = 'None'
      if tlist.index('MX') == 1:
        lasta = None
        lastns = None
        lastmx = tlist[0]
        host = tlist[0]
        mailserver = tlist[3]
      if tlist.index('MX') == 0:
        lasta = None
        lastns = None
        mailserver = tlist[2]
        if lastmx:
          host = lastmx
      outputfile.write('%s,%s,%s,%s\n' % (zone['name'], host, ttype, mailserver))
    if RE_NS.match(line):
      tlist = line.split()
      ttype = 'NS'
      nameserver = 'None'
      if tlist.index('NS') == 2:
        lasta = None
        lastmx = None
        host = tlist[0]
        nameserver = tlist[3]
      if tlist.index('NS') == 1:
        lasta = None
        lastmx = None
        lastns = tlist[0]
        host = tlist[0]
        nameserver = tlist[2]
      if tlist.index('NS') == 0:
        lasta = None
        lastmx = None
        nameserver = tlist[1]
        if lastns:
          host = lastns
      outputfile.write('%s,%s,%s,%s\n' % (zone['name'], host, ttype, nameserver))
    if RE_A.match(line):
      tlist = line.split()
      ttype = 'A'
      IP = 'None'
      if tlist.index('A') == 1:
        lastmx = None
        lastns = None
        lasta = tlist[0]
        host = tlist[0]
        IP = tlist[2]
      if tlist.index('A') == 0:
        lastmx = None
        lastns = None
        IP = tlist[1]
        if lasta:
          host = lasta
      if host != 'Unknown\Root':
        fulldns = '%s.%s' % (host, zone['name'][:-1])
      else:
        fulldns = zone['name'][:-1]
      outputfile.write('%s,%s,%s,%s,%s\n' % (zone['name'], host, ttype, IP, fulldns))
    if RE_CNAME.match(line):
      tlist = line.split()
      lastmx = None
      lastns = None
      lasta = None
      ttype = 'CNAME'
      alias = 'None'
      if tlist.index('CNAME') == 2:
        host = tlist[0]
        alias = tlist[3]
      if tlist.index('CNAME') == 1:
        host = tlist[0]
        alias = tlist[2]
      outputfile.write('%s,%s,%s,%s\n' % (zone['name'], host, ttype, alias))

  origfile.close()

def exportzones(zones):
  """
  go through all the zones in the bind config and update them
  """
  backupfile = open(OUTPUTFILEN, 'w')

  for zone in zones.values():
    exportzone(zone, backupfile)

  backupfile.close()

if __name__ == "__main__":
  config = os.path.join(NAMEDCHROOTDIR, "etc", "named.conf")

  fdatadir, zones = parseconfig(NAMEDCHROOTDIR)

  exportzones(zones)
  
  ###############################
  ################################
  ###############################
