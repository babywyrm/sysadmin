#!/usr/bin/env python3 
########################
##
## versus_postfix_sendmail_
##

import os,sys,re
import smtplib
########################

host = '127.0.0.1' port = 25
From = 'kyle@writer.htb' To = 'john@writer.htb'
Message = '''\
Subject: YO YOYOYOYOYOYOOOO
Thing. Bout. Life. '''

try:
io = smtplib.SMTP(host,port)
io.ehlo()
io.sendmail(From,To,Message) except Exceptions as e:
print (e) finally:
io.quit()

######################
##
