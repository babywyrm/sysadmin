
##############
##############

from jira import JIRA
from jira.exceptions import JIRAError

def jira_connect(server, user, pw):
    ''' connects to jira server and returns jira object '''
    try:
        log.info("Connecting to JIRA: %s" % server)
        jira_options = {'server': 'https://'+server, 'verify': False}
        jira = JIRA(options=jira_options, basic_auth=(user, pw))
        return jira
    except Exception, e:
        log.error("Failed to connect to JIRA: %s" % e)
        sys.exit(1)


server = jira01.company.com
user = 'admin'
pw = 'mypasswd'

jira = jira_connect(server, user, pw)

# update assignee
issue = jira.issue('PROJ-123')

try:
  issue.update(fields={ 'assignee': 'New Guy' })
except JIRAError, exep:
  print("Failed to update Assignee %s" % exep)
  sys.exit(1)
  
##############
##############

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from jira.client import JIRA
import sys
import pprint

def connect_jira(jira_server, jira_user, jira_password):
    '''
    Connect to JIRA. Return None on error
    '''
    try:
        jira_options = {'server': jira_server}
        jira = JIRA(options=jira_options,
                    # Note the tuple
                    basic_auth=(jira_user,
                                jira_password))
        return jira
    except Exception,e:
        print "Failed to connect to JIRA: %s" % e
        return None

def print_issue(issue):
    '''
    Print out formatted jira issue
    '''
    print "Issue:       %s" % issue.key
    print "Description: %s" % issue.fields.description
    print "Assignee:    %s" % issue.fields.assignee.displayName
    print "Status:      %s" % issue.fields.status.name
    print "Link:        %s/browse/%s" % (server, issue.key)

server = 'https://jira.domain.com'
jira = connect_jira(server, 'username', 'password')

if len(sys.argv) < 2:
    sys.exit("You must give an issue id, dick.")

issueId = sys.argv[1]
try:
    issue = jira.issue(issueId)
    print dir(issue)
    print dir(issue.fields)
    pprint.pprint(issue.fields)
except Exception,e:
    print "Can't find that ticket, dick."
    
##############
##############
##
## Lol    
