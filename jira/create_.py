
##
## https://gist.github.com/JaviSoto/2599214
##
## new_jira_task_.py
##
##
##

import sys
import webbrowser as wb

import simplejson as json
 
from restkit import Resource, BasicAuth, request

def createTask(server_base_url, user, password, project, task_summary):
    auth = BasicAuth(user, password)
 
    resource_name = "issue"
    complete_url = "%s/rest/api/latest/%s/" % (server_base_url, resource_name)
    resource = Resource(complete_url, filters=[auth])
 
    try:
        data = {
            "fields": {
                "project": {
                    "key": project
                },
                "summary": task_summary,
                "issuetype": {
                    "name": "Task"
                }
            }
        }
        response = resource.post(headers = {'Content-Type' : 'application/json'}, payload=json.dumps(data))
    except Exception, ex:
        print "EXCEPTION: %s " % ex.msg
        return None

    if response.status_int / 100 != 2:
        print "ERROR: status %s" % response.status_int
        return None
 
    issue = json.loads(response.body_string())
 
    return issue
 
if __name__ == '__main__':
    if (len(sys.argv) != 3):
        print "Usage: %s project task_summary" % sys.argv[0]
        sys.exit(1);

    server_url = 'https://<jirasubdomain>.atlassian.net'

    username = "<username>"
    password = "<password>"

    project = sys.argv[1]
    task_summary = sys.argv[2]

    issue = createTask(server_url, username, password, project, task_summary)
    issue_code = issue["key"]
    issue_url = "%s/browse/%s" % (server_url, issue_code)

    if (issue != None):
        print issue
        wb.open(issue_url)
    else:
        sys.exit(2)

##
##

#!/bin/bash

# You should point Alfred to run this script like this: /Path/To/Script/newJiraTask.sh {query}

i=0

task=""

for parameter in $@; do
	if [ $i -eq 0 ]; then
		projectName=$parameter
	else
		task="$task $parameter"
	fi
	let i++
done

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

python $DIR/newJiraTask.py $projectName "$task"

##
##
##
##
