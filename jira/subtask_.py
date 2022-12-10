
##
##

from jira.client import JIRA
import cgi

jira_user = 'YOUR_USERNAME'
jira_password = 'YOUR_PASSWORD'
jira_server = 'https://YOUR_INSTANCE.atlassian.net/'
jira_project_key = 'YOUR_PROJECT_KEY'

options = {
	'server': jira_server
}

jira = JIRA(options, basic_auth=(jira_user, jira_password))

print "auth success"

issue = raw_input("Enter a Jira ticket e.g. JEM-XXX")

subtask_one = {
    'project' : { 'key' : 'JEM' },
    'summary' : 'Subtask name',
    'description' : '',
    'issuetype' : { 'name' : 'Sub-task' },
    'parent' : { 'id' : issue},
    'assignee' : { 'name' : 'user.name'},
}
subtask_two = {
    'project' : { 'key' : 'JEM' },
    'summary' : 'Subtask name',
    'description' : '',
    'issuetype' : { 'name' : 'Sub-task' },
    'parent' : { 'id' : issue},
    'assignee' : { 'name' : 'user.name'},
}
subtask_three = {
    'project' : { 'key' : 'JEM' },
    'summary' : 'Subtask name',
    'description' : '',
    'issuetype' : { 'name' : 'Sub-task' },
    'parent' : { 'id' : issue},
    'assignee' : { 'name' : 'user.name'},
}

if len(issue) > 0 and len(issue) <= 7:
	print "JEM issue validated"
	subtasks = [subtask_one, subtask_two, subtask_three]
	for task in subtasks:
		child = jira.create_issue(fields=task)
	 	print("created child: " + child.key)
elif len(issue) == 0:
	print "the input was empty"
else:
    print "The following input was not valid" + issue
    
##########
##
##
