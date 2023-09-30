##
##
##

from jira import JIRA

jira = JIRA(server="https://domain.com", basic_auth=('username', 'password'))

# first initial search
query = "timespent > 0 AND project = PROJKEY and issuetype=defect"
relevant_issues = jira.search_issues(query, maxResults=50)

# loop hast to be adjusted if the number of results is very large so the search is executed again
while relevant_issues:
    for issue in relevant_issues:
        for worklog in jira.worklogs(issue):
            print(issue.fields.summary)
            print(worklog)
            worklog.delete(adjustEstimate="leave")
    # if issues remain they are found here        
    relevant_issues = jira.search_issues(query, maxResults=50)
print("done")

