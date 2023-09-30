const BulkCloseDefaultOptions = {
  name:"[Task name]",

  // Jira JQL syntax used for retrieving a list of issues
  searchJql:
    "project = MY_JIRA_PROJECT AND " +
    "status not in (CLOSED,DONE) AND " +
    "issuetype not in (Epic) AND " +
    "updatedDate <= -182d AND " +
    "(labels is EMPTY OR labels not in (stale-keep,stale)) " +
    "ORDER BY updatedDate ASC",
  
  // comment to add when closing issue
  closeComment:[
    "*This issue is being closed because it has been inactive for more than 6 months.*",
    "",
    "- if you believe that the issue is still relevant, please reopen it manually.",
    "- if you wish to keep this issue open, add a label {{stale-keep}} to it."
  ],

  // label to apply to closed issue
  staleLabel:"stale",

  // a list of transitions that result in closed issue
  closeTransitions: ["won't fix", "close", "done"]
};

export default class BulkClose {
  constructor(client) {
    this.client = client;    
  }

  log(msg, ...other) {
    console.log(msg, ...other);
  }
  error(msg, ...other) {
    console.error(msg, ...other);
  }

  asString(arrOrStr) {
    if (Array.isArray(arrOrStr)) {
      return arrOrStr.join('\n')
    }

    return arrOrStr
  }

  buildIssueUpdate(options) {
    let issueUpdate = options.issueUpdate||{}

    if (typeof options.closeComment !== "undefined") {
      issueUpdate.comment = [
        {
          "add": {
            "body": this.asString(options.closeComment)
          }
        }
      ]
    }
    if (typeof options.staleLabel !== "undefined") {
      issueUpdate.labels = [{ "add": options.staleLabel }]
    }

    return issueUpdate
  }

  async run(options) {
    
    for (const o of options) {
      await this.runOne(o)
    };
    
  }

  async runOne(options) {
    this.log(`Fetching issues for task [${options.name}]  ...`);
    
    // construct options
    const opt = Object.assign({}, BulkCloseDefaultOptions,options);
    const list = await this.getList(opt); 
    this.log(`Found ${list.length} issues. Iterating ...`);

    for (const o of list) {

      // detect transitions
      const transitions = await this.getAvailableTransitions(o.id);
      const transition = this.detectTransitionId(transitions,opt);
      if (!transition) {
        this.error(
          `Unknown transition for ${o.id}. Available transitions: ${transitions.map(t=>t.name)}`
        );
        continue
      }

      this.log(
        `Transitioning ${o.id} to ${transition.name} (${transition.id})`
      );
      await this.closeIssue(o.id, transition.id,opt);
    };

    this.log("");

    return list;
  }

  async getList(options) {
    const MAX = 50;
    let page = 1;
    let result = [];
    let inProgress = true;

    while (inProgress) {
      const startAt = (page - 1) * MAX;
      const response = await this.client.search.search({
        jql: options.searchJql,
        startAt: startAt,
        maxResults: MAX
      });

      inProgress = response.total > startAt + response.issues.length;
      page++;

      response.issues.forEach(issue => {
        result.push({
          id: issue.key,
          name: issue.name
        });
      });
    }

    return result;
  }

  async closeIssue(issueKey, transitionId,issueUpdate) {
    const transition = { id: transitionId };
    const update = this.buildIssueUpdate(issueUpdate)

    await this.client.issue.editIssue({
      issueKey: issueKey,
      issue: {
        update: update
      }
    });
    await this.client.issue.transitionIssue({
      issueKey: issueKey,
      transition: transition
    });
  }

  async getAvailableTransitions(issueKey) {
    let result = await this.client.issue.getTransitions({
      issueKey: issueKey
    });

    return result.transitions.map(o => ({
      id: o.id,
      name: o.name
    }));
  }

  detectTransitionId(transitionsList,options) {
    return transitionsList.find(o => {
      if (options.closeTransitions.indexOf(o.name.toLowerCase()) > -1) {
        return true;
      }
      return false;
    });
  }
}

import client from './client.mjs'
export const action = new BulkClose(client)
