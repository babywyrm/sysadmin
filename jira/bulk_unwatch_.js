// Simple JS snippet to bulk unwatch (stop watching, un-watch) issues in JIRA.
// Written and tested for JIRA 5.2, but should work for all 5+ versions.

// WHAT IT DOES:
// 1. Gets list of issues you watch using JQL search via REST API. You can modify JQL per your needs.
// 2. For each issue found, triggers REST API call to unwatch this issue for current user.

// HOWTO: 
// 1. Go to JIRA in your browser, log in.
// 2. Open your browser JavaScript console.
//    IMPORTANT: this code snippet will be using your current browser session with JIRA.
//    Remmember, that it is insecure to execute any JavaScript code in your browser console if you don't know what it does.
// 3. Copy and past the code block below into your browser JavaScript console.
// 4. Hit ENTER
// 5. Watch the progress. 
//    IMPORTANT: It only unwatches 50 issues per run, so you might need to run it multiple times.


AJS.$.ajax({
  url: '/rest/api/latest/search', 
  data: {jql:'watcher = currentUser()'}, 
  success: function (response) { 
    AJS.$.each(response.issues, function(i,issue) { 
      AJS.$.ajax({
        url: '/rest/api/1.0/issues/' + issue.id + '/watchers', 
        type: 'delete',
        success: function () { console.log('Unwatched ' + issue.key); }
      });
    });
  } 
});

//
//
//
