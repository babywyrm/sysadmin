
##
#
https://realpython.com/flask-by-example-integrating-flask-and-angularjs/
#
##

Flask by Example – Integrating Flask and Angular
by Real Python 29 Comments  flask front-end web-dev
Tweet Share Email
Table of Contents

Current Functionality
Update index.html
Create the Angular Module
Dependency Injection and $scope
Refactor app.py
Basic Polling
Updating the DOM
Conclusion and Next Steps
Remove ads
Welcome back. With the Redis task queue setup, let’s use AngularJS to poll the back-end to see if the task is complete and then update the DOM once the data is made available.

Free Bonus: Click here to get access to a free Flask + Python video tutorial that shows you how to build Flask web app, step-by-step.

Updates:

02/29/2020: Upgraded to Python version 3.8.1.
03/22/2016: Upgraded to Python version 3.5.1 and Angular version 1.4.9.
02/22/2015: Added Python 3 support.
Remember: Here’s what we’re building - A Flask app that calculates word-frequency pairs based on the text from a given URL.

Part One: Set up a local development environment and then deploy both a staging and a production environment on Heroku.
Part Two: Set up a PostgreSQL database along with SQLAlchemy and Alembic to handle migrations.
Part Three: Add in the back-end logic to scrape and then process the word counts from a webpage using the requests, BeautifulSoup, and Natural Language Toolkit (NLTK) libraries.
Part Four: Implement a Redis task queue to handle the text processing.
Part Five: Set up Angular on the front-end to continuously poll the back-end to see if the request is done processing. (current)
Part Six: Push to the staging server on Heroku - setting up Redis and detailing how to run two processes (web and worker) on a single Dyno.
Part Seven: Update the front-end to make it more user-friendly.
Part Eight: Create a custom Angular Directive to display a frequency distribution chart using JavaScript and D3.
Need the code? Grab it from the repo.

New to Angular? Review the following tutorial: AngularJS by Example: Building a Bitcoin Investment Calculator

Ready? Let’s start by looking at the current state of our app…

Current Functionality
First, fire up Redis in one terminal window:

$ redis-server
In another window, navigate to your project directory and then run the worker:

$ cd flask-by-example
$ python worker.py
20:38:04 RQ worker started, version 0.5.6
20:38:04
20:38:04 *** Listening on default...
Finally, open a third terminal window, navigate to your project directory, and fire up the main app:

$ cd flask-by-example
$ python manage.py runserver
Open up http://localhost:5000/ and test with the URL https://realpython.com. In the terminal a job id should have outputted. Grab the id and navigate to this url:

http://localhost:5000/results/add_the_job_id_here

You should see a similar JSON response in your browser:

[
  [
    "Python", 
    315
  ], 
  [
    "intermediate", 
    167
  ], 
  [
    "python", 
    161
  ], 
  [
    "basics", 
    118
  ], 
  [
    "web-dev", 
    108
  ], 
  [
    "data-science", 
    51
  ], 
  [
    "best-practices", 
    49
  ], 
  [
    "advanced", 
    45
  ], 
  [
    "django", 
    43
  ], 
  [
    "flask", 
    41
  ]
]
Now we’re ready to add in Angular.

Remove ads
Update index.html
Add Angular to index.html:

<script src="//ajax.googleapis.com/ajax/libs/angularjs/1.4.9/angular.min.js"></script>
Add the following directives to index.html:

ng-app: <html ng-app="WordcountApp">
ng-controller: <body ng-controller="WordcountController">
ng-submit: <form role="form" ng-submit="getResults()">
So, we bootstrapped Angular—which tells Angular to treat this HTML document as an Angular application - added a controller, and then added a function called getResults() - which is triggered on the form submission.

Create the Angular Module
Create a “static” directory, and then add a file called main.js to that directory. Be sure to add the requirement to the index.html file:
```
<script src="{{ url_for('static', filename='main.js') }}"></script>
Let’s start with this basic code:

(function () {
  'use strict';

  angular.module('WordcountApp', [])

  .controller('WordcountController', ['$scope', '$log',
    function($scope, $log) {
      $scope.getResults = function() {
        $log.log("test");
      };
    }
  ]);

}());
Here, when the form is submitted, getResults() is called, which simply logs the text “test” to the JavaScript console in the browser. Be sure to test it out.

Dependency Injection and $scope
In the above example, we utilized dependency injection to “inject” the $scope object and $log service. Stop here. It’s very important that you understand $scope. Start with the Angular documentation, then be sure to run through the Angular intro tutorial if you haven’t already.

$scope may sound complicated but it really just provides a means of communication between the View and Controller. Both have access to it, and when you change a variable attached to $scope in one, the variable will automatically update in the other (data binding). The same can be said for dependency injection: It’s much simpler than it sounds. Think of it as just a bit of magic for obtaining access to various services. So by injecting a service, we can now use it in our controller.

Back to our app…

If you test this out, you’ll see that the form submission no longer sends a POST request to the back end. This is exactly what we want. Instead, we’ll use the Angular $http service to handle this request asynchronously:

.controller('WordcountController', ['$scope', '$log', '$http',
  function($scope, $log, $http) {

  $scope.getResults = function() {

    $log.log("test");

    // get the URL from the input
    var userInput = $scope.url;

    // fire the API request
    $http.post('/start', {"url": userInput}).
      success(function(results) {
        $log.log(results);
      }).
      error(function(error) {
        $log.log(error);
      });

  };

}
]);
  ```
Also, update the input element in index.html:

<input type="text" ng-model="url" name="url" class="form-control" id="url-box" placeholder="Enter URL..." style="max-width: 300px;">
We injected the $http service, grabbed the URL from the input box (via ng-model="url"), and then issued a POST request to the back-end. The success and error callbacks handle the response. In the case of a 200 response, it will be handled by the success handler, which, in turn, logs the response to the console.

Before testing, let’s refactor the back-end, since the /start endpoint does not currently exist.

Remove ads
Refactor app.py
Refactor out the Redis job creation from the index view function, and then add it to a new view function called get_counts():
```
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/start', methods=['POST'])
def get_counts():
    # this import solves a rq bug which currently exists
    from app import count_and_save_words

    # get url
    data = json.loads(request.data.decode())
    url = data["url"]
    if not url[:8].startswith(('https://', 'http://')):
        url = 'http://' + url
    # start job
    job = q.enqueue_call(
        func=count_and_save_words, args=(url,), result_ttl=5000
    )
    # return created job id
    return job.get_id()
  ```
Make sure to add the following import at the top as well:

import json
These changes should be straightforward.

Now we test. Refresh your browser, submit a new URL. You should see the job id in your JavaScript console. Perfect. Now that Angular has the job id we can add in the polling functionality.

Basic Polling
Update main.js by adding the following code to the controller:

function getWordCount(jobID) {
  var timeout = "";

  var poller = function() {
    // fire another request
    $http.get('/results/'+jobID).
      success(function(data, status, headers, config) {
        if(status === 202) {
          $log.log(data, status);
        } else if (status === 200){
          $log.log(data);
          $timeout.cancel(timeout);
          return false;
        }
        // continue to call the poller() function every 2 seconds
        // until the timeout is cancelled
        timeout = $timeout(poller, 2000);
      });
  };
  poller();
}
Then update the success handler in the POST request:

$http.post('/start', {"url": userInput}).
  success(function(results) {
    $log.log(results);
    getWordCount(results);

  }).
  error(function(error) {
    $log.log(error);
  });
Make sure to inject the $timeout service into the controller as well.

What’s happening here?

A successful HTTP request results in the firing of the getWordCount() function.
Within the poller() function, we called the /results/job_id endpoint.
Using the $timeout service, this function continues to fire every 2 seconds until the timeout is cancelled when a 200 response is returned along with the word counts. Check out the Angular documentation for an awesome description of how the $timeout service works.
When you test this out, be sure to open the JavaScript console. You should see something similar to this:

Nay! 202
Nay! 202
Nay! 202
Nay! 202
Nay! 202
Nay! 202
(10) [Array(2), Array(2), Array(2), Array(2), Array(2), Array(2), Array(2), Array(2), Array(2), Array(2)]
So, in the above example, the poller() function is called seven times. The first six calls returned a 202, while the last call returned a 200 along with the word count array.

Perfect.

Now we need to append the word counts to the DOM.

Remove ads
Updating the DOM
Update index.html:

<div class="container">
  <div class="row">
    <div class="col-sm-5 col-sm-offset-1">
      <h1>Wordcount 3000</h1>
      <br>
      <form role="form" ng-submit="getResults()">
        <div class="form-group">
          <input type="text" name="url" class="form-control" id="url-box" placeholder="Enter URL..." style="max-width: 300px;" ng-model="url" required>
        </div>
        <button type="submit" class="btn btn-default">Submit</button>
      </form>
    </div>
    <div class="col-sm-5 col-sm-offset-1">
      <h2>Frequencies</h2>
      <br>
      {% raw %}
      <div id="results">

          {{wordcounts}}

      </div>
      {% endraw %}
    </div>
  </div>
</div>
What did we change?

The input tag now has a required attribute, indicating that the input box must be filled out before the form can be submitted.
Say goodbye to the Jinja2 template tags. Jinja2 is served from the server side, and since the polling is handled completely on the client side, we need to use Angular tags. That said, since both Jinja2 and Angular template tags utilize double curly braces, {{}}, we have to to escape the Jinja2 tags using {% raw %} and {% endraw %}. If you need to use a number of Angular tags, it’s a good idea to change the template tags AngularJS uses with the $interpolateProvider. For more, check out the Angular docs.
Second, update the success handler in the poller() function:

success(function(data, status, headers, config) {
  if(status === 202) {
    $log.log(data, status);
  } else if (status === 200){
    $log.log(data);
    $scope.wordcounts = data;
    $timeout.cancel(timeout);
    return false;
  }
  // continue to call the poller() function every 2 seconds
  // until the timeout is cancelled
  timeout = $timeout(poller, 2000);
});
Here, we attached the results to the $scope object so that it’s available in the View.

Test that out. If all went well, you should see the object on the DOM. Not very pretty, but that’s an easy fix with Bootstrap, add the following code underneath the div with id=results and remove the {% raw %} and {% endraw %} tags that were wrapping the results div from the code above:

<div id="results">
  <table class="table table-striped">
    <thead>
      <tr>
        <th>Word</th>
        <th>Count</th>
      </tr>
    </thead>
    <tbody>
      {% raw %}
      <tr ng-repeat="element in wordcounts">

        <td>{{ element[0] }}</td>
        <td>{{ element[1] }}</td>

      </tr>
    {% endraw %}
    </tbody>
  </table>
</div>
Conclusion and Next Steps
Before moving on to charting with D3, we still need to:

Add a loading spinner: Also know as a throbber, this will be displayed until the task is done so that the end user knows that something is happening.
Refactor the Angular Controller: Right now there’s too much happening (logic) in the controller. We need to move the majority of the functionality into a service. We’ll discuss both the why and how.
Update Staging: We need to update the staging environment on Heroku - adding the code changes, our worker, and Redis.
See you next time!
  
