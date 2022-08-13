
####################
<br>
https://gist.github.com/justsml/529d0b1ddc5249095ff4b890aad5e801
<br>
####################


Fetch API Examples
⚠️ 2019-2020: See more examples and updates on my article here!
https://danlevy.net/you-may-not-need-axios/

=====================================================
=====================================================
DEPRECATED BELOW
Table of Contents
GET Requests

Easy: Get JSON from a URL
Intermediate: Custom headers
Advanced: CORS example
POST/PUT Requests

Easy: Posting JSON
Intermediate: Posting an HTML <form>
Intermediate: Form encoded data
Advanced: Uploading Files
Advanced: Uploading Multiple Files
Bonus

Dependant Fetch Requests
Concurrent Downloads
GET Requests
Easy: Get JSON from a URL
fetch('https://api.github.com/orgs/nodejs')
.then(response => response.json())
.then(data => {
  console.log(data) // Prints result from `response.json()` in getRequest
})
.catch(error => console.error(error))
Intermediate: Custom headers
fetch('https://api.github.com/orgs/nodejs', {
  headers: new Headers({
    'User-agent': 'Mozilla/4.0 Custom User Agent'
  })
})
.then(response => response.json())
.then(data => {
  console.log(data)
})
.catch(error => console.error(error))
Advanced: CORS example
CORS is primarily checked at the server - so make sure your configuration is correct on the server-side.

The credentials option controls if your cookies are automatically included.

fetch('https://api.github.com/orgs/nodejs', {
  credentials: 'include', // Useful for including session ID (and, IIRC, authorization headers)
})
.then(response => response.json())
.then(data => {
  console.log(data) // Prints result from `response.json()`
})
.catch(error => console.error(error))
POST/PUT Requests
Easy: Posting JSON
postRequest('http://example.com/api/v1/users', {user: 'Dan'})
  .then(data => console.log(data)) // Result from the `response.json()` call
  .catch(error => console.error(error))

function postRequest(url, data) {
  return fetch(url, {
    credentials: 'same-origin', // 'include', default: 'omit'
    method: 'POST', // 'GET', 'PUT', 'DELETE', etc.
    body: JSON.stringify(data), // Coordinate the body type with 'Content-Type'
    headers: new Headers({
      'Content-Type': 'application/json'
    }),
  })
  .then(response => response.json())
}
Intermediate: Posting an HTML <form>
postForm('http://example.com/api/v1/users')
  .then(data => console.log(data))
  .catch(error => console.error(error))

function postForm(url) {
  const formData = new FormData(document.querySelector('form.edit-user'))

  return fetch(url, {
    method: 'POST', // or 'PUT'
    body: formData  // a FormData will automatically set the 'Content-Type'
  })
  .then(response => response.json())
}
Intermediate: Form encoded data
To post data with a Content-Type of application/x-www-form-urlencoded we will use URLSearchParams to encode the data like a query string.

For example, new URLSearchParams({a: 1, b: 2}) yields a=1&b=2.

postFormData('http://example.com/api/v1/users', {user: 'Mary'})
  .then(data => console.log(data))
  .catch(error => console.error(error))

function postFormData(url, data) {
  return fetch(url, {
    method: 'POST', // 'GET', 'PUT', 'DELETE', etc.
    body: new URLSearchParams(data),
    headers: new Headers({
      'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
    })
  })
  .then(response => response.json())
}
Advanced: Uploading files
postFile('http://example.com/api/v1/users', 'input[type="file"].avatar')
  .then(data => console.log(data))
  .catch(error => console.error(error))

function postFile(url, fileSelector) {
  const formData = new FormData()
  const fileField = document.querySelector(fileSelector)
  
  formData.append('username', 'abc123')
  formData.append('avatar', fileField.files[0])

  return fetch(url, {
    method: 'POST', // 'GET', 'PUT', 'DELETE', etc.
    body: formData  // Coordinate the body type with 'Content-Type'
  })
  .then(response => response.json())
}
Advanced: Uploading multiple files
Setup a file upload element with the multiple attribute:

<input type='file' multiple class='files' name='files' />
Then use with something like:

postFile('http://example.com/api/v1/users', 'input[type="file"].files')
  .then(data => console.log(data))
  .catch(error => console.error(error))

function postFile(url, fileSelector) {
  const formData = new FormData()
  const fileFields = document.querySelectorAll(fileSelector)

  // Add all files to formData
  Array.prototype.forEach.call(fileFields.files, f => formData.append('files', f))
  // Alternatively for PHP peeps, use `files[]` for the name to support arrays
  // Array.prototype.forEach.call(fileFields.files, f => formData.append('files[]', f))
  
  return fetch(url, {
    method: 'POST', // 'GET', 'PUT', 'DELETE', etc.
    body: formData  // Coordinate the body type with 'Content-Type'
  })
  .then(response => response.json())
}
@pom421
pom421 commented on Nov 3, 2018
Thanks for the reminder ! :)

May be you can remove the comment on body: formData // Coordinate the body type with 'Content-Type' since you said above that FormData will set the body for us.

Anyway, great to have all this examples in one place!

@josecalvillob
josecalvillob commented on Dec 9, 2018
I included credentials: 'include' and I still got and error saying "blocked by CORS"

Any idea on why that is happening?

@TuralAsgar
TuralAsgar commented on Feb 19, 2019
I included credentials: 'include' and I still got and error saying "blocked by CORS"

Any idea on why that is happening?

use credentials: "same-origin"

@NourSoltany
NourSoltany commented on Mar 26, 2019
👍

@AlexOldest
AlexOldest commented on Apr 5, 2019
Thank you. It works great with JSON files. I can't deduce how to get XML content out of the response object.

@mylesluke
mylesluke commented on Jun 23, 2019
I included credentials: 'include' and I still got and error saying "blocked by CORS"
Any idea on why that is happening?

use credentials: "same-origin"

Try implimenting this before the URL: https://cors-anywhere.herokuapp.com/

@justsml
Author
justsml commented on Jun 23, 2019
@mylesluke your server must support cookies as well. There's a specific 'credentials' header it needs to send... Also, per the spec, you cannot use a wildcard '*' domain if you configure credentials.

@justsml
Author
justsml commented on Jun 23, 2019
@AlexOldest You can always use res.text() instead of the res.json().
Here's the API documentation: https://developer.mozilla.org/en-US/docs/Web/API/Response

@justsml
Author
justsml commented on Jun 23, 2019
From @tural-esger

I included credentials: 'include' and I still got and error saying "blocked by CORS"
Any idea on why that is happening?

use credentials: "same-origin"

Your server must support 'cookies' CORS config as well.
There's a specific 'credentials' header it needs to send ... Also, per the spec, you cannot use a wildcard '*' domain if you configure credentials.

@carrieaz
carrieaz commented on Aug 28, 2019
In the uploading file section, when uploading one file in <input type='file' ..>, you used example code: formData.append('avatar', fileField.files[0]), what the HTML line for it look like? what is 'avatar' and 'files' in the tag? Thanks!

@justsml
Author
justsml commented on Sep 1, 2019
@carrieaz
Check out my updated article on this stuff: https://danlevy.net/you-may-not-need-axios/#uploading-multiple-files

@freelancer2020
freelancer2020 commented on Oct 9, 2019
When i am sending files to the server or just updating json file using the front-end fetch() , do i need any back-end language to handle the request ? because till now i can fetch data from the server and render it to web page , but when i am trying to upload some data to the server failed!

@justsml
Author
justsml commented on Oct 15, 2019
@freelancer2020
Fetch needs no special server support.
Your server would need to support whatever data format you're sending. Whether that's JSON, URL encoded form data, or files.
To send fields in a way that a default PHP server might expect, use something like this: body: new URLSearchParams(data),

@memoev
memoev commented on Nov 27, 2019
Dude, thanks for doing this! It has helped me a lot.

@justsml
Author
justsml commented on Nov 27, 2019
❤️ @mexcelus - i really appreciate the kind words.

@dlwhitehurst
dlwhitehurst commented on Apr 7, 2020
How would I extract the Location header e.g. after a POST? Can you help here?

@muhammedozalp
muhammedozalp commented on May 30, 2021
Thank you very much
I have tried fetch post lots of hours until

function postFormData(url, data) {
      return fetch(url, {
          method: 'POST', // 'GET', 'PUT', 'DELETE', etc.
          body: new URLSearchParams(data),
          headers: new Headers({
              'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
          })
    })
    .then(response => response.json())
}
@VictorReisSp
VictorReisSp commented on Sep 1, 2021
perfect <3

@fagnermacedo
fagnermacedo commented on Apr 27
Thanks. Works perfect.
