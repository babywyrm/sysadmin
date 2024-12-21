# HTTP.Request.Smuggling.Desync.Attack

##
#
https://github.com/nachiketrathod/HTTP.Request.Smuggling.Desync.Attack/blob/main/README.md
#
##

[browser-powered-desync-attacks.pdf](https://github.com/user-attachments/files/18217262/browser-powered-desync-attacks.pdf)




<p align="center">
      <a href="http://nachiketrathod.com">
	     <img src="/Images/request.png" height=190 width=1000"></a>
</p>
								  

<p align="center"> 
      <a href="https://www.twitter.com/4ccess0denie1">
           <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/4ccess0denie1?color=%2300acee&label=Follow%20%404ccess0denie1&logo=Twitter&logoColor=%2300acee&style=flat-square"></a>
      <a href="https://www.linkedin.com/in/nachiketrathod">
           <img alt="linkedin nachiketrathod" src="https://img.shields.io/badge/LinkedIn-nachiketrathod-0077B5?style=flat-square&logo=linkedin&logoColor=00acee"></a>
           <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/nachiketrathod/HTTP.Request.Smuggling.Lab?logo=github&style=flat-square">
	   <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/nachiketrathod/HTTP.Request.Smuggling.Lab?logo=Github&style=flat-square">
</p>

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>TL;DR:</a></h2>

HTTP request smuggling is a technique for **`interfering`** with the way of website process the sequences of HTTP requests that are received from one or more users.
This page discusses all techniques used for request smuggling **/** desync attack. `E.g.` **`CL.TE`**,**`TE.CL`**,**`CL.CL`** and **`TE.TE`** .
This vulnerabilities are often **`critical`** in nature, allowing an attacker to bypass **security controls**, gain **unauthorized access** to sensitive data, and directly compromise other application users.

**Lab** : Exploiting HTTP request smuggling to bypass front-end security controls via **TE.CL** vulnerability.

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>1. Core concepts :ghost:</a></h2>
<blockquote>
<p>"Smashing into the Cell Next Door"</p>
<p>"Hiding Wookiees in HTTP"</p>
</blockquote>

### **What is HTTP Request Smuggling?**

1.  If you picturised any website as an **end user** it would probably look like this, why because that's all that you can directly see.

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/1.png" height=300 width=290"></a>
            </kbd>
</p>
							   
2.  Morden websites communicate to each other via chain of `web-servers` speaking HTTP over `stream based transport layer proctols` like **`TCP or TLS`**.

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/2.png" height=300 width=550"></a>
	    </kbd>
</p>

These streams(**TLS/TCP**) are heavily reused and follows the HTTP 1.1 `keepalive` protocol.


#### ***`Question, what dose it even mean?`***

- That means that every reqests are placed back to back on these streams and every server parses `HTTP-Headers` to workout where each one ends and the next one starts.
    
- So from all over the world request are coming and passing through this tiny tunnel of **TLS/TCP** streams and passing to the backend and then split up into individual requests.

#### ***`Question, what could possibly go wrong here?`***

- what if an attacker sends an ambiguous reqest which is deliberately crafted and so that `front-end` and `back-end` disagree about how long this messages is. 
- **let's understand this with below example,**

<p align="left">
      <a href="http://nachiketrathod.com">
	<kbd>   
		<img src="/Images/3.png" height=300 width=800"></a> 
	</kbd>
</p>

**`Example:`**

**Front-end** will thinks that this `Blue + Orange` block of data is one request, so immediately it will send the whole thing to backend.

But for some reason **Back-end** thinks that this message will finishes with second blue block and therefore it thinks that orange bit of data is the start of the next request and it's just gonna wait for that second request to be finished until that request is completed.

**And what's gonna complete that request?** 

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/4.png" height=400 width=750"></a>
	    </kbd>
</p>

Well, it could be someone else sending a request to the application. So an attacker can apply **`arbitary prefix/content`** to someone else request via smuggling and That's the core primitive of this technique.

### `1. Desynchronizing: the classic approach CL.CL`

**`Example:`**

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/5.png" height=280 width=750"></a>
	    </kbd>
</p>

This is an example of an ambiguous request. this one is ambiguous because we are using absolute classic old school `Desynchronization` technique.
- In this example, we simply specifed Content-Length header (C.L) twice. 
- Front-end will use **`C.L - 6`** --> will forward data up to Orange one (12345G) to the Back-end.
- Back-end will use  **`C.L - 5`** --> and it'll thik that **Orange - G** is the start of the next request.

In this example, the injected **'G'** will corrupt the `green user's` real request and they will probably get a response along the lines of **"Unknown method GPOST".**
 
check that in the below example,

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/6.png" height=280 width=750"></a>
	    </kbd>
</p>

Note: **This above technique is so old-school and classic that it doesn't actually work on anything that's worth hacking these days.**

#### ***`Question, if not the classic approach then which technique works on the plenty of interesting systems?`***
In real life, the dual content-length technique rarely works because many systems sensibly reject requests with multiple content-length headers. Instead, we're going to attack systems using chunked encoding and this time we've got the specification [RFC 2616](https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1) on our side.

<p align="center">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/7.png" height=50 width=750"></a>
	    </kbd>
</p>

Since the specification implicitly allows processing requests using both `Transfer-Encoding: chunked` and `Content-Length`, few servers reject such requests.
Whenever we find a way to hide the Transfer-Encoding header from one server in a chain it will fall back to using the Content-Length and we can desynchronize the whole system.

You might not be very familiar with chunked encoding since tools like Burp Suite automatically buffer chunked requests/responses into regular messages for ease of editing. 
- In a chunked message: **`the body consists of 0 or more chunks.`** 
- Each chunk consists of the `chunk size`, `followed by a newline`, `followed by the chunk contents`. 
- The message is **`terminated with a chunk of size 0.`** 

### `2. Desynchronizing: the chunked approach CL.TE`

**`Example:`**

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/8.png" height=300 width=700"></a>
	    </kbd>
</p>

- **chunked-encoding is an alternative way of specifying the length of the message whereby insted of specifying it upfront you send transfer-encoding chunked and that triggers the server to parse the body of the request and until it reaches the terminating chunk which is a zero followed by an empty line.**

  As you can see here, 

- If the Front-end looks at the C.L --> 6 and Back-end treats this message as chunked than we'll see the exactly the same result as the classic approach which is **"Unknown method GPOST".**

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/9.png" height=300 width=700"></a>
	    </kbd>
</p>

### `3. Desynchronizing: the TE.CL approach`

`If it's the backend that doesn't support chunked encoding, we'll need to flip the offsets around:`

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/10.png" height=280 width=700"></a>
	    </kbd>
</p>

#### ***`Question, why the Content-Length is 3?`***

As you can see in the above example there is only one visible byte of data which is 6 that's because every line ends with standard HTTP Line ending which is **`\r\n`.**

- This technique(TE.CL) works on quite a few systems, but we can exploit many more by making the TransferEncoding header slightly harder to spot, so that one system doesn't see it.  
- This can be achieved using discrepancies in server's HTTP parsing. Here's a few examples of requests where only some servers recognise
the Transfer-Encoding:	chunked header.

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/11.png" height=600 width=500"></a>
	    </kbd>
</p>

Note: **"Each of these quirks is harmless if both the front-end and back-end server have it, and a major threat otherwise."**

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>2. Methodology :atom:</a></h2> 	

The theory behind request smuggling is straightforward, but the number of uncontrolled variables and our
total lack of visibility into what's happening behind the front-end can cause complications.

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/12.png" height=280 width=900"></a>
	    </kbd>
</p>
							    
<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>3. Detecting desync :detective:	</a></h2>

 **"IMP"**
- To detect request smuggling vulnerabilities we've to issue an ambiguous request followed by a normal 'Victim' r equest, then observe whether the latter gets an unexpected       response.
- **However, this is extremely prone to interference; if another user's request hits the poisoned socket before our victim request, they'll get the corrupted response and we won't spot the vulnerability.**
- This means that on a live site with a high volume of traffic it can be hard to prove request smuggling exists without exploiting numerous
  genuine users in the process.
- Even on a site with no other traffic, you'll risk false negatives caused by application-level quirks terminating connections.
							    
**`what will be the detecion strategy?`**

* sequence of messages which make vulnerable backend systems hang and time out the connection.This technique has few false positives, and most importantly has virtually no
risk of affecting other users.

**`Example 1:`**
1. Let's assume the front-end server uses the Content-Length header, and the back-end uses the TransferEncoding header. **`[CL.TE]`** 

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/13.png" height=280 width=500"></a>
	    </kbd>
</p>
							    
2. **`the front end will forward the blue text only, and the back end will time out while waiting for the next chunk size.This will cause an observable time delay.`**
3. If we take all methods for above example:
   * `CL.CL`  -->  Back-end Response  
   * `TE.TE`  -->  Front-end Response 
   * `TE.CL`  -->  Front-end Response [the frontend will reject the request, thanks to the invalid chunk size 'Q'.This prevents the backend socket from being poisoned]
   * `CL.TE`  -->  Timeout [Read the point number 2]
   
**`Example 2:`**
1. Let's assume the front-end server uses the TransferEncoding header, and the back-end uses the Content-length header. **`[TE.CL]`** 

<p align="left">
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/14.png" height=280 width=500"></a>
	    </kbd>
</p>

2. **`Thanks to the terminating '0' chunk the front-end will only forward the blue text, and the back-end will time out waiting for the X[new request] to arrive.`**
3. If we take all methods for above example:
   * `CL.CL`  -->  Back-end Response
   * `TE.TE`  -->  Back-end Response
   * `TE.CL`  -->  Timeout
   * `CL.TE`  -->  Socket poision :skull_and_crossbones: [this approach will poison the backend socket with an X, potentially harming legitimate users. Fortunately, by always running the prior detection method first, we can rule out that possibility.]

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>4. Confirming desync :thumbsup:	</a></h2>

- In this step will see the full potential of request smuggling is to prove backend socket poisoning is possible.
- To do this we'll issue a request designed to poison a backend socket, followed by a request which will hopefully fall victim to the poison.
- If the first request causes an error the backend server may decide to close the connection, discarding the poisoned buffer and breaking the attack.
- Try to avoid this by targeting an endpoint that is designed to accept a POST request, and preserving any expected GET/POST parameters.

   Note: **Some sites have multiple distinct backend systems, with the front-end looking at each request's method,URL, and headers to decide `where to route it`. If the `victim request gets routed to a different back-end from the attack request, the attack will fail`. As such, the 'attack' and 'victim' requests should initially be as similar as possible.**
 
**`4.1) If the target request looks like:`**
<p>
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/16.png" height=200 width=600"></a>
	    </kbd>
</p>


**`4.2) This is what an attack might look like:`**  
<p>
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/15.png" height=300 width=700"></a>
	    </kbd>
</p>

**`4.3) [CL.TE] and [TE.CL] socket poisoning would look like:`**
<p>
      <a href="http://nachiketrathod.com">
	   <kbd>
	     <img src="/Images/17.png" height=300 width=700"></a>
	    </kbd>
</p>

* `CL.TE` --> If the attack is successful the victim request (in green) will get a 404 response.
* `TE.CL` --> **`The TE.CL attack looks similar, but the need for a closing chunk means we need to specify all the headers ourselves and place the victim request in the body. Ensure the Content-Length in the prefix is slightly larger than the body.`**

Note: **If the site is live, another user's request may hit the poisoned socket before yours, which will make your attack fail and potentially upset the user. As a result this process often takes a few attempts, and on hightraffic sites may require thousands of attempts. Please exercise both caution and restraint, and target staging servers were possible.**

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>5. Explore :alien:</a></h2>

I'll demonstrate the **`[TE.CL]`** attack via vulnrable Lab, created with [Muzkkir Husseni](https://github.com/mymuzzy/FinitHicDeo).

Application server validate http request length on the basis of two headers.
1. Transfer-Encoding
2. Content-Length

On Live senario server has multiple load balancer or Frontend and Backend server which process the request. We are aim to exploit improper validation of request on application.
Assume, We have 4 different senarios,
1. Frontend server is validating the request length via Transfer-Encoding and Backend server validating via Content-Length headers.
2. Frontend server is validating the request length via Content-Length and Backend server validating via Transfer-Encoding headers.
3. Frontend server is validating the request length via Content-Length and Backend server validating via Content-Length headers.
4. Frontend server is validating the request length via Transfer-Encoding and Backend server validating via Transfer-Encoding headers.

To learn more types of attack visit [This Blog](https://medium.com/@knownsec404team/protocol-layer-attack-http-request-smuggling-cc654535b6f)

### **Transfer-Encoding and Content-Length Header:**

**`Transfer-Encoding:`**

When the server needs to send large amount of data, chunked encoding is used by the server because it did not exactly know how big (length) the data is going to be. In HTTP terms, when server sends response Content-Length header is omitted by the server. Instead server writes the length of current chunk in hexadecimal format followed by \r\n and then chunk, followed by \r\n (Content begins with chunk size in hex followed by chunk).
This feature can be used for progressive rendering; however the server needs to flush the data as much as possible so that client can render content progressively.
This feature is often used when server pushes data to the client in large amounts - usually in large size (mega/giga).
 * For more visit [This Blog](https://stackoverflow.com/questions/19907628/transfer-encoding-chunked)

**`Content-Length:`**

The Content-Length entity-header field indicates the size of the entity-body, in decimal number of OCTETs, sent to the recipient or, in the case of the HEAD method, the size of the entity-body that would have been sent had the request been a GET.
 * For more visit [This Blog](https://stackoverflow.com/questions/2773396/whats-the-content-length-field-in-http-header)

### **Live Demo:**

<p>
      <a href="https://drive.google.com/file/d/12TvWtaJgUNUw7awFeGUYW9mQbh7NTY0s/view">
	   <kbd>
	     <img src="/Images/FHD.png" height=300 width=650"></a>
	    </kbd>
</p>

**`Calculating Transfer-Encoding header:`**
							    
```
GET / HTTP/1.1
Host: 192.168.0.109
Content-Length: 4
Transfer-Encoding: chunked

2c
GET /path HTTP/1.1
Host: 127.0.0.1:8080


0
```

<p>
      <a href="https://drive.google.com/file/d/12TvWtaJgUNUw7awFeGUYW9mQbh7NTY0s/view">
	   <kbd>
	     <img src="/Images/19.png" height=300 width=800"></a>
	    </kbd>
</p>

On above example we are having the **`TE-CL`** Vulnerability on server. Let me explain all values one by one.
- **"Content-Length"** header in request is set according to the size of the `"2c\r\n"` bytes. 
- According to method, we are calculating the total size of first line of the content. 
- Here we also calculating the **"\r\n"** new line feed.

- **"Transfer-Encoding"** header is calculated by total bytes of the content. 
- Here we are having simple HTTP GET request which size is **`44`** till the header ends, after `"\r\n\r\n0"` which indicate to stop. 
- Decimal 44 is now converted to hexadecimal which gives `"2c"`. The reason we have added `"2c"` before the content is  the total hexadecimal value of the content. 
- After the **`"0"`** we have to add two **"\r\n"** line feed and send the request to the server.

If you send below request to the CTF server. which gives the response with the flag.

```

GET /a HTTP/1.1
Host: 192.168.0.109
Content-Length: 4
Transfer-Encoding: chunkedasd

2c
GET /flag HTTP/1.1
Host: 127.0.0.1:8080


0

GET /a HTTP/1.1
Host: 127.0.0.1:8080
    
```

<p>
      <a href="https://drive.google.com/file/d/12TvWtaJgUNUw7awFeGUYW9mQbh7NTY0s/view">
	   <kbd>
	     <img src="/Images/21.png" height=320 width=800"></a>
	    </kbd>
</p>
							    
							    
For learn more you can visit [PortSwigger's Labs](https://portswigger.net/web-security/request-smuggling). 
							    
<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>References:</a></h2>

 * https://medium.com/@knownsec404team/protocol-layer-attack-http-request-smuggling-cc654535b6f
 * https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf
 * https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door.pdf
 * https://www.youtube.com/watch?v=_A04msdplXs&t=904s

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>Lab Download:</a></h2>

 * [Parctice lab](https://drive.google.com/file/d/12TvWtaJgUNUw7awFeGUYW9mQbh7NTY0s/view)

<h2><a id="user-content-tldr" class="anchor" href="#tldr"><span class="octicon octicon-link"></span></a>Special Thanks</a></h2>

 - [James Kettle](https://twitter.com/albinowax)
 - [Muzkkir Husseni](https://github.com/mymuzzy/FinitHicDeo)
 - [Nishith Khadadiya](https://twitter.com/busk3r)

 <strong>EOF</strong>
