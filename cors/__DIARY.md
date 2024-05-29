##
#
https://github.com/xitu/gold-miner/blob/master/article/2021/deep-dive-cors-history-how-it-works-best-practices.md
#
##

> - Original article address: [Deep dive in CORS: History, how it works, and best practices](https://ieftimov.com/post/deep-dive-cors-history-how-it-works-best-practices/)
> - Original author: [Ilija Eftimov](https://ieftimov.com/)
> - Translation from: [Gold Miner Translation Project](https://github.com/xitu/gold-miner)
> - This article’s permanent link: [https://github.com/xitu/gold-miner/blob/master/article/2021/deep-dive-cors-history-how-it-works-best-practices.md](https://github.com/xitu/gold-miner/blob/master/article/2021/deep-dive-cors-history-how-it-works-best-practices.md)
> - Translator: [snowyYU](https://github.com/snowyYU)
> - Proofreaders: [Kimhooo](https://github.com/Kimhooo), [Chorer](https://github.com/Chorer)

# In-depth understanding of CORS: history, working principles and best practices

Understand the history and evolution of the Same Origin Policy and CORS, gain a deeper understanding of CORS and the various types of cross-origin access, and learn (some) best practices.

## Translator’s note:

- The browser used in this article is FireFox browser, and the code demonstration results are slightly different from Chrome browser.
- The backend nodejs version code can be viewed [here](https://github.com/snowyYU/Deep-dive-in-CORS-BK-Code).

## Common error messages in the browser console

> No 'Access-Control-Allow-Origin' header is present on the requested resource.

> Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at [https://example.com/](https://example.com/)

> Access to fetch at '[https://example.com](https://example.com)' from origin 'http://localhost:3000' has been blocked by CORS policy.

You must have seen these errors before, but if you haven’t, it’s okay. There will be many CORS-related error messages below for your reference.

Seeing these errors always makes people very annoyed. But to be fair, CORS is definitely a very useful mechanism that can effectively avoid vulnerabilities caused by configuration problems in backend services, prevent malicious attacks, and promote the evolution of web standards.

Let’s start from the beginning

## Starting from the birth of the first subresource

A subresource is an HTML element that is usually embedded in the document flow or executed in a related context (such as a `<script>` tag). In [1993](http://1997.webhistory.org/www.lists/www-talk.1993q1/0182.html), the first subresource `<img>` was introduced. With the introduction of the `<img>` tag, websites became more beautiful, and of course, websites began to become more and more complex from then on.

![Back to 1993](https://ieftimov.com/back-to-the-origin-with-cors/meet-img.png)

You can see that if the browser needs to render a page with an `<img>` tag, it will get the relevant sub-resources from one place. When the browser initiates a resource request, if one or more of the protocol, domain name, and port number of the request address is different from the target address, then this request is a **cross-origin request**.

### Origin and cross-domain

A complete origin consists of three things: protocol, qualified domain name, and port. For example, `http://example.com` and `https://example.com` are different origins - the first one uses the `http` protocol and the second one uses the `https` protocol. In addition, `http` uses port 80 by default, while `https` uses port 443 by default. Although the domain name is `example.com`, they have different protocols and ports, so they belong to different origins.

Got it? If any one of the three factors mentioned above is inconsistent, then their sources are not the same.

We compare `https://blog.example.com/posts/foo.html` with the following URL, and it is clear at a glance whether they are from the same origin:

| URL | Result | Reason |
| ---------------------------------------------- | ------ | ------------------------------------- |
| `https://blog.example.com/posts/bar.html` | Same origin | Only the path is different |
| `https://blog.example.com/contact.html` | Same origin | Only the path is different |
| `http://blog.example.com/posts/bar.html` | Different origin | Different protocol |
| `https://blog.example.com:8080/posts/bar.html` | Different origin | Different port (`https://` defaults to port 443) |
| `https://example.com/posts/bar.html` | Different origin | Different hostname |

To illustrate a cross-origin request, if the page `http://example.com/posts/bar.html` tries to render a resource from the address `https://example.com`, a cross-origin request will be generated (note that their protocols are different).

### Cross-domain requests are dangerous

Above we have learned what is homology and what is cross-domain. Now let's take a look at the main problems.

After the introduction of `<img>`, new tags emerged in large numbers, such as `<script>`, `<frame>`, `<video>`, `<audio>`, `<iframe>`, `<link>`, `<form>`, etc. During the loading process of a web page, the resources required by the page can be obtained through the above tags, and these resource requests may be either homologous or cross-domain.

Imagine if CORS didn't exist, and browsers allowed all kinds of cross-origin requests.

Suppose there is a `<script>` tag on the page under my `evil.com` domain. It looks like this is just an ordinary page where users can get some useful information. In fact, in the `<script>` tag, I wrote a piece of code to initiate a request to the bank's `DELETE /account` interface. Since we assumed above that the browser allows various cross-domain requests, every time you visit this page, there will be an AJAX request quietly calling the bank's API.

![Poof, your account is ruined🌬](https://ieftimov.com/back-to-the-origin-with-cors/malicious-javascript-injection.png)

Hey, imagine you are browsing the web and suddenly you get an email from your bank, congratulating you on successfully deleting your account. I know what you are thinking, if it is so easy to delete an account, then you can do **anything** to the bank, ahem, but I digress.

In order for my evil `<script>` to work properly, I also need to add authentication information (cookies) from the target bank website to the request. This way the bank's server knows who you are and whose account you want to delete.

Let's look at another, less sinister example.

I want to know the employee information of **Awesome Corp**, whose intranet is `intra.awesome-corp.com`. On my website `dangerous.com`, I put a tag `<img src="https://intra.awesome-corp.com/avatars/john-doe.png">`.

For those who do not have access to the target company intranet `intra.awesome-corp.com`, the above tag will not load the image - it will generate an error message. On the other hand, if you can connect to the awesome company intranet, and you open the `dangerous.com` website, then I know you have access to the awesome company intranet.

This means I will be able to get some information about you. Although this information is not enough for me to launch a valuable attack, the fact that you can access the internal network of Bang Bang Company is more valuable to the attacker.

![Leaking information to third parties💦](https://ieftimov.com/back-to-the-origin-with-cors/resource-embed-attack-vector.png)

The above two examples are very simple, but they also illustrate the necessity of the same-origin policy and CORS. Of course, the harm of cross-domain requests is more than that. Some harms can be avoided, but there are also some harms that we are helpless - they are naturally rooted in the network. However, the current attacks launched through the medium have been greatly reduced - this is thanks to CORS.

But before talking about CORS, let's talk about the same-origin policy.

## Same-origin strategy

The same-origin policy prevents cross-origin attacks by blocking read permissions for resources loaded from different origins. However, this policy still allows some tags to load resources from different origins, such as the `<img>` tag.

The same-origin policy was introduced in Netscape Navigator 2.02 in 1995 and was originally intended to protect cross-domain access to the DOM.

Although there is no strict requirement for the implementation of the same-origin policy to follow an exact specification, all modern browsers implement this policy in their own way. The details of the same-origin policy can be found in [RFC6454](https://tools.ietf.org/html/rfc6454) of the Internet Engineering Task Force (IETF).

This ruleset defines the implementation of the same-origin policy:

| Tags | Cross-origin | Note |
| --------------------- | ------------ | ---------------------------------------------------------- |
| `<iframe>` | Allow embedding | Depends on `X-Frame-Options` |
| `<link>` | Embedding allowed | May require correct `Content-Type` |
| `<form>` | Allow writing | This tag is often used for cross-domain writing operations |
| `<img>` | Allow embedding | Disable cross-origin JavaScript loading into a `<canvas>` tag |
| `<audio>` / `<video>` | Allow embedding| |
| `<script>` | Allow embedding | May block access to certain APIs |

The same-origin policy solves many problems, but it also brings many limitations. Especially in single-page applications and rich media websites, its many rules actually restrict the development of the website.

In this context, CORS was born, with the goal of providing a more flexible way for cross-domain access within the framework of the same-origin policy.

## Introduction to CORS

So far we have figured out what an origin is, how it is defined, the shortcomings of cross-origin requests, and the same-origin policy implemented by browsers.

Now it's time to get familiar with Cross-Origin Resource Sharing (CORS). CORS is a mechanism that allows controlled access to subresources on a web page over the network. The mechanism divides access to subresources into three categories:

1. Cross-domain write operations
2. Cross-domain resource embedding
3. Cross-domain read operations

Before we go into detail about all three, it is important to understand that while a browser may allow a certain type of cross-origin request (by default), this does not mean that the request will be accepted by the server.

**Cross-origin writes** include links, redirects, and form submissions. All of these operations are **allowed** when CORS is enabled in the browser. In some cases, something called a **preflight request** is generated, which may affect cross-origin write operations. We will explain this in detail below.

**Cross-domain embedding** refers to sub-resources loaded through tags such as `<script>`, `<link>`, `<img>`, `<video>`, `<audio>`, `<object>`, `<embed>`, and `<iframe>`. By default, they are all **allowed** to be cross-domain embedded. However, `<iframe>` is a bit special - because its purpose is to load different pages in the frame, you can use the `X-Frame-options` response header to control whether it can be loaded across domains.

Subresources like `<img>` that can be embedded in websites - one of the reasons they were born is to obtain resources from different origins. This is why cross-domain embedding and cross-domain reading are distinguished in CORS, and the corresponding treatments are also different.

**Cross-origin reads** are generated by AJAX / `fetch` to obtain subresources. By default, browsers will **restrict** such requests. Of course, there is a way to achieve cross-origin reads by embedding subresources, but accordingly, today's browsers also have another strategy to deal with this method.

If your browser is updated to the latest version, it should already implement the above strategy.

### Cross-domain write operation

Performing a cross-origin write operation sometimes does not succeed. Let's look at an example to see CORS in action.

First, let's look at an HTTP service implemented in the Crystal language (the framework uses Kemal):

```Crystal
require "kemal"

port = ENV["PORT"].to_i || 4000

get "/" do
  "Hello world!"
end

get "/greet" do
  "Hey!"
end

post "/greet" do |env|
  name = env.params.json["name"].as(String)
  "Hello, #{name}!"
end

Kemal.config.port = port
Kemal.run
```

When receiving a request in the `/greet` path, it first gets the `name` attribute value in the request body, and then returns `Hello #{name}!`. We use the following command to start this small service:

```bash
$ crystal run server.cr
```

The service starts and starts listening on `localhost:4000`. When you access `localhost:4000` through your browser, you will see "Hello World":

![Hello, world! 🌍](https://ieftimov.com/back-to-the-origin-with-cors/hello-world-localhost.png)

OK, our service is running successfully. Now let's make a POST /greet request to localhost:4000 from the browser console. We use the fetch method to make the request:

```javascript
fetch('http://localhost:4000/greet', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Ilija' }),
})
  .then((resp) => resp.text())
  .then(console.log)
```

After executing this code, we receive a greeting from the service:

![Hi there! 👋](https://ieftimov.com/back-to-the-origin-with-cors/hello-world-localhost-post.png)

This is a non-cross-domain POST request, a same-origin request initiated from the http://localhost:4000 page (the same origin as the request target address).

Let's try to send a cross-origin request to this address. We open `https://google.com` and then make the same request as above from this tab:

![Hello, CORS! 💣](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post.png)

With this approach, we see the famous CORS error. Even though the Crystal service is able to respond to the request, our browser intercepts the request. From the error message we can see that the request is attempting a cross-origin write operation.

In the first example, we made a request from the `http://localhost:4000` page to `http://localhost:4000/greet`, and because the page address and the target address have the same origin, the browser did not intercept the request. In the second example, on the contrary, the request initiated from the website (`https://google.com`) attempted to write to `http://localhost:4000`, and the browser marked the request and intercepted it.

### Preflight Request

Looking at the contents of the Network tab in the developer console, we can see that the above code makes two requests:

![See two outbound requests in the Network panel](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-network.png)

What's interesting is that the method of the first request is OPTIONS , while the method of the second request is POST .

If you look closely at the `OPTIONS` request, you will find that the browser first sends an `OPTIONS` request and then sends a `POST` request:

![A closer look at the OPTIONS request 🔍](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-network-options.png)

Interestingly, even though the response to the OPTIONS request is HTTP 200, it is still marked in red in the request list. Why is that?

This is a **preflight request** initiated by modern browsers. If CORS considers a request to be complex, the browser will first initiate a preflight request. The criteria for determining whether a request is a **complex** request are as follows:

- The request method is not `GET`, `POST` or `HEAD`
- The request header contains fields other than `Accept`, `Accept-Language`, and `Content-Language`
- The request header contains the `Content-Type` field, and its value is not among `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain`

Therefore, in the above example, even though we initiated a POST request, the browser still determined that our request was a complex request due to the Content-Type: application/json in the request header.

If we modify our request and service to send and process `text/plain` content (instead of JSON), the browser will not initiate the preflight request:

```Crystal
require "kemal"

get "/" do
  "Hello world!"
end

get "/greet" do
  "Hey!"
end

post "/greet" do |env|
  body = env.request.body

  name = "there"
  name = body.gets.as(String) if !body.nil?

  "Hello, #{name}!"
end

Kemal.config.port = 4000
Kemal.run
```

Now we can make a request with `Content-type: text/plain` in the request header:

```javascript
fetch('http://localhost:4000/greet', {
  method: 'POST',
  headers: {
    'Content-Type': 'text/plain',
  },
  body: 'Ilija',
})
  .then((resp) => resp.text())
  .then(console.log)
```

See, there is no preflight request this time, but the browser's CORS policy is still blocking the response:

![CORS still holds up](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-text-plain.png)

However, because we did not initiate a **complex** request this time, our browser **did not intercept the request**:

![Request initiated successfully➡️](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-text-plain-response-blocked.png)

In short: for cross-origin requests like `text/plain`, our service **lacked response configuration**, which resulted in the inability to process this request, and no unified exception handling, which has nothing to do with the browser. However, the browser did its best to do the following - it would not expose the response directly in the page and request list. Therefore, in this case, CORS did not intercept the request - **it intercepted the response**.

The CORS policy in the browser considers this request to be a cross-origin read request. Even though the request method is `POST`, the attribute value of `Content-type` in the request header shows that it is essentially the same as a `GET` request. Cross-origin read requests are intercepted by default, so we see the intercepted response in the request list.

Eliminating preflight requests to deal with CORS policies is not a good idea. In fact, if you want the server to properly handle preflight requests, it should return a response with the correct response header for the `OPTIONS` method request.

When handling OPTIONS requests, you need to be aware that browsers pay special attention to three attributes that appear in the preflight request response header:

- `Access-Control-Allow-Methods` - This attribute identifies which request methods are supported by the response URL under the CORS policy.
- `Access-Control-Allow-Headers` - This property identifies which request headers are supported for the response URL under the CORS policy.
- `Access-Control-Max-Age` — This indicates the number of seconds that the information provided in the `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` headers can be cached (default is 5).

Now let's look at the complex request example above:

```javascript
fetch('http://localhost:4000/greet', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Ilija' }),
})
  .then((resp) => resp.text())
  .then(console.log)
```

As we know above, when initiating this request, our browser will first check whether the server can handle cross-domain requests based on the response of the preflight request. In order to respond to this cross-domain request correctly, we must first add the `OPTIONS /greet` endpoint to our service. In the response header of this service, the newly added endpoint will tell the browser that `POST /greet` requests from the origin `https://www.google.com` and with the `Content-type: application/json` header can be received.

To achieve this, we use the Access-Control-Allow-* response headers:

```Crystal
options "/greet" do |env|
  # Allow `POST /greet`...
  env.response.headers["Access-Control-Allow-Methods"] = "POST"
  # ...with `Content-type` header in the request...
  env.response.headers["Access-Control-Allow-Headers"] = "Content-type"
  # ...from https://www.google.com origin.
  env.response.headers["Access-Control-Allow-Origin"] = "https://www.google.com"
end
```

Restart the service and make the request again:

![Still blocked? 🤔](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-blocked.png)

Our request is still being blocked. Even though our `OPTIONS /greet` endpoint does handle the request appropriately, we still see an error message. However, the Network tab in the developer tools shows us some interesting information:

![OPTIONS The request line turns green! 🎉](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-blocked-network-inspect.png)

The request to the `OPTIONS /greet` endpoint succeeded! However, the `POST /greet` call still fails. If we take a look at the internals of the `POST /greet` request, we will see a familiar message:

![POST is also successful? 😲](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-blocked-post-inspect.png)

In fact, the request succeeded - the service returned HTTP 200. The preflight request did work - the browser successfully initiated the POST request. However, the response to the POST request did not include the CORS header information, so even though the browser initiated the request, the response was blocked by itself.

In order for the browser to correctly handle the response from the `POST /greet` request, we also need to add a CORS header to the `POST` endpoint:

```Crystal
post "/greet" do |env|
  name = env.params.json["name"].as(String)

  env.response.headers["Access-Control-Allow-Origin"] = "https://www.google.com"

  "Hello, #{name}!"
end
```

When we add the `Access-Control-Allow-Origin` attribute to the response header, it tells the browser to open the `https://www.google.com` tab to access the response content.

Try it again:

![POST success! ](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-success.png)

We can see that `POST /greet` returns the correct response content and no errors are reported. If we take another look at the Network tab, we will find that both requests are green:

![OPTIONS & POST success! 💪](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-success-network.png)

By using the correct response headers in the preflight endpoint `OPTIONS /greet`, cross-origin requests can access the `POST /greet` endpoint in our service. Most importantly, after adding the correct CORS response header information for the `POST /greet` endpoint, the browser can finally stop blocking cross-origin responses.

### Cross-domain reading

As we mentioned above, cross-origin reads are blocked by default. This is intentional - we don't want to load resources from other origins on the current page.

Suppose we add an operation for `GET /greet` request in the Crystal service:

```Crystal
get "/greet" do
  "Hey!"
end
```

We try to request the `GET /greet` endpoint from the `www.google.com` page and find that it is blocked by CORS:

![CORS interception 🙅](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-get.png)

Looking closely at the request content, we find something interesting:

![ GET request successful 🎉](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-get-blocked-inspect.png)

As before, the browser did allow the request to be made successfully - an HTTP 200 response was received. However, the browser did not display the response to that request on the page/console. Again, CORS did not intercept the request in this example - it intercepted the response.

Just like cross-origin write operations, we can set up CORS and enable it for cross-origin reads by adding a header with `Access-Control-Allow-Origin`:

```Crystal
get "/greet" do |env|
  env.response.headers["Access-Control-Allow-Origin"] = "https://www.google.com"
  "Hey!"
end
```

When the browser gets a response from the server, it checks the value of the `Access-Control-Allow-Origin` attribute in the response header to decide whether to allow the page to read the response content. Now that we set the value to `https://www.google.com`, we can load the response correctly:

![Successfully initiated a GET cross-origin request🎉](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-get-success.png)

In this way, the browser can prevent the harm caused by cross-domain reading, and give the back-end service a certain operating space so that it can respond to specific cross-domain requests.

## Configure CORS

As we did in the example above, in order to comply with the CORS policy in the browser, we set the value of the `Access-Control-Allow-Origin` attribute in the response header to `https://www.google.com` for the `/greet` request:

```Crystal
post "/greet" do |env|
  body = env.request.body

  name = "there"
  name = body.gets.as(String) if !body.nil?

  env.response.headers["Access-Control-Allow-Origin"] = "https://www.google.com"
  "Hello, #{name}!"
end
```

This will allow the `https://www.google.com` origin to call our service, and the browser will not report any errors. After setting the value of `Access-Control-Allow-Origin`, we can try to perform the `fetch` operation again:

![Success! 🎉](https://ieftimov.com/back-to-the-origin-with-cors/google-cross-origin-post-text-plain-success.png)

Success! Now we can make a cross-origin request from `https://www.google.com` to `/greet`. Alternatively, we can set the corresponding attribute value in the header to `*`, so that the browser will allow any origin to make a correct cross-origin request to our service.
You need to think twice before configuring this value, but it is safe in most cases. Here is a summary suggestion for your reference: If the cross-domain request is made from a tab in the browser's incognito mode, and the data obtained is exactly what you want to display, then you can set a lenient value (`*`) to deal with the CORS policy.

Another way to configure CORS to relax request restrictions is to use a response header with the `Access-Control-Allow-Credentials` attribute. When the request's credetials mode is `include`, the browser will decide whether to expose the response to the front-end JavaScript code based on the value of the `Access-Control-Allow-Credentials` in the response header.

The credetials pattern in the request comes from the [Fetch API](https://fetch.spec.whatwg.org/) documentation, and its origin can be traced back to the original XMLHttpRequest object:

```javascript
var client = new XMLHttpRequest()
client.open('GET', './')
client.withCredentials = true
```

From the documentation of the `fetch` method, we know that the `withCredentials` attribute in XML is used as an optional parameter in the call of the `fetch` method:

```javascript
fetch('./', { credentials: 'include' }).then(/* ... */)
```

The optional `credentials` attribute values ​​are `omit`, `same-origin`, and `include`. The backend service can decide how the browser displays the response (via the `Access-Control-Allow-Credentials` response header) based on the different `credentials` attribute values ​​in the request.

The Fetch API documentation provides a detailed [division and description](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials) of the interaction between CORS and the `fetch` API and the security mechanisms used by browsers.

## Some best practices

Before we wrap up, let’s cover some best practices for Cross-Origin Resource Sharing (CORS).

### For a large number of users

A common example is if you have a website that displays content that is publicly available and does not require payment, identity verification, or authorization to view - in this case you can set the response header `Access-Control-Allow-Origin: *` for requests to obtain this content.

It is better to set the value to `*` in the following scenarios:

- Unrestricted access to this resource by a large number of users
- This resource needs to be accessible to a large number of users without restriction
- There are many sources and clients accessing resources, and it is impossible to set a specific value, or you don't care about the problems caused by cross-domain requests

If this setting is applied to respond to requests for resources on a private network (for example, protected by a firewall, or requiring VPN access), there will be certain risks. When you connect to the company's intranet through VPN, you have access to intranet files:

![Simplified example of VPNs connection](https://ieftimov.com/back-to-the-origin-with-cors/vpn-access-diagram.png)

Now, assuming that the attacker has a link to a file on their website dangerous.com, they could (theoretically) create a script on their website that has access to that file:

![File leak](https://ieftimov.com/back-to-the-origin-with-cors/vpn-access-attacker-diagram.png)

While launching such an attack is difficult and requires a lot of knowledge about VPNs and the files stored within them, we must be aware that setting `Access-Control-Allow-Origin: *` is potentially risky.

### Internal facing

Continuing with the example above, suppose we need to perform statistical analysis on our website. We may need to use the relevant data sent by the user's browser to collect the user's experience and behavior.

A common approach is to periodically use JavaScript to initiate asynchronous requests from the user's browser. The backend has an API to receive these requests and then store and process the data.

In this case, our backend API is public, but we don't want **any** website to be able to send data to our data collection API. In fact, we are only interested in requests from our own website - that's it.

![](https://ieftimov.com/back-to-the-origin-with-cors/no-cross-origin-api.png)

In this example, we set the API response header attribute `Access-Control-Allow-Origin` value to our website URL. This way, requests from other origins will be blocked by the browser.

Even if users or other websites desperately plug data into our statistics interface, the `Access-Control-Allow-Origin` attribute set in the API resource response header will not allow the request to pass:

![](https://ieftimov.com/back-to-the-origin-with-cors/failed-cross-origin-api.png)

### The Origin attribute value in the request header is NUll

Another interesting example is the `null` origin. This happens when you use a browser to directly open a local file with a resource request. For example, a request from some JavaScript running in a static file on your local machine will set the `Origin` property in the request header to `null`.

In this case, if our service does not allow requests with an origin value of `null` to access our resources, this may affect the efficiency of developers. If your website/product is for developers, you can allow this type of cross-domain request to access resources by setting `Access-Control-Allow-Origin`.

### Avoid using cookies as much as possible

In the above article, we talked about how, by default, cookies are not allowed in requests when using the `Access-Control-Allow-Credentials` field. You only need to set the response header `Access-Control-Allow-Credentials: true` to allow cross-domain requests to send cookies. This will tell the browser backend service to allow cross-domain requests to carry authentication information (such as cookies).

Allowing and accepting cross-domain cookies can be risky. This exposes you to potential attack vectors, so you should only enable it when absolutely necessary.

When you know exactly which clients will access your server, cross-domain cookies can only play their own value. This is why CORS rules do not allow us to set `Access-Control-Allow-Origin: *` when cross-domain requests are allowed to carry authentication information.

Technically speaking, `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` can be used in combination, but this is an [anti-pattern](https://zh.wikipedia.org/wiki/%E5%8F%8D%E9%9D%A2%E6%A8%A1%E5%BC%8F) and should be avoided.

If you want your service to be accessible to different clients and origins, you should consider developing an API to generate authentication information (using token-based authentication) instead of using cookies. However, if you cannot solve the problem with an API, make sure you have protection against cross-site request forgery (CSRF).

## Additional Reading

I hope this (long) article can give you a clear understanding of CORS, including its principles and its significance. Below are some reference links to this article, and some articles about CORS that I personally think are great:

- [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [`Access-Control-Allow-Credentials` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials) on MDN Web Docs
- [Authoritative guide to CORS (Cross-Origin Resource Sharing) for REST APIs](https://www.moesif.com/blog/technical/cors/Authoritative-Guide-to-CORS-Cross-Origin-Resource-Sharing-for-REST-APIs/)
- The [“CORS protocol” section](https://fetch.spec.whatwg.org/#http-cors-protocol) of the [Fetch API spec](https://fetch.spec.whatwg.org)
- [Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) on MDN Web Docs
- [Quentin's](https://stackoverflow.com/users/19068/quentin) great [summary of CORS](https://stackoverflow.com/a/35553666) on StackOverflow

> If you find errors or other areas that need improvement in the translation, you are welcome to modify the translation and PR it in [Gold-miner Translation Project](https://github.com/xitu/gold-miner), and you can also get corresponding bonus points. The **Permanent link of this article** at the beginning of the article is the MarkDown link of this article on GitHub.

---

> [Gold-Miner Translation Project](https://github.com/xitu/gold-miner) is a community that translates high-quality Internet technology articles. The source of the articles is the English sharing articles on [Juejin](https://juejin.im). The content covers [Android](https://github.com/xitu/gold-miner#android), [iOS](https://github.com/xitu/gold-miner#ios), [Front-end](https://github.com/xitu/gold-miner#Front-end), [Back-end](https://github.com/xitu/gold-miner#Back-end), [Blockchain](https://github.com/xitu/gold-miner#Blockchain), [Products](https://github.com/xitu/gold-miner#Products), [Design](https://github.com/xitu/gold-miner#Design), [Artificial Intelligence](https://github.com/xitu/gold-miner#Artificial Intelligence) and other fields. If you want to see more high-quality translations, please continue to pay attention to the [Nuggets Translation Project](https://github.com/xitu/gold-miner), [Official Weibo](http://weibo.com/juejinfanyi), and [Zhihu Column](https://zhuanlan.zhihu.com/juejinfanyi).
