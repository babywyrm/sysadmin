# Handle CORS Client-side

>**Cross-origin resource sharing** (CORS) is a mechanism that allows restricted resources (e.g. fonts) on a web page to be requested from another domain outside the domain from which the first resource was served. **This is set on the server-side and there is nothing you can do from the client-side to change that setting, that is up to the server/API. There are some ways to get around it tho.**

_Sources_ : [MDN - HTTP Access Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS) | [Wiki - CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing)

**CORS** is set server-side by supplying each _request_ with additional headers which allow requests to be requested outside of the own domain, for example to your `localhost`. This is primarily set by the header:
```http
Access-Control-Allow-Origin
```
The header specifies which origins (domains/servers) the information can be accessed from. To enable **CORS** you usually set it to allow access from all origins with a _wildcard (*)_:
```http
Access-Control-Allow-Origin: *
```
or you can tell the server to serve content to specific domains, every other domain will be blocked from showing the content in a browser:
```http
Access-Control-Allow-Origin: https://developer.mozilla.org
```

## Bypass client-side for production

### Proxy

**`WARNING`: Great services, but you are dependent on these services to work, if they break or go down, so does your app**

You can use a service that proxies your request and automatically enable `CORS` for your:
* https://cors-anywhere.herokuapp.com/
* [More Proxies here](https://gist.github.com/jimmywarting/ac1be6ea0297c16c477e17f8fbe51347)

Then you have to call your API by prepending one of these URLs to your request, for example:
* https://cors-anywhere.herokuapp.com/http://yourapi.com
 

### JSONP

**`WARNING`: This isn't allowed on every API and may break when calling certain APIS** 

You can bypass **CORS** in production using `JSONP` which stands for **JSON with Padding** and is kinda also a 'hack'. But it is a widely used hack which many APIs support. You are not sending a pure JSON-request but you are wrapping your data in a function that gets evaluated. `JSONP` explained in the link below:

[JSONP explained in layman terms @ Stack Overflow](http://stackoverflow.com/questions/3839966/can-anyone-explain-what-jsonp-is-in-layman-terms)


#### jQuery $.ajax() JSONP

The simplest way to handle JSON is through the `$.ajax()`-function in _jQuery_ as it handles the real dirty parts automatically:

```js
$.ajax({
  method: 'GET',
  url: 'http://localhost:3000',
  dataType: 'jsonp', //change the datatype to 'jsonp' works in most cases
  success: (res) => {
   console.log(res);
  }
})
```

[jQuery: Working with JSONP](https://learn.jquery.com/ajax/working-with-jsonp/)

#### fetch-jsonp library

There is no native implementation of `JSONP` in either `XMLHttpRequest` or `fetch`. If you want to use `fetch` you can use this 1kb library which handle `JSONP` with `fetch`:

[fetch-jsonp @ GitHub](https://github.com/camsong/fetch-jsonp)

1. Link the code in your `index.html`:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/fetch-jsonp/1.0.6/fetch-jsonp.min.js"></script>
```

2. And use like fetch but with the function `fetchJsonp`:
```js
fetchJsonp('http://localhost:3000')
  .then(res => res.json())
  .then(json => console.log(json));
```

#### Vanilla JavaScript jsonp

It can be done in regular JavaScript as well of course:

* **[Simple JSONP in vanilla JS](https://gist.github.com/gf3/132080/110d1b68d7328d7bfe7e36617f7df85679a08968)**

## Handle CORS via a Node proxy server

**`WARNING`: This works in many cases but it is not a "fix all"-solution. You also have to have a server running at all time.**

We are entering backend territory, be aware. You can redirect the traffic from your choosen API through your own server(in this case, `node` but it can be any server) and this will allow you to set the headers that control `CORS` yourself. So the request will actually be `your app` -> `your server` -> `external API` -> `your server` -> `your app`. You can set up a `node`-server that makes a request to to the API via the package `request` for you. This is basically what the links further up under [#proxy](Proxy) does.

Instructions for setting this up yourself are in the repository in the link below.

* [__node-api-proxy__ by _jesperorb_](https://github.com/jesperorb/node-api-proxy)

This will allow you to make your calls to `http://localhost:8000` instead of the API-URL (or to whatever URL you decide to host it on). 

## Bypass during development :hammer:

**`WARNING`: All users who uses your site must use this hack so this is only intended for bypassing temporarily and for testing during development. You can't assume it will work for your end users. This is just a client-side quick fix and it doesn't change the way the server handles the request. This will make your site work on your computer and every other browser that also has this extension installed.**

If you have _Chrome_ you can use a extensions which 'hacks' the response/request. Be sure to disable it when not testing as it can break other sites, GitHub have been known to have problems with this extension if you have it enabled when browsing or using GitHub.

[Allow-Control-Allow-Origin: * @ Chrome Web Store](https://chrome.google.com/webstore/detail/allow-control-allow-origi/nlfbmbojpeacfghkpbjhddihlkkiljbi?hl=en)

