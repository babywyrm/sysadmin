Using CORS and JSONP to make cross-origin requests
You can make API requests across domains using cross-origin resource sharing (CORS) and JSONP callbacks.

##
#
https://docs.github.com/en/rest/using-the-rest-api/using-cors-and-jsonp-to-make-cross-origin-requests?apiVersion=2022-11-28
#
https://medium.com/developers-arena/understanding-json-jsonp-cors-and-bypassing-cors-with-jsonp-fa5f0cc4edd4
#
##

In this article
About cross-origin requests
Cross-origin resource sharing (CORS)
JSON-P callbacks
About cross-origin requests
A cross-origin request is a request made to a different domain than the one originating the request. For security reasons, most web browsers block cross-origin requests. However, you can use cross-origin resource sharing (CORS) and JSONP callbacks to make cross-origin requests.

Cross-origin resource sharing (CORS)
The REST API supports cross-origin resource sharing (CORS) for AJAX requests from any origin. For more information, see the "CORS W3C Recommendation" and the HTML 5 Security Guide

Here's a sample request sent from a browser hitting http://example.com:
```
$ curl -I https://api.github.com -H "Origin: http://example.com"
HTTP/2 302
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: ETag, Link, X-GitHub-OTP, x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval
```

This is what the CORS preflight request looks like:
```
$ curl -I https://api.github.com -H "Origin: http://example.com" -X OPTIONS
HTTP/2 204
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Authorization, Content-Type, If-Match, If-Modified-Since, If-None-Match, If-Unmodified-Since, X-GitHub-OTP, X-Requested-With
Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE
Access-Control-Expose-Headers: ETag, Link, X-GitHub-OTP, x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval
Access-Control-Max-Age: 86400
```


JSON-P callbacks
You can send a ?callback parameter to any GET call to have the results wrapped in a JSON function. This is typically used when browsers want to embed GitHub content in web pages and avoid cross-domain problems. The response includes the same data output as the regular API, plus the relevant HTTP Header information.

$ curl https://api.github.com?callback=foo
```
> /**/foo({
>   "meta": {
>     "status": 200,
>     "x-ratelimit-limit": "5000",
>     "x-ratelimit-remaining": "4966",
>     "x-ratelimit-reset": "1372700873",
>     "Link": [ // pagination headers and other links
>       ["https://api.github.com?page=2", {"rel": "next"}]
>     ]
>   },
>   "data": {
>     // the data
>   }
> })
```



You can write a JavaScript handler to process the callback. Here's a minimal example you can try:
```
<html>
<head>
<script type="text/javascript">
function foo(response) {
  var meta = response.meta;
  var data = response.data;
  console.log(meta);
  console.log(data);
}

var script = document.createElement('script');
script.src = 'https://api.github.com?callback=foo';

document.getElementsByTagName('head')[0].appendChild(script);
</script>
</head>

<body>
  <p>Open up your browser's console.</p>
</body>
</html>
```


All of the headers have the same string value as the HTTP Headers, except Link. Link headers are pre-parsed for you and come through as an array of [url, options] tuples.

For example, a link that looks like this:

Link: <url1>; rel="next", <url2>; rel="foo"; bar="baz"
will look like this in the Callback output:
```
{
  "Link": [
    [
      "url1",
      {
        "rel": "next"
      }
    ],
    [
      "url2",
      {
        "rel": "foo",
        "bar": "baz"
      }
    ]
  ]
}
Press alt+up to activate
