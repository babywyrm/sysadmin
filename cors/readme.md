
Summary
CORS or Cross Origin Resource Sharing is a way to allow cross domain requests to be serviced by the browser. It was implemented by browser vendors as a response to requests to let client side script make webservice calls across domains. Point to note is that it is the called webservice that has to allow CORS by adding appropriate headers to the response: Access-Control-Allow-Origin Access-Control-Allow-Headers Access-Control-Allow-Methods

Terms
CAS: Central Authentication Service - aka Single Sign on
CORS: Cross Origin Resource Sharing
Scenario
Sign-on process requires:

Client side script to POST credential data to a webservice/API hosted on a domain that is different from the page making the request. E.g. Page on ui.mydomain.com, service on api.mydomain.com
The result of the POST is a redirect that the browser needs to follow (HTTP 302)
What happens
Modern browsers (e.g. Chrome) set the Origin header to null as the detect sensitive information being sent in the redirect. See here When the webservice/API responds, the browser checks for Access-Control-Allow-Origin, (If present: Access-Control-Allow-Headers, Access-Control-Allow-Methods)

If there is no Access-Control-Allow-Origin header: The browser blocks and does not load the response as it infers this as cross origin request that is not allowed
If there is Access-Control-Allow-Origin header, but has a value other than "*", the browser still blocks as it sees that the allowed origin does not match with requested origin (null)
References
CAS and jQuery AJAX: stackoverflow
Fetch API: Blog


##
####################
####################
##


NPM
Bypass CORS restrictions on external domains from Node.js server, scraping any webpage data's as a HTML DOM to make your own APIs. Relative paths for resources will still load using target page's domain.

On the server, setup a route to which the client can pass the URL of the page to retrive:

app.get('/geturl', function(req,res){
    require('bypasscors')(req.query.url, function(html){
	    return res.send(html);
    });
});
On the frontend, you can use jQuery to parse the HTML as DOM :

$.get('/geturl', {url: "http://google.com"}, function(html){
	$(html).find("div")
})
Example: Live demo: http://hkrnews.com/

Local demo:

npm i bypasscors express
node node_modules/bypasscors/example
Virtual DOM and JS
This approach only returns the html and text returned at that URL, not the HTML DOM and text inserted after page load by AJAX requests or by single-page interface frameworks like React.js. To overcome this you can create a virtual DOM and JS execution environment by creating an invisible iframe then loading into its source the URL to your local-host-proxied scraper end point, then you can access the iframe DOMs contents (chrome treats both the iframe and your domain as same origin). If you need a JS DOM execution environment on the server-side you can use Ghost Driver which implements Selenium WebDriver methods executed in the environment of the PhantomJS Webkit engine.

<iframe id="dom-iframe" style="width:0;height:0;border:0; border:none;"></iframe>

document.getElementById('dom-iframe').src = '/get?url=' + url;

document.getElementById('dom-iframe').contentWindow.document.body.innerHTML;

###############
###############
<br>
<br>


cors-bypass
Bypass the browsers CORS restrictions, without needing to setup a server-side proxy. Demo

Allows you to make HTTP requests from a HTTPS page
100% coverage for the WebSocket API spec
How does this module work?
It uses postMessage to send cross-domain events, which is used to provide mock HTTP APIs (fetch, WebSocket, XMLHTTPRequest etc.). Simplified version

How do I use it
Theres three components to this module: the Server, Adapter and Client.

Server
Simply serve a HTML file on a domain from which you want to make requests from (HTTP domain for example), with the following (use a bundler like Webpack, Parcel etc):

import { Server } from 'cors-bypass'

const server = new Server()
Without a bundler
Adapter
Next you need a HTML file from the domain that will make requests (your web app's domain). The adapter is in control of forwarding requests from a client located on any page of your site, to the server (using a BroadcastChannel).

import { Adapter } from 'cors-bypass'
const adapter = new Adapter()
Without a bundler
Client
As long as the Adapter is running in a different tab (on the same domain as the client), you will be able to make requests.

// Located somewhere on https://your-site.com
import * as BypassCors from 'cors-bypass'

const client = new BypassCors.Client()

await client.getServer() // null - no server connected yet
await client.openServerInNewTab({
  serverUrl: 'http://random-domain.com/server.html',
  adapterUrl: 'https://your-site.com/adapter.html'
})
await client.getServer() // { id: 123, url: 'http://random-domain.com/server.html' }

// Create a WebSocket (websocket is loaded in the server tab, but it's API is available on this page)
const ws = new BypassCors.WebSocket('ws://echo.websocket.org')
ws.onopen = () => ws.send('hello')
ws.onmessage = ({ data }) => console.log('received', data)
Use cases
HTTP requests for Offline PWAs
As using a Service Worker require HTTPS, it's impossible to connect to local devices which only support HTTP.

Using this module does requires the user to open an extra window, but it lets you bypass cors.
