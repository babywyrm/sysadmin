##
#
https://gist.github.com/Zirak/3086939
#
##


Lol.




So, you want to send a motherfucking XMLHttpRequest (XHR, or commonly and falsly known as AJAX.) 
Too bad, just ran out of motherfucking XMLHttpRequests; but I still have one regular. XHR is not magic. 
It does not autofuckinmagically send things the way you want them do be sent. It does not do the thinking for you. It just sends an Http Request.

You get a hold on such a prime beast like this:

```
var xhr = new XMLHttpRequest();
It's different in IE6-. But I don't give a fuck about IE6. If you do, then google it. Congrats, you're on your way to AwesomeVille. Step 1, getting the car, complete. Bitchin ride. I heard the flames make it go faster. Your car's smart, though, so just tell it how and where to go, otherwise known as Step 10:

xhr.open( method, url );
Your car knows how to GET, POST, DELETE, HEAD, OPTIONS and PUT. No, you don't need to know all of them (you fucking well should), but usually just GET or POST will do. Here, I wrote the coordinates down for you:

xhr.open( 'GET', 'awesome.ville' );
(See "Tonsil A: open" for more rants, if I can be fucked to write it. Why not Appendix? I wanted an original unnecessary organ.)

Here's the part where you set up the gear. Your ride needs pimpin. Luckily, it has event handlers. The most important one you'll care about is readystatechange. You can skip this step, also known as Step 11:

xhr.onreadystatechange = function () {
    //when xhr.readyState === 4, it was received by the server
	if ( xhr.readyState === 4 ) {
	    //do shit, preferabbly call a callback or some other crap
		//xhr.status has the status code. I bet you didn't see that coming.
		//xhr.responseText includes the raw response
		//xhr.responseXML is a DOM object if you requested an XML doc
	}
};

```

And a very crucial point: Gas. It's important to know if you run on diesel or not. Luckily, we have request headers, in the glorious step 100:
```
xhr.setRequestHeader( headerName, headerValue );
//or, hardcoded to nearly every fucking need your pathetic ass will ever
// encounter:
xhr.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded' );
```

Now, ride, motherfucker! Ride into the horizon, Step 101!

xhr.send();
Say what? You wanna sent data to the server? ...Fine. Ruin my analogy. If you've ever taken the time to get up from your smelly sofa and actually look at how HTTP request bodies look, then you'll know they look like this:

key0=value0&key1=value1
And every key and every value are, of course, URI encoded. Here's a stupid example:

xhr.send( 'tifa\'sBoobs=huge&your%20mother=insulted' );
Which translated to, surprise, tifasBoobs=huge and your mother=insulted.

In conclusion:

//step 1
var xhr = new XMLHttpRequest();
//step 10
xhr.open( method, url );
//step 11
xhr.onreadystatechange = function () { ... };
//step 100
xhr.setRequestHeader( ..., ... );
//repeat step 100 until obtained all secret desires
//step 101
xhr.send( optionalEncodedData );
Here are some motherfucking references:

http://www.w3.org/TR/XMLHttpRequest/
https://developer.mozilla.org/en/AJAX/Getting_Started (note: XHR support was added in IE7, the first section lies)
https://developer.mozilla.org/en/using_xmlhttprequest
http://en.wikipedia.org/wiki/XMLHttpRequest#HTTP_request
gistfile2.md
So, you want to send a JSON-P (JSON with Padding) request. As you may see by my demeanor, I've been through some stuff. The anger's gone. Went to a therapist. Bought a house near a lake and a boat. Every day I go and shoot ducks. Fucking ducks.

JSON-P is a horrible name for a simple concept. Let's say you're the average Joe (you're probably below average, but I'm sure you're a special snowflake) and you want to use a JSON API from the browser. So you send an XHR (you know how to do that from the above file). And then you get an error:

XMLHttpRequest cannot load http://slumdogapis.com/porn/search?q=naked. Origin http://my.awesome.site.com is not allowed by Access-Control-Allow-Origin.
Shit. You just met the Same-Origin policy (wikipedia, w3c, mdn). It means "sorry dawg, no access for you". The rationale behind it is explained in the articles presented.

Seeing as how that isn't going to go away and people wanted JSON data from other sites, someone (portrayed here as a stoned man from the 60s) came up and said "Hey man, since JSON is just, like, javascript, why can't we just, like, wrap it in a callback, and like inject a script there?" And thus JSON-P was born.

Before we begin, I'd like to make a very important note. JSON-P relies on the server to add a callback. Therefore, if the server does not provide a JSON-P api, you can't do anything about it.

The stoner explained it neatly. The server wraps the JSON with a function call, like this:

foo({"searchResults":["slumdognaked.jpg", "slumdogMoreNaked.jpg.exe"]});
We then create a script element, and inject it into the page:

//create a script element...
var script = document.createElement('script');
///...direct it to our desired target...
script.src = 'http://slumdogapis.com/porn/search?q=naked';
//...and inject it into the DOM
document.head.appendChild(script); //or document.body, or whatever
And voila, the data is fetched, and foo is called. Of course, in reality, it's not foo, and you can set your own callback by passing a GET parameter (remember those?), the key usually being callback or jsonp (check the documentation of whatever you're using):

var script = document.createElement('script');
script.src = 'http://slumdogapis.com/porn/search?q=naked&callback=my_awesome_global_function';
document.head.appendChild(script);
And now for the other obvious thing. Global functions are bad and this way is stupid. That's why libraries generate a unique function each time you do a json-p request (which is...you know, just a GET to a script), call your function later when that unique function is called, and clean up after them. Here's how I usually do it:

function jsonp (url, cb) {
    var uniqueName;

    do {
        //Math.floor is to ensure we don't get fractions or 0
        uniqueName = 'callback' + Math.floor(Date.now() * Math.random());
    } while (window[uniqueName]);

    window[uniqueName] = function () {
        //cleanup on aisle awesome
        script.parentNode.removeChild(script); //so we don't pollute the DOM
        delete window[uniqueName]; //so we don't pollute the global scope (see comment below regarding IE8-)

        //FIRE ZEH MISSILES
        cb.apply(this, arguments);
    };

    //ensure we have the GET arguments prefix
    if (url.indexOf('?') < 0) {
        url += '?';
    }
    url += '&callback=' + uniqueName;

    var script = document.createElement('script');
    script.src = url;

    //thar she blows!
    document.head.appendChild(script);
}
And its usage:

jsonp('http://slumdogapis.com/porn/search?q=naked', callback_function);
Of course, the solution is not entirely comprehensive. We don't, for instance, accept data as a parameter and make it fit for urls. But this goes beyond the scope of this humble tutorial.

I'm off to shoot some ducks. Fucking ducks.

Comment for above code: Regarding delete window[uniqueName] misbehaves in IE8 and below. If you care for these browsers, you can window[uniqueName] = null or just leave it be.

http://en.wikipedia.org/wiki/JSONP
https://github.com/Zirak/SO-ChatBot/blob/master/source/IO.js#L279 what I actually do. Relies on IO.urlstringify.
