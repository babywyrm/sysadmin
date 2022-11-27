//
//

http://www.mauvecloud.net/charsets/CharCodeFinder.html
https://hackerone.com/reports/1530898
https://medium.com/@amar.infosec4fun/xss-challenges-4c21b3ae9673
https://bishopfox.com/blog/ruby-vulnerabilities-exploits

//
//

It looks like in your scenario you are supposed to read from CSRF-TOKEN cookie. Otherwise it would be marked HttpOnly as JSESSIONID. The later means you cannot access it from the web page but merely send back to server automatically.

In general there is nothing wrong in reading CSRF token from cookies. Please check this good discussion: Why is it common to put CSRF prevention tokens in cookies?

You can read your cookie (not HttpOnly, of cause) using the following code

function getCookie(name) {
  if (!document.cookie) {
    return null;
  }

  const xsrfCookies = document.cookie.split(';')
    .map(c => c.trim())
    .filter(c => c.startsWith(name + '='));

  if (xsrfCookies.length === 0) {
    return null;
  }
  return decodeURIComponent(xsrfCookies[0].split('=')[1]);
}

So fetch call could look like

const csrfToken = getCookie('CSRF-TOKEN');

const headers = new Headers({
        'Content-Type': 'x-www-form-urlencoded',
        'X-CSRF-TOKEN': csrfToken
    });
    return this.fetcher(url, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
            email: 'test@example.com',
            password: 'password'
        })
    });
    
///
///


    See this: https://github.com/codeigniter4/CodeIgni...ssues/2454

    Basically, CSRF behavior differs when it detects an AJAX call, but `fetch` calls are indistinguishable from regular HTTP requests. You can work around this by providing the headers with your `fetch` command:

    fetch(url, {
        method: "get",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        }


Thanks MGatner! But I've no problems at all with the "get" method, fetch works as is for get. It is the post I've had a stub on. Currently, my solution is putting everything in FormData() - and that somehow makes it all work.

Code:
    let form = new FormData();

    let csrfs = document.querySelectorAll('input[name=csrf_token]');
    form.append(csrfs[0].name, csrfs[0].value);

    let pkg = JSON.stringify({
        view: "modules/cartproducts",
        products: productIds
    });
    form.append('json', pkg);


///
///



If you're using Fetch API to send a non-GET requests to a Rails controller, you may bump into the InvalidAuthenticityToken exception. It's because Rails requires a special CSRF token to validate the request, and you can pass it via X-CSRF-Token header.

Here is a working example of adding the CSRF token in the headers:

// Grab the CSRF token from the meta tag
const csrfToken = document.querySelector("[name='csrf-token']").content

fetch("/v1/articles", {
  method: "POST",
  headers: {
    "X-CSRF-Token": csrfToken, // 👈👈👈 Set the token
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ title: "awesome post" })
}).then(response => {
  if (!response.ok) { throw response; }
  return response.json()
}).then((data) => {
  console.log(data)
}).catch(error => {
  console.error("error", error)
})

In old-fashioned Rails apps, CSRF token is handled by rails-ujs transparently so there is no extra work for you.

However, if you're running Rails + React or even vanilla JavaScript where you want to fire the raw requests from the frontend, you'll need to do what the code snippet above shows: grab the CSRF token from the markup and pass it in the headers.
A note for test env

In test env, Rails won't check CSRF token for non-GET requests, and it also won't generate the meta tag for it. So you'll need to do a presence check in your JavaScript before accessing the .content. Kinda awkward. 😳

You may want to put this into a util method.
utils.js

export function getCSRFToken() {
  const csrfToken = document.querySelector("[name='csrf-token']")

  if (csrfToken) {
    return csrfToken.content
  } else {
    return null
  }
}

credentials: "same-origin"

During my quick research, all examples I found on the internet have included credentials: "same-origin" in the request parameters, e.g.

fetch("/v1/articles", {
  // method, headers, body omitted
  credentials: "same-origin"
})

According to the MDN article , the default credentials value of fetch() has been changed from omit to same-origin, so we're safe to omit it 😉:

    Since Aug 25, 2017. The spec changed the default credentials policy to same-origin. Firefox changed since 61.0b13.

Alternatives

If you find yourself doing this many times, you may want to consider a more adavanced libraries like axios or ky which supports global defaults, so that you'll only need to configure the CSRF header once.


////
//
//
//
