
##
#
https://github.com/zigoo0/JSONBee
#
https://github.com/kapytein/jsonp
#
https://github.com/camsong/fetch-jsonp
#





# JSONBee
A ready to use JSONP endpoints to help bypass content security policy of different websites.

The tool was presented during HackIT 2018 in Kiev. The presentation can be found here (not sure why format of the slides is screwed :D): https://www.slideshare.net/Hacken_Ecosystem/ebrahem-hegazy-bug-hunters-manual-for-bypassing-contentsecuritypolicy

# What is JSONBee?

The main idea behind this tool is to find the JSONP endpoint(s) that would help you bypass content security policy for your target website in an automated way. JSONBee takes an input of a url name (i.e. https://www.facebook.com), parses the CSP (Content-Security-Policy), and automatically suggest the XSS payload that would bypass the CSP. It mainly focuses on JSONP endpoints gathered during my bug bounty hunting activities, and could be used to bypass the CSP.

JSONBee relies on 3 methods to gather the JSONP endpoints:
* The repository within this project;
* Google dorks;
* Internet archive (archive.org).

The tool is not yet fully completed as I'm still adding some validations and features too. However, the repository will be hosted here so that anyone can use it till the tool is ready.

The repo contains ready-to-use payloads that can bypass CSP for Facebook.com, Google.com and more.

**Bypasing Facebook.com Content-Security policy:**

Facebook.com allows *.google.com in its CSP policy (script-src directive), thus, below payload would work like a charm to execute JavaScript on Facebook.com:
`"><script+src="https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=alert(1337)"></script>`

If you came across a website that trusts any of the domains in jsonp.txt file in its script-src directive, then pickup a payload  that matches the domain and have fun :)

# How can you help?
You are all welcome to contribute by adding links to sites that uses JSONP endpoins/callbacks to make the repo bigger and more usefull for bug hunters, pentesters, and security researchers.



# JSONP



> `<script src="https://cdn.xgqfrms.xyz/jsonp/users.json?callback=jsonpGlobalCallback"></script>` bug ❌

![image](https://user-images.githubusercontent.com/7291672/194763687-d58aa895-fdef-4689-a954-1114b6a58981.png)

> Fetch API OK ✅

Text !== JSON

```js
  /*
    err = TypeError: Failed to execute 'json' on 'Response': body stream already read at jsonp.html:40:16
    Uncaught (in promise) SyntaxError: Unexpected token 'j', "jsonpGloba"... is not valid JSON
  */
  const log = console.log;
  const app = document.querySelector(`#app`);
  log(`app =`, app);
  function jsonpGlobalCallback (arr) {
    log(`json =`, arr);
  }
  const url = `https://cdn.xgqfrms.xyz/jsonp/users.json?callback=jsonpGlobalCallback`;
  // const url = `https://cdn.xgqfrms.xyz/jsonp/users.json`;
  fetch(url, {
    // cors
  })
  .then(res => {
    log(`res =`, res);
    // read stream
    // log(`res =`, res, res.json());
    return res.text();
    // return res.json();
  })
  .then(jsonpText => {
    log(`jsonp text =`, jsonpText);
    app.innerHTML = ``;
    app.insertAdjacentHTML(`beforeend`, jsonpText);
  })
  .catch(err => {
    log(`err =`, err);
  });
```

<img width="733" alt="image" src="https://user-images.githubusercontent.com/7291672/194767188-5bb54411-9267-45e6-b9dd-935b664b7f16.png">

<img width="767" alt="image" src="https://user-images.githubusercontent.com/7291672/194767294-d2197e55-baa0-4688-a9fd-6826120856e5.png">



https://www.cnblogs.com/xgqfrms/p/13424717.html

https://www.cnblogs.com/xgqfrms/tag/JSONP/
