##
#
https://gist.github.com/dfkaye/da49b6c05aed48e6dfb28a2c7e87cf06
#
##

# 'safe-eval' with Worker

Before we get started&hellip;

*Prefer `script-src-elem` over `script-src` for better cross-browser support of this solution.* 

## Update, May 13, 2022

I have a variation on this solution using *embedded* workers with blob URLs at https://gist.github.com/dfkaye/14e5cc5dbe5bb38a9d80f25f54061c7f.

## The problem

You want to do this:

```
Function(`return ${expr}`)
```
    
But your `Content-Security-Policy` header prevents the main thread from running `eval()` or `Function()` by default; for example:

```
<meta
  http-equiv="Content-Security-Policy"
  content="script-src 'self' 'strict-dynamic' 'nonce-4AEemGb0xJptoIGFP3Nd';"
>
```
    
Notably, the `script-src` policy does *not* contain 'unsafe-eval' &mdash; in effect, your site does not trust *any* code, whether yours or a third party's, to evaluate code safely.

## The solution

1. Create a web worker (we'll define its contents in a moment) and subscribe to its `message` event:

```
var worker = new Worker("./worker.js");

worker.addEventListener('message', function(e) {
  console.info('worker completed');

  // event.data contains the stringified JSON response
  var data = JSON.parse(e.data);

  // do things in the main thread using data...
  console.log(JSON.stringify(data, null, 2));
});
```

2. Define the functionality you want inside the 'worker.js' file. The following pretends to assign a new value in `data`, specifically, `data[cellid] = value`, and then return the modified `data`, `id`, and `value`.

```
function evaluate(e) {
  console.info('worker evaluating');
  console.log(e.data);

var data = JSON.parse(e.data.data || '{}');
  var item = JSON.parse(e.data.item || '{}');
  var id = item.id;
  var value = item.value;

  // Replace cellId (A1, PP12, etc.) with data[cellid] value.
  var expr = value.substring(1).trim().replace(/[A-Z]+[\d]+/g, function(cellid) {
    var item = data[cellid] || { value: '' };
    var test = Number(item.value);

    // Quote the value if it can't be coerced to a Number.
    return test !== test ? '"' + item.value + '"' : (item.value || 0);
  });

  var computedValue = value;

  try {
    computedValue = Function(`return ${expr};`).call(null);
  } catch (e) {
    console.error({
      error: "Error evaluating " + value,
      expr,
      computedValue
    });
  }

  self.postMessage(JSON.stringify({
    id: id,
    value: computedValue
  }));
}
```

3. Subscribe to the message event inside the worker

```
self.addEventListener('message', evaluate);
```

4. Back in the main thread, create a function that calls `worker.postMesage()` &mdash; we'll assume the function uses fields from the `data` and `item` arguments, then makes that call:

```
function useWorker(data, item) {
  worker.postMessage({
    data: JSON.stringify(data),
    item: JSON.stringify(item)
  });
}
```

5. Call that function

```
var data = {};
var item = { id: "test", value: "something" };

useWorker(data, item);
```

You should see the "worker completed" message in the console along with formatted <abbr title="JavaScript Object Notation">JSON</abbr> data:

```
{
  "id": "test",
  "value": "something"
}
```

## Restrictions

1. The worker must reside in its own file - it cannot be created from a `Blob` or data schema <abbr title="Uniform Resource Identifier">URI</abbr> - more on that here &#8594; https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers#Content_security_policy.

2. Content Security Policy's `script-src` must include 'self' or 'strict-dynamic'  (recommend including both for browsers that do not support 'strict-dynamic') - more about the script-src directive here &#8594; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src

# Update <time datetime="2020-01-03">3 January 2020</time>

1. *Do __not__ use `script-src` &mdash; Use __`script-src-elem`__ for best cross-browser support.*

The `script-src` directive is not carefully supported across all browsers to enable workers launched from trusted scripts to run `eval()`.

This past week (2020 new year's) I found that only Firefox <= 71 runs `eval()` in a worker launched from code in a `script-src` directive when defined in the `<meta>` tag in the page itself.  Edge ignored it completely and ran the worker.  Chrome complained that the worker's CSP did *not* allow 'unsafe-eval'.

Moving that directive to the server and adding the response header there resulted in __ALL__ browsers failing to execute the worker.

Changing `script-src` to `script-src-elem` in both server and `<meta>` tag versions resulted in successful execution across all browsers.

2. There is also a `worker-src` directive, but&hellip;

According to this, https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/worker-src, you can specify a CSP header for worker scripts.

I had no success using this directive on server response headers or in the `<meta>` tag.

