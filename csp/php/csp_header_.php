<?php

  /**
   * @author Dave LaRonde
   * @author Lucas Larson
   * @link   https://gist.github.com/phpdave/24d879514e7411047267
   */

  // Content Security Protocol (CSP) works only in modern browsers Chrome ≥25,
  // Firefox ≥23, Safari ≥7
  $headerCSP = "Content-Security-Policy: "

               . // XMLHttpRequest (AJAX request), WebSocket, or EventSource
               "connect-src 'self' *.google-analytics.com *.doubleclick.net;"

               . // default policy for loading HTML elements
               "default-src 'self' *.example.com *.google-analytics.com *.googletagmanager.com googletagmanager.com *.google.com;"

               . // allow parent framing – this one blocks clickjacking and
                 // UI redress
               "frame-ancestors 'self';"

               . // valid sources for frames
               "frame-src 'self'"

               . // valid src domains for media via HTML audio and
                 // video elements
               "media-src 'self' *.example.com;"

               . // valid src domains for object, embed, and applet elements
               "object-src 'none';"

               . // a URL that will get raw JSON data in post that lets you
                 // know what was violated and blocked
                 // sign up for your own at report-uri.com
                 // hat tip Matt Ferderer https://dev.to/mattferderer/what-is-csp-why--how-to-add-it-to-your-website-28df
               "report-uri https://example.report-uri.com/r/d/csp/reportOnly;"

               . // report-to, which is deprecating report-uri
               "Report-To: {'group':'default','max_age':31536000,'endpoints':[{'url':'https://example.report-uri.com/a/d/g'}],'include_subdomains':true};"

               . // The Network Error Logging (NEL) spec defines a mechanism for collecting client-side network errors from an origin
               "NEL: {'report_to':'default','max_age':31536000,'include_subdomains':true};"

               . // allows JavaScript from self, jQuery and Google Analytics;
                 // inline allows inline JavaScript
               "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.example.com *.jquery.com *.google-analytics.com *.googletagmanager.com;"

               . // allows CSS from self and inline allows inline CSS
               "style-src 'self' 'unsafe-inline' *.example.com *.cloudflare.com *.jsdelivr.net *.googleapis.com;"

               . // allows fonts from self and jsdelivr.net for Computer Modern!
               "font-src 'self' 'unsafe-inline' *.example.com *.jsdelivr.net;";


  // Sends the header in the HTTP response to instruct the browser how it
  // should handle content and what is whitelisted. It’s up to the browser to
  // follow the policy which each browser has varying support
  // $contentSecurityPolicy → $headerCSP via @hobbyman https://git.io/fjtmU
  header($headerCSP);


  // X-Frame-Options was never officially created – its X- prefix indicates
  // it’s non-standard – but most browsers support it to block iframing
  header('X-Frame-Options: SAMEORIGIN');
