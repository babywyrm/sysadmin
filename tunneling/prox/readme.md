

##
#
https://github.com/drk1wi/Modlishka
#
https://github.com/kgretzky/evilginx2
#
##

# ..Modlishka..

Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow, which allows to transparently proxy multi-domain destination traffic, both TLS and non-TLS, over a single domain, without a requirement of installing any additional certificate on the client. What does this exactly mean? In short, it simply has a lot of potential, that can be used in many use case scenarios...

From the security perspective, Modlishka can be currently used to:
-	 Support ethical phishing penetration tests with a transparent and automated reverse proxy component that has a universal 2FA “bypass” support.
-  Automatically poison HTTP 301 browsers cache and permanently hijack non-TLS URLS.
-  Diagnose and hijack browser-based applications HTTP traffic from the "Client Domain Hooking" attack perspective.
-  Wrap legacy websites with TLS layer, confuse crawler bots and automated scanners, etc.


Modlishka was written as an attempt overcome standard reverse proxy limitations and as a personal challenge to see what is possible with sufficient motivation and a bit of extra research time. 
The achieved results appeared to be very interesting and the tool was initially released and later updated with aim to:
- Highlight currently used two factor authentication ([2FA](https://blog.duszynski.eu/phishing-ng-bypassing-2fa-with-modlishka/)) scheme weaknesses, so adequate security solutions can be created and implemented by the industry.
- Support other projects that could benefit from a universal and transparent reverse proxy.
- Raise community awareness about modern phishing techniques and strategies and support penetration testers in their daily work.


Modlishka was primarily written for security related tasks. Nevertheless, it can be helpful in other, non-security related, usage scenarios.

Efficient proxying !

Features
--------

Some of the most important 'Modlishka' features :

**General:**
-   Point-and-click HTTP and HTTPS reverse proxying of an arbitrary domain/s.
-   Full control of "cross" origin TLS traffic flow from your users browsers (without a requirement of installing any additional certificate on the client).
-   Easy and fast configuration through command line options and JSON configuration files.
-   Pattern based JavaScript payload injection.
-   Wrapping websites with an extra "security": TLS wrapping, authentication, relevant security headers, etc. 
-   Striping websites from all encryption and security headers (back to 90's MITM style). 
-   Stateless design. Can be scaled up easily to handle an arbitrary amount of traffic  - e.g. through a DNS load balancer.
-   Can be extended easily with your ideas through modular plugins.
-   Automatic test TLS certificate generation plugin for the proxy domain (requires a self-signed CA certificate)
-   Written in Go, so it works basically on all platforms and architectures: Windows, OSX, Linux, BSD supported...

**Security related:**
-  Support for majority of 2FA authentication schemes (out of the box).
-   Practical implementation of the "[Client Domain Hooking](https://blog.duszynski.eu/client-domain-hooking-in-practice/)" attack. Supported with a diagnostic plugin.
-  User credential harvesting (with context based on URL parameter passed identifiers).
-  Web panel plugin with a summary of automatically collected credentials and one-click user session impersonation module (proof-of-concept/beta).
-  No website templates (just point Modlishka to the target domain - in most cases, it will be handled automatically without any additional manual configuration).


Proxying In Action (2FA bypass)
------
_"A picture is worth a thousand words":_

Modlishka in action against an example two factor authentication scheme (SMS based bypass proof-of-concept)  :

[https://vimeo.com/308709275](https://vimeo.com/308709275)

Installation
------------

Latest source code version can be fetched from [here](https://github.com/drk1wi/modlishka/zipball/master) (zip) or [here](https://github.com/drk1wi/modlishka/tarball/master) (tar).



Fetch the code with _'go install'_ :

    $ go install github.com/drk1wi/Modlishka@latest

Compile manually:

    $ git clone https://github.com/drk1wi/Modlishka.git
    $ cd Modlishka
    $ make
    
------

![alt text](https://github.com/drk1wi/assets/raw/master/0876a672f771046e833f2242f6be5d3cf01519efdbb9dad0e1ed2d33e33fecbc.png)

    # ./dist/proxy -h
  
    
    Usage of ./dist/proxy:
          
      -cert string
        	base64 encoded TLS certificate
      
      -certKey string
        	base64 encoded TLS certificate key
      
      -certPool string
        	base64 encoded Certification Authority certificate
      
      -config string
        	JSON configuration file. Convenient instead of using command line switches.
          
      -controlCreds string
          Username and password to protect the credentials page.  user:pass format
          
      -controlURL string
          URL to view captured credentials and settings. (default "SayHello2Modlishka")
          
      -credParams string
          	Credential regexp with matching groups. e.g. : base64(username_regex),base64(password_regex)

      -debug
        	Print debug information
      
      -disableSecurity
        	Disable proxy security features like anti-SSRF. 'Here be dragons' - disable at your own risk.
      
      -dynamicMode
          	Enable dynamic mode for 'Client Domain Hooking'
      
      -forceHTTP
         	Strip all TLS from the traffic and proxy through HTTP only
    
      -forceHTTPS
         	Strip all clear-text from the traffic and proxy through HTTPS only
     
      -jsRules string
        	Comma separated list of URL patterns and JS base64 encoded payloads that will be injected - e.g.: target.tld:base64(alert(1)),..,etc
      
      -listeningAddress string
        	Listening address - e.g.: 0.0.0.0  (default "127.0.0.1")
      
      -log string
        	Local file to which fetched requests will be written (appended)
      
      -plugins string
        	Comma seperated list of enabled plugin names (default "all")
      
      -proxyAddress string
    	    Proxy that should be used (socks/https/http) - e.g.: http://127.0.0.1:8080 
         
      -proxyDomain string
        	Proxy domain name that will be used - e.g.: proxy.tld
      
      -postOnly
        	Log only HTTP POST requests
      
      -rules string
          	Comma separated list of 'string' patterns and their replacements - e.g.: base64(new):base64(old),base64(newer):base64(older)

      -target string
        	Target domain name  - e.g.: target.tld
         
      -targetRes string
        	Comma separated list of domains that were not translated automatically. Use this to force domain translation - e.g.: static.target.tld 
      
      -terminateTriggers string
        	Session termination: Comma separated list of URLs from target's origin which will trigger session termination
        		
      -terminateUrl string
        	URL to which a client will be redirected after Session Termination rules trigger
      
      -trackingCookie string
        	Name of the HTTP cookie used to track the client (default "id")
      
      -trackingParam string
        	Name of the HTTP parameter used to track the client (default "id")




References
-----

 * [WIKI](https://github.com/drk1wi/Modlishka/wiki) pages:  with more details about the tool usage and configuration.
 * [FAQ](https://github.com/drk1wi/Modlishka/wiki/FAQ)

 Blog posts:
 *  ["Modlishka introduction"](https://blog.duszynski.eu/phishing-ng-bypassing-2fa-with-modlishka/) "Bypassing standard 2FA mechanism proof-of-concept" blog post.
 * "[Hijacking browser TLS traffic through Client Domain Hooking](https://blog.duszynski.eu/hijacking-browser-tls-traffic-through-client-domain-hooking/)" technical paper - in case you are interested about the approach that is used to handle the traffic.

License
-------
Author: Modlishka was designed and implemented by Piotr Duszyński ([@drk1wi](https://twitter.com/drk1wi)) (this includes the technique described in the "Client Domain Hooking" paper) . You can find the relevant license [here](https://github.com/drk1wi/Modlishka/blob/master/LICENSE). All rights reserved.

The initial version of the tool was written as part of a bigger project that was dissolved and assets were distributed accordingly. 

Credits 
-------
Big kudos go to all [contributors](https://github.com/drk1wi/Modlishka/graphs/contributors) 💪!

Kudos for helping with the final code optimization and great support go to Giuseppe Trotta ([@Giutro](https://twitter.com/giutro)). 

Disclaimer
----------



<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# Evilginx 3.0

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This tool is a successor to [Evilginx](https://github.com/kgretzky/evilginx), released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website.
Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

<p align="center">
  <img alt="Screenshot" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/screen.png" height="320" />
</p>

## Disclaimer

I am very much aware that Evilginx can be used for nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration and find ways to protect their users against this type of phishing attacks. Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

## Evilginx Mastery Training Course

If you want everything about reverse proxy phishing with **Evilginx** - check out my [Evilginx Mastery](https://academy.breakdev.org/evilginx-mastery) course!

<p align="center">
  <a href="https://academy.breakdev.org/evilginx-mastery"><img alt="Evilginx Mastery" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx_mastery.jpg" height="320" /></a>
</p>

Learn everything about the latest methods of phishing, using reverse proxying to bypass Multi-Factor Authentication. Learn to think like an attacker, during your red team engagements, and become the master of phishing with Evilginx.

Grab it here:
https://academy.breakdev.org/evilginx-mastery

## Write-ups

If you want to learn more about reverse proxy phishing, I've published extensive blog posts about **Evilginx** here:

[Evilginx 2.0 - Release](https://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens)

[Evilginx 2.1 - First Update](https://breakdev.org/evilginx-2-1-the-first-post-release-update/)

[Evilginx 2.2 - Jolly Winter Update](https://breakdev.org/evilginx-2-2-jolly-winter-update/)

[Evilginx 2.3 - Phisherman's Dream](https://breakdev.org/evilginx-2-3-phishermans-dream/)

[Evilginx 2.4 - Gone Phishing](https://breakdev.org/evilginx-2-4-gone-phishing/)

[Evilginx 3.0](https://breakdev.org/evilginx-3-0-evilginx-mastery/)

## Help

In case you want to learn how to install and use **Evilginx**, please refer to online documentation available at:

https://help.evilginx.com

## Support

I DO NOT offer support for providing or creating phishlets. I will also NOT help you with creation of your own phishlets. Please look for ready-to-use phishlets, provided by other people.

## License

**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.

This tool is made only for educational purposes and can be used in legitimate penetration tests or research only. Author does not take any responsibility for any actions taken by its users.

