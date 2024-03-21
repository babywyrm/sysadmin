# htaccess

##
#
https://github.com/cavo789/htaccess/blob/master/readme.md
#
##

![banner](./banner.svg)

> Some tips and tricks for your .htaccess file (Apache)

## Table of Contents

* [Table of Contents](#table-of-contents)
  * [CSP - Content Security Policy](#csp---content-security-policy)
  * [Files](#files)
    * [Block access to some files based on their names](#block-access-to-some-files-based-on-their-names)
    * [Block access to some files based on their extensions](#block-access-to-some-files-based-on-their-extensions)
    * [Block access to hidden files & directories](#block-access-to-hidden-files--directories)
  * [Force](#force)
    * [Force download](#force-download)
      * [Prevent downloading](#prevent-downloading)
    * [Force https and www, compatible hstspreload](#force-https-and-www-compatible-hstspreload)
  * [Misc](#misc)
    * [Disable error reporting](#disable-error-reporting)
    * [Enable error reporting](#enable-error-reporting)
    * [Enable a maintenance mode](#enable-a-maintenance-mode)
  * [Optimization](#optimization)
    * [Compress files based on their type or extensions](#compress-files-based-on-their-type-or-extensions)
    * [Add expiration (expires headers)](#add-expiration-expires-headers)
  * [Protection](#protection)
    * [Deny All Access](#deny-all-access)
    * [Deny All Access except you](#deny-all-access-except-you)
    * [Stops a browser from trying to MIME-sniff](#stops-a-browser-from-trying-to-mime-sniff)
    * [Avoid Clickjacking and enable XSS-protection for browsers](#avoid-clickjacking-and-enable-xss-protection-for-browsers)
    * [Disable script execution](#disable-script-execution)
    * [Disallow listing for directories](#disallow-listing-for-directories)
    * [htpasswd](#htpasswd)
      * [File password](#file-password)
      * [Folder password](#folder-password)
    * [Whitelist - Disallow access to all files except the ones mentioned](#whitelist---disallow-access-to-all-files-except-the-ones-mentioned)
  * [Redirect](#redirect)
    * [Redirect an entire site](#redirect-an-entire-site)
    * [Permanent redirection](#permanent-redirection)
    * [Temporary redirection](#temporary-redirection)
    * [Redirect a subfolder](#redirect-a-subfolder)
  * [Search engine](#search-engine)
    * [Disallow indexing](#disallow-indexing)
* [License](#license)

### CSP - Content Security Policy

Be inspired by the following lines:

```htaccess
<IfModule mod_headers.c>

   # Add CSP (Content Security Policy)
   Header set Protected-by "What-you-want-or-just-drop-this-line"

   # Replace XXXXXXXXXXXXXX by your site name like www.yoursite.com
   Header always set Feature-Policy "camera 'none'; fullscreen 'self'; microphone 'none'; payment 'none'; sync-xhr 'self' XXXXXXXXXXXXXX"

   # Blocks a request if the requested type is
   #    "style" and the MIME type is not "text/css", or
   #    "script" and the MIME type is not a JavaScript MIME type.
   Header set X-Content-Type-Options "nosniff"

   # Prevent from Clickjacking by allowing frame to be displayed only
   # on the same origin as the page itself.
   Header always set X-Frame-Options SAMEORIGIN

   # Force HTTPS (don't use this if you're still on http)
   # env=HTTPS didn't work... but while "expr=%{HTTPS} == 'on'" is well working
   # see https://stackoverflow.com/questions/24144552/how-to-set-hsts-header-from-htaccess-only-on-https#comment81632711_24145033
   Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" "expr=%{HTTPS} == 'on'"

   # Enables XSS filtering. Rather than sanitizing the page, the browser
   # will prevent rendering of the page if an attack is detected.
   Header always set X-XSS-Protection "1; mode=block"

   # The Referrer header will be omitted entirely. No referrer information is
   # sent along with requests.
   Header always set Referrer-Policy "no-referrer"

   # CSP : define / whitelist domains where files can be loaded
   # (f.i. fonts.googleapis.com, ...)
   # This should be done for scripts, images, styles, frame, ...
   # Replace XXXXXXXXXXXXXX by your site name like https://www.yoursite.com
   # ----------------------------------------------------------------------
   # UNCOMMENT THE FOLLOWING LINE ONLY IF YOU KNOW WHAT YOU'RE DOING.
   # THIS LINE CAN BREAK YOUR SITE SO, ENABLE IT AND TEST YOUR SITE A LOT,
   # ALL PAGES IF POSSIBLE.
   # ----------------------------------------------------------------------
   #Header set Content-Security-Policy: "default-src 'self'; base-uri 'self'; form-action 'none'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://ajax.googleapis.com https://www.google.com https://www.google-analytics.com https://code.jquery.com https://www.gstatic.com https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com https://unpkg.com; font-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://fonts.googleapis.com https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com; img-src 'self' data: https://www.paypal.com https://raw.githubusercontent.com; frame-src XXXXXXXXXXXXXX https://www.google.com https://www.youtube.com; frame-ancestors 'none'"
</IfModule>
```

### Files

#### Block access to some files based on their names

Refuse requests to these files:

```htaccess
<FilesMatch "(file_1\.gif|file_2\.png)">
    Order Allow,Deny
    Deny from all
</FilesMatch>
```

#### Block access to some files based on their extensions

Blocks access to all files except those whose extension is mentioned in the list below:

**Option 1**

```htaccess
RewriteCond %{REQUEST_FILENAME} !(.*)\.(bmp|css|eot|html?|icon?|jpe?g|js|gif|pdf|png|svg|te?xt|ttf|webp|woff2?|xml|zip)$
RewriteRule . - [F]
```

**Option 2**

```htaccess
RewriteCond %{REQUEST_FILENAME} !\.(ico?n|img|gif|jpe?g|png|css|map)$ [NC]
RewriteCond %{REQUEST_FILENAME} !\.js(\?.*)?$ [NC]
RewriteCond %{REQUEST_FILENAME} !\.(eot|svg|ttf|woff2?)(\?.*)?$ [NC]
# Comment this line if you wish to make possible to access the /libraries folder by url.
RewriteRule . - [F]
```

#### Block access to hidden files & directories

Don't allow to access to a file or folder when the name start with a dot (i.e. a hidden file / folder):

```htaccess
<IfModule mod_rewrite.c>
    RewriteCond %{SCRIPT_FILENAME} -d [OR]
    RewriteCond %{SCRIPT_FILENAME} -f
    RewriteRule "(^|/)\." - [F]
</IfModule>
```

### Force

#### Force download

Don't allow the browser to download such files but tell him how to display them (text in the example):

```htaccess
<FilesMatch "\.(tex|log|aux)$">
    Header set Content-Type text/plain
</FilesMatch>
```

##### Prevent downloading

For instance, force download for pdf files:

```htaccess
<FilesMatch "\.(pdf)$">
    ForceType application/octet-stream
    Header set Content-Disposition attachment
</FilesMatch>
```

#### Force https and www, compatible hstspreload

> When implemented in your .htaccess, try to get access to `yoursite.com` or `http://yoursite.com` should redirect to `https://www.yoursite.com`.

Also, test your site with [https://hstspreload.org/](https://hstspreload.org/) to verify that your preloading is correct (green).

```htaccess
<IfModule mod_rewrite.c>

 # Rewrite the URL to force https and www.
 RewriteEngine On

 # Compliant with hstspreload.org : first redirect to https if needed
 RewriteCond %{HTTPS} !=on
 RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

 #   then redirect to www. when the prefix wasn't mentionned
 # hstspreload.org seems to not really like to make the two at once
 RewriteCond %{HTTP_HOST} !^www\.
 RewriteRule ^ https://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

</IfModule>
```

### Misc

#### Disable error reporting

Don't show errors (just like a `error_reporting=E_NONE` does)

```htaccess
<IfModule mod_php5.c>
    php_flag display_errors off
    php_flag log_errors on
    php_flag track_errors on
    php_value error_log error.log
</IfModule>
```

#### Enable error reporting

Show errors (just like a `error_reporting=E_ALL` does).

Only use this on a development server otherwise you'll expose sensitive information to your visitor.

```htaccess
<IfModule mod_php5.c>
    php_flag display_errors on
    php_flag log_errors on
    php_flag track_errors on
    php_value error_log error.log
</IfModule>
```

#### Enable a maintenance mode

Redirect every requests done to your site to a specific page (called `maintenance.php` here below). Just think to replace the code `ADD_YOUR_IP_HERE` by your current IP adress.

```htaccess
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REMOTE_ADDR} !127.0.0.1 [NC]
    RewriteCond %{REMOTE_ADDR} !localhost [NC]
    RewriteCond %{REMOTE_ADDR} !ADD_YOUR_IP_HERE [NC]
    RewriteCond %{REQUEST_FILENAME} !maintenance.php(.*)$ [NC]
    RewriteRule .* /maintenance.php [L,NC,QSA]
</IfModule>
```

### Optimization

#### Compress files based on their type or extensions

```htaccess
<IfModule mod_deflate.c>
    SetOutputFilter DEFLATE
    <IfModule mod_filter.c>
        AddOutputFilterByType DEFLATE application/font-otf application/font-ttf application/font-woff application/javascript application/json application/manifest+json application/rss+xml application/vnd.ms-fontobject application/xhtml+xml application/xml application/x-javascript image/svg+xml text/css text/csv text/html text/javascript text/plain text/xml
    </IfModule>
</IfModule>

# On somes hosters, mod_deflate isn't installed but well mod_gzip.
<IfModule mod_gzip.c>
    mod_gzip_on Yes
    mod_gzip_dechunk Yes
    mod_gzip_item_include file      \.(html?|txt|css|js|php|pl)$
    mod_gzip_item_include handler   ^cgi-script$
    mod_gzip_item_include mime      ^text/.*
    mod_gzip_item_include mime      ^application/font-otf
    mod_gzip_item_include mime      ^application/font-ttf
    mod_gzip_item_include mime      ^application/font-woff
    mod_gzip_item_include mime      ^application/vnd.ms-fontobject
    mod_gzip_item_include mime      ^application/x-javascript.*
    mod_gzip_item_exclude mime      ^image/.*
    mod_gzip_item_include mime      ^image/svg+xml*
    mod_gzip_item_exclude rspheader ^Content-Encoding:.*gzip.*
</IfModule>
```

#### Add expiration (expires headers)

Enable ETAGs

```htaccess
<IfModule mod_headers.c>
    # Keep the connection alive (not really related to expirations but really increase download speed
    Header set Connection keep-alive
</IfModule>

<IfModule mod_expires.c>

    ExpiresActive On

    # Default expiration: 1 hour after request
    ExpiresDefault "access plus 1 month"

    # CSS and JS expiration
    ExpiresByType text/css "access 1 month"
    ExpiresByType text/javascript "access 1 month"
    ExpiresByType application/javascript "access 1 month"
    ExpiresByType application/x-javascript "access 1 month"

    # webfonts
    ExpiresByType application/vnd.ms-fontobject "access plus 1 month"
    ExpiresByType application/x-font-woff "access 1 year"
    ExpiresByType application/x-font-woff2 "access 1 year"
    ExpiresByType font/eot "access plus 1 month"
    ExpiresByType font/truetype "access 1 year"
    ExpiresByType font/opentype "access 1 year"
    ExpiresByType font/woff "access 1 year"
    ExpiresByType image/svg+xml "access 1 year"
    ExpiresByType application/vnd.ms-fontobject "access 1 year"
    ExpiresByType application/font-otf "access 1 year"
    ExpiresByType application/font-ttf "access 1 year"
    ExpiresByType application/font-woff "access 1 year"
    ExpiresByType application/x-font-ttf "access 1 year"

    # Media
    AddType image/vnd.microsoft.icon .cur
    ExpiresByType application/ico "access 1 year"
    ExpiresByType audio/ogg "access plus 1 month"
    ExpiresByType image/bmp "access plus 1 month"
    ExpiresByType image/gif "access 1 month"
    ExpiresByType image/ico "access 1 year"
    ExpiresByType image/icon "access 1 year"
    ExpiresByType image/jpg "access 1 month"
    ExpiresByType image/jpeg "access 1 month"
    ExpiresByType image/png "access 1 month"
    ExpiresByType image/svg+xml "access 1 month"
    ExpiresByType image/vnd.microsoft.icon "access 1 year"
    ExpiresByType image/webp "access 1 month"
    ExpiresByType image/x-icon "access 1 year"
    ExpiresByType text/ico "access 1 year"
    ExpiresByType video/mp4 "access plus 1 month"
    ExpiresByType video/ogg "access plus 1 month"
    ExpiresByType video/webm "access plus 1 month"

    # Flash
    ExpiresByType application/x-shockwave-flash "access plus 2 months"
    ExpiresByType image/swf "access plus 2592000 seconds"

    # Files
    ExpiresByType application/pdf "access 1 week"
    ExpiresByType application/x-gzip "access 1 month"
    ExpiresByType text/x-component "access 1 month"

    # Data
    ExpiresByType application/atom+xml "access plus 1 hour"
    ExpiresByType application/rdf+xml "access plus 1 hour"
    ExpiresByType application/rss+xml "access plus 1 hour"
    ExpiresByType text/html "access plus 0 seconds"
    ExpiresByType application/json "access plus 0 seconds"
    ExpiresByType application/ld+json  "access plus 0 seconds"
    ExpiresByType application/schema+json "access plus 0 seconds"
    ExpiresByType application/vnd.geo+json "access plus 0 seconds"
    ExpiresByType application/xml "access plus 0 seconds"
    ExpiresByType text/xml "access plus 0 seconds"
</IfModule>

# Perhaps the MIME type of SWF is incorrect, in this case, the FileMatch will do the job
<IfModule mod_headers.c>
    <FilesMatch "\.(swf)$">
        Header set Expires "access plus 2592000 seconds"
    </FilesMatch>
</IfModule>
```

### Protection

#### Deny All Access

```htaccess
## Apache 2.2
Deny from all

## Apache 2.4
# Require all denied
```

#### Deny All Access except you

Just replace `xxx.xxx.xxx.xxx` by your IP adress.

```htaccess
## Apache 2.2
Order deny,allow
Deny from all
Allow from xxx.xxx.xxx.xxx

## Apache 2.4
# Require all denied
# Require ip xxx.xxx.xxx.xxx
```

#### Stops a browser from trying to MIME-sniff

```htaccess
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
```

#### Avoid Clickjacking and enable XSS-protection for browsers

```htaccess
<FilesMatch "\.(pl|php|cgi|spl)$">
    <IfModule mod_headers.c>
        # security
        Header set X-Frame-Options "DENY"
        Header set X-XSS-Protection "1; mode=block"
    </IfModule>
</FilesMatch>
```

#### Disable script execution

Put these lines in f.i. `/tmp/.htaccess` to prevent execution of scripts in the `/tmp` folder.

```htaccess
# secure directory by disabling script execution
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
Options -ExecCGI

##Deny access to all CGI, Perl, PHP and Python
<FilesMatch "\.(asp?x|cgi|php|pl|py)$">
    Deny from all
</FilesMatch>
```

#### Disallow listing for directories

Don't allow the webserver to provide the list of files / folders like a `dir` does.

```htaccess
<IfModule mod_autoindex.c>
    Options -Indexes
</IfModule>
```

#### htpasswd

- `.htpasswd` generator : [http://aspirine.org/htpasswd.html](http://aspirine.org/htpasswd.html)

##### File password

```htaccess
AuthName "File access restriction"
AuthType Basic
AuthUserFile /home/your_account/.htpasswd

<Files "confidential.md">
Require valid-user
</Files>
```

##### Folder password

Place these lines in a file called `.htaccess` in the folder to protect (f.i. `folder_name`):

```htaccess
AuthType Basic
AuthName "This folder is protected"
AuthUserFile /home/your_account/folder_name/.htpasswd
Require valid-user
```

#### Whitelist - Disallow access to all files except the ones mentioned

```htaccess
# prevent accessing to all files excepted those mentioned (case sensitive!)

<FilesMatch "(?<!\.png|\.jpe?g|\.gif|\.svg|\.icon?)$">
# Apache 2.2
#    deny from all
# Apache 2.4
#    Require all denied
</FilesMatch>
```

### Redirect

#### Redirect an entire site

```htaccess
Redirect 301 / https://www.newsite.com/
```

#### Permanent redirection

```htaccess
RedirectPermanent /old.php http://www.yoursite.com/new.php
```

#### Temporary redirection

```htaccess
Redirect 301 /old.php http://www.yoursite.com/new.php
```

#### Redirect a subfolder

For instance, redirect `/category/apple.php` to `apple.php`

```htaccess
RedirectMatch 301 ^/category/(.*)$ /$1
```

or solve spelling issue by f.i. redirect every requests to the `fruit` folder to the plural form.

```htaccess
RedirectMatch 301 ^/fruit/(.*)$ /fruits/$1
```

Another example: redirecting URLs from `/archive/2020/...` to `/2020/...`.

```htaccess
RewriteRule ^archive/2020/(.*)$ /2020/$1 [R=301,NC,L]
```

### Search engine

#### Disallow indexing

Put these lines in f.i. `yoursite/administrator` to inform search engines that you don't allow him to index files in that folder (and sub-folders).

```htaccess
# Be sure that pages under this folder won't be indexed
<IfModule mod_headers.c>
    Header set X-Robots-Tag "noindex, nofollow"
</IfModule>
```

## License

[MIT](LICENSE)
