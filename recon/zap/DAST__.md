
##
#
https://behradtaher.dev/2022/01/19/Automating-DAST-With-ZAP/#Automating-authentication-using-Mozilla-Zest-scripting-engine
#
https://github.com/zaproxy/community-scripts/tree/main/httpsender
#
##

Automating DAST Scanning with OWASP ZAP
Author: Behrad Taher Date: January 19, 2022  0:55:45

Tux, the Linux mascot

OWASP ZAP is an open source Dynamic Application Security Testing tool. DAST tools are an integral part of application security testing as they allow for automating detection of vulnerabilities in a web application by simulating attacks and analyzing responses from an application. This includes crawling the application to discover endpoints and fuzzing parameters to find sinks that can potentially accept unsanitized input as well as identifying low hanging fruit such as lack of secure cookies or CSP headers. With a rich feature set and highly configurable scan options ZAP is an excellent choice which in my opinion offers more than many paid DAST solutions.

Some of the key benefits to OWASP ZAP:

    Free/Open source
    Updated regularly
    Docker image available for easy automation into CI/CD pipelines
    Robust scripting support in multiple formats
    Dual functioning GUI and CLI options which make configuring a scan and then automating it simple
    Broad support for common authentication and session management methods
    Multiple reporting formats supported (HTML,mrkdwn,JSON)
    Integrated browser for manual crawling/scanning
    Integrated proxy to intercept and modify HTTP requests
    Easy to use wrapper scripts in Python to easily run scans via CLI or container

In this post I’ll cover some of the basics of configuring an authenticated scan as well as some of the more advanced features such as global variables and custom scripting which in my experience can be hard to find proper documentation on. I’ll also include a script I created to output a formatted results report into a slack webhook.
Intro to the GUI

While the goal of this post is to describe using ZAP in an automated fashion, one important piece of advice I would recommend to anyone is to get familiar with the GUI. More often than not you WILL run into errors using the CLI and the best way to debug them is to run the identical scan config through the GUI where you have much more detail into what’s happening.
Tux, the Linux mascot
Manually exploring our application through the ZAP integrated browser
Configuring scan parameters within a context

In ZAP the specific configuration for one application is stored in what’s called a ‘context’. This includes everything from URL whitelist/blacklist, authentication and session management methods, authorization triggers, user parameters, and specific scan settings such as the technology being tested and the vulnerabilities to check for.

The key benefit to this is we can configure the context in the GUI which makes it easy to test, and export it as an XML file to be used with the ZAP CLI.

To create a new context, from the sites tree on the left tab, right click the URL for your app and select Include in Context -> New Context

This will open the contexts menu and from here we can set a few useful configurations:

    Technology: I’ll disable the checks for certain languages, databases, and web servers which my application doesn’t use, this will reduce unneccesary scanning.
    Session Management: ZAP offers 3 forms of session management to ensure authenticated scans remain logged in, for my application a session ID is used so I’ll select Cookie-based Session Management and ZAP will automatically send the dynamic session ID with each request
    Authorization: For ZAP to better understand how your application works we can use an HTTP Status Code such as 403 or even regex filter the HTTP headers to identify when a request is unauthorized

Automating authentication using Mozilla Zest scripting engine

While ZAP does include common authentication methods such as form-based and json-based auth, many times more modern web apps will require a more complex set of HTTP requests or redirects which will require some additional customization.

To address the issue of complicated auth patterns, one of the most useful features to ZAP is the scripting engine. I’ll demonstrate how we can record a login sequence and automatically convert that into a Mozilla Zest script.
Tux, the Linux mascot
To create a Zest script select the icon in the top left of the ‘Scripts’ tab*

We’ll use the default authentication template and parameterize it so the same script can be used against alternate users or URLs:

Tux, the Linux mascot

Finally to record the login sequence right click the script and select Start Recording then you can manually perform the login sequence from the ZAP integrated browser:

Tux, the Linux mascot

To test the authentication script, there’s a Run button available in the Script Console tab, it will check assertions such as response size and HTTP status codes to determine if the login sequence was successful.

Now we can add this authentication script to our context to set it as the default authentication mechanism for any scans related to this application:

Tux, the Linux mascot

Additionally in the above screenshot you can see I set 2 regex patterns to identify Logged In and Logged Out messages. This will assist ZAP by letting it know if the user is authenticated, and if not to re-authenticate them.

One more thing we need to do is enable Forced User Mode in the GUI this is done by clicking the lock emoji on the top toolbar.
Running authenticated scans through the GUI

ZAP Spider:
Now that the authentication and user is configured we can right click the context to run an active scan or crawl the application with the Spider or Ajax Spider tools:
Spider Results
Starting off by crawling the site with the Spider to populate the list of endpoints

Active Scan:

The Active Scan is the in depth DAST vulnerability scan that ZAP provides.

We can run an active scan by right clicking the URL in the site tree. For this application and other similar Django apps I’ve tested this scan takes roughly 20 minutes.

There’s multiple configuration options/filters you can modify to either speed up or slow down an active scan but for the purpose of this article we’ll use the default settings.
Tux, the Linux mascot
This tab displays all of the requests sent during an active scan
Running it all through Docker with zap-full-scan.py

At this point we’ve successfully created a context for our web application and an authentication script which is working in all of the scans we’ve tested in the GUI - now we can test this using the ZAP docker container.

First we need to export the .context file and the auth.zst script as we will be mounting them to the ZAP container.

There are several ways to run ZAP through Docker, the easiest being the pre-packaged python scripts provided in the ZAP container to run the common scans. For this demo we’ll be using the zap-full-scan.py script. This is essentially a python script that acts as a wrapper around the zap.sh script.

1
2
3

	

docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py \
-t http://targeturl  -j -d -n demo.context -U admin \
-z "-config script.scripts(0).name=login.zst -config script.scripts(0).engine='Mozilla Zest' -config script.scripts(0).type=authentication -config script.scripts(0).enabled=true -config script.scripts(0).file=/zap/wrk/auth.zst" -J zap_results.json

Let’s break down what the above command is doing:
$(pwd):/zap/wrk/:rw: Mounts the current directory to the /zap/wrk/ directory of the zap container
-j: Runs the ajax spider in addition to the traditional spider to populate the URL endpoints of the app prior to any scans
-d: Displays debugging information in the output
-n demo.context: Passes in our custom context file, which includes things like the authentication method, app technology stack, URL endpoints etc
-U admin@gmail.com: Provides the user to scan with. This user must also be included in the context file.
-z: ZAP command line options. These are any other configuration options the ZAP API can receive. Example format: “-config aaa=bbb -config ccc=ddd”

    The following parameter passes in our auth.zst script:
    -config script.scripts(0).type=authentication -config script.scripts(0).enabled=true -config script.scripts(0).file=/zap/wrk/login.zst
    If we needed to load another script we would reference it as script.scripts(1)

Generating a custom report for a Slack webhook

ZAP supports multiple reporting formats: HTML, Markdown, JSON, but for automation purposes it can be beneficial to get a summarized report in the format of an incoming Slack webhook. I wrote a simple script to parse the findings from a JSON formatted ZAP report, here’s the code if you want to implement something similar:

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27

	

f = open('zap_results.json')
data = json.load(f)
findings = data['site'][0]['alerts']
out = ""

def formatter(finding):
    code = int(finding['riskcode'])
    name = finding['name']
    count = finding['count']
    if code >= 3:
        formatted_finding = ":red_circle: " + name + " - Count: " + count
    elif code == 2:
        formatted_finding = ":large_orange_circle: " + name + " - Count: " + count
    elif code == 1:
        formatted_finding = ":large_green_circle: " + name + " - Count: " + count
    else:
        formatted_finding = ":large_blue_circle: " + name + " - Count: " + count
    return formatted_finding

for x in range(len(findings)):
    finding = formatter(findings[x])
    out = out + finding 

block = [{"type": "header","text": {"type": "plain_text","text": ":zap: New ZAP Scan Result - " + date + " :zap:" + "\n\n"}},{"type": "section","text": {"type": "mrkdwn","text": out}}]
url = "https://hooks.slack.com/{your_webhook}"
webhook = WebhookClient(url)
response = webhook.send(text="fallback",blocks=block)

slack report

The output is a consice summary that can be quickly analyzed for any new or remediated findings from a scan that’s being run on a continuous basis.
Troubleshooting issues with ZAP Docker

As mentioned earlier it’s recommended to run the scans with the -d parameter to get verbose debugging output. From this output there’s a few things we should monitor to ensure our containerized ZAP scan is running properly.

One of the easiest methods to confirm the scans are running correctly is to compare the results to the Active Scan we ran earlier in the GUI. Important artifacts to check for include:

1. Number of URLs discovered with the traditional_spider and ajax_spider
2. Number of alerts generated in the report
3. Confirm authentication was performed (and maintained) by the scan

    An easy way to confirm this is to check the web server logs for the HTTP status codes returned during the scan

