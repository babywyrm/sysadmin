Postman vs Insomnia comparison
------------------------------

Postman | API Development Environment [https://www.getpostman.com](https://www.getpostman.com)  
Insomnia REST Client - [https://insomnia.rest/](https://insomnia.rest/)

| Features&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Insomnia  | Postman  | Notes |
| ------------- |:--------:|:-----:| -----|
| Create and send HTTP requests |   x   |  x  |   |
| Authorization header helpers    |   x   |  x  | Can create "Authorization" header for you for different authentication schemes: Basic, Digest, OAuth, Bearer Token, HAWK, AWS  |
| Maintains responses history per request  |   x   |  -  |  Whereas Postman maintains history for sent requests, responses are not organized per request, just mixed together in a single long list. Not too useful.  |
| Manages cookies like a web browser does    |   x    |  x   | Stores cookies obtained from "Set-Cookie" response header and sends them back in subsequent requests on per-domain basis. You can also manage cookies manually   |
| Use certificates for client authentication            |   x   |   x  |    |
| Generate code snippets          |   x    |   x  |  Can generate code snippets to send HTTP requests in various languages: curl, NodeJS, C#, Python, Ruby, raw HTTP protocol  |
| View raw HTTP traffic  |  x  |   0   | Whereas both tools show and parse responses, it's hard to see the actual request being sent. Insomnia provides access to raw HTTP traffic log through UI. With Postman, it's much trickier, you need to have Postman DevTools Console opened when making request.
| UI | xx | x | Insomnia has minimalistic, cute and simple UI. Postman UI is a bit overloaded and complicated for newcomer (maybe due to a bigger number of features). |
| Environment and variables |  x |  x |  Both tools have a notion of variable, and environment as a container for variables, which can be overriden by more specific environment (e.g. dev/stage/prod overrides global environment) |
| Organization |  x  |   x  | Both tools have a notion of a workspace to isolate different projects. Postman organize requests in collections and folders, whereas Insomnia uses folders only
| Request chaining |  x  |  xxx  | Both tools can pull response data of one request and feed it into the next request. But Postman is more powerful here. You can run all requests in a collection as a whole. You can write "before" and "after" request hooks in JavaScript with arbitrary logic. You can build simple sequential workflows consisting of several requests, that share some data with each other. You can have basic conditional logic. With Insomnia, you need to run requests one by one manually, and don't have a place to inject custom logic.
| API testing. Run tests/assertions against responses | - | x | With Postman, you can write tests/assertions against responses. Collection acts an executable description of an API. You can run all requests in the collection as a whole, and see test run results. Has CLI interface to run collections (newman). Can be used to automate API testing and integrate it into CI/CD workflow. |
| API Documentation | - |  `PREMIUM` |  Postman can generate documentation, that includes request description (Markdown), examples, code snippets (in various languages). Each request can have several examples (pairs of request-response payloads). Examples can be used to refine API protocol at design phase to show how endpoint works under different conditions (200, 4xx responses) |
| Mock server endpoint | - | `PREMIUM` | Postman can create mock of a server endpoint, based on request examples. Useful after design phase finished, so you can have frontend and backend teams work in parallel. |
| Data sync | `PREMIUM` |  x |  Postman syncs your data for free, whereas with Insomnia it's out of free tier.
| Team collaboration |  `PREMIUM` | `PREMIUM` |  |
| Built-in HTTP sniffer | - | x | Postman has a built in HTTP proxy sniffer, although it's very limited. It captures only requests without responses. In fact, it's not a full-blown sniffer for inspectation purposes. Instead, you can use it to bootstrap your project from the captured real-world requests, instead of crafting them manually. Supports only HTTP traffic. For HTTPS traffic self-signed certificate is used, which triggers warning in browser. Does not work if website has HTTPS+HSTS, because in this case you cannot bypass security warning in a browser |
| Import and Export | x | x | Postman supports: RAML, WADL, Swagger, curl. Insomnia supports: Postman v2, HAR, Curl.  |
| Other | - | - | Insomnia can craft GraphQL requests. Postman can craft SOAP requests.

Premium tier
============
Insomnia: $5-$8 per user/month. Includes: syncing, team collaboration.  
Postman: $10 per user/month. Includesteam collaboration, API documentation, mock servers, API monitoring, integrations.




Run Postman collections using Newman and Python
Balasundar's photo
Balasundar
·
Dec 9, 2020
·

5 min read

Subscribe to my newsletter and never miss my upcoming articles
Play this article
Your browser does not support the audio element.

In this article we are going to run a postman collection using the Newman and send the output of the Newman command through email.

Requirements :

    Postman.
    npm.
    newman.
    Python3.

Postman

Postman is a collaboration platform for API development. Postman's features simplify each step of building an API and streamline collaboration so you can create better APIs—faster(read more).

Download and Install Postman.
Newman

Newman is a powerful command-line collection runner for Postman. It allows you to run and test a Postman collection directly from the command-line. Newman maintains feature parity with Postman and allows you to run collections the same way they are executed inside the collection runner in Postman.

Installation :

Execute the below command to install Newman into your system.

$ npm install -g newman

Offline Mode

Export Postman Collection

Follow the below steps to export the collection from postman.
Select the collection -> Right click -> Select Export -> Save the file.

postman_export_collection.png

Run newman

Now we are ready to run the collection using newman.

$ newman run path/to/collection/collection_name.postman_collection.json

options:

-e : is used to provide Postman Environment.

-g : is used to provide Postman Global Variables.

Example:

    $ newman run path/to/collection/collection_name.postman_collection.json -e path/to/environment_file/environment_name.postman_environment.json

Online Mode

Get Postman API Key :

To access our collections using Postman API first we have to the get the API Key from Postman. You can generate your Postman API Key by visiting Postman API Keys page.

postman_generated_api_key_page.png Click on "Generate API Key".

key_name.jpeg Give a name to your API key.

key.png Copy the API Key to clipboard.

We need the id of the collection in order to access it through postman API. The collection_id can be retrieved from the Postman collections API.

API URL: api.getpostman.com/collections

Add the API Key which you copied earlier in the Postman request header.

postman_api_authorization.png

Send the request. Now you can find the id of the collection in the API's response.

got_the_collection_id.png

A collection can be accessed by using the Postman Collections API.

API URL sample: api.getpostman.com/collections/collection_id

Run your collection using Newman

$ newman run 'https://api.getpostman.com/collections/collection_id?apikey=your_postman_api_key'

The both commands (online and offline) will return the same output. newman_report_terminal.png

Now we came to our primary task, Which is running the newman and send the output / test report through email using Python. Let's do that!.

import sys
import subprocess
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

num_of_inputs = len(sys.argv)
collection = sys.argv[1]
environment = None
global_vars = None

if num_of_inputs > 2:
    environment = sys.argv[2]
if num_of_inputs > 3:
    golbals = sys.argv[3]

command = "newman run "+collection
if environment:
    command += " -e "+environment
if global_vars:
    command += " -g "+global_vars

command = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output, error = command.communicate()

if error:
    email_body = "Error while running the command"
else:
    email_body = output.decode('utf-8')

sender_email = "your email address"
password = "email password"
receivers = "receiver email address" # or [list of receivers]

email_message = MIMEMultipart("alternative")
email_message["Subject"] = "API Test Report"
email_message["From"] = "Sender name"
email_message["To"] = "receiver email address"

# to send as html
html_content = MIMEText(email_body, "html")
email_message.attach(html_content)

# to send as a plain text email
text_content = MIMEText(email_body, "text")
email_message.attach(text_content)

# using gmail smtp server
context = ssl.create_default_context()
with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
    server.login(sender_email, password)
    server.sendmail(sender_email, receivers, email_message.as_string())

Run the code. lets assume the programs name as newman_report.py, collection name as sample_collection.postman_collection.json and the environment file name as sample_environment.postman_environment.json.

#without environment
$ python newman_report.py sample_collection.postman_collection.json
#or
#with environment
$ python newman_report.py sample_collection.postman_collection.json sample_environment.postman_environment.json

We made it!.

newman_test_report_email.png Schedule the execution of the program using a cron job. So that when ever the program is getting executed you will receive the test report via email.

Thanks for reading.

Please share your feedback and suggestion.

#################
##
##
