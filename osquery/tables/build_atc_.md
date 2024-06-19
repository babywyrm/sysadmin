
##
#
Automatic.  Table.  Construction.
#
https://www.kolide.com/blog/how-to-build-custom-osquery-tables-using-atc
#
https://holdmybeersecurity.com/2019/10/11/poc-monitoring-user-browser-activity-with-osquery/
#
##

How to Build Custom Osquery Tables Using ATC
Use ATC to search files downloaded across your Macs
Fritz Ifert-Miller

In this tutorial, we’ll break down how you can use osquery’s ATC feature to expand osquery’s data collection capabilities. As an example, we will look into how to tap into macOS’ quarantine events database to search files to help locate malware a user may have downloaded from a web browser. But before we dig into the details, let’s start at the beginning.
What Is an ATC table?

ATC (automatic table construction) is a method which can expose the contents of local SQLite database file as an osquery virtual table.

ATC was added to osquery by Mitchell Grenier (obelisk) in response to a number of virtual table pull requests which all functioned by parsing SQLite databases. Rather than approving each table as a separate pull request, Mitchell took the opportunity to add a native SQLite parsing method to osquery, which would allow adding any number of new virtual tables on a customizable basis.

An illustration showing someone making a physical table with the osquery logo inlaid into the surface with the SQLite logo laying on top
Why Is Parsing SQLite DBs Useful?

Many applications use SQLite databases as a storage method for application data, including things like:

    Google Chrome Browser History

    1Password Vault Sync Configuration

    Skype Call History

    iMessage Chat History

    macOS Quarantine Events (System-wide Download History)

As these examples illustrate, while application databases can provide tremendous utility, they also represent a potential concern for user privacy (a core tenet of osquery’s security philosophy). There are times however, where the introspection of databases can be invaluable to an Incident Response team in their forensics gathering (eg. the aforementioned Quarantine Events database).

While you may be concerned by the privacy implications of reading databases containing PII, you can take some solace in the fact that ATC tables must be declared at a configuration level in osquery and are not as simple as:

SELECT * FROM atc_table WHERE path = '/foo/bar.db'

Let’s examine a real life scenario in which ATC tables could be utilized to expand the data collection capabilities of osquery.
Searching the macOS Download History Using ATC:

“My computer was infected with malware, but don’t worry I cleaned it up.”

There are few things more frustrating to an incidence response team than the needless deletion of evidentiary findings. Discovering the active presence of malware on a device is of the highest concern. However, it is equally vital to know about the past-presence of malware and its respective source of origin (eg. an installer download link sent via email).

Yet, combing through various download history files is no one’s idea of fun, and not all applications keep a record.

You might be surprised to learn however, that if you are using an Apple computer, a record of every file you’ve ever downloaded exists on your device. No matter whether it was downloaded in Safari, Chrome, Mail.app, AirDrop, or any other 3rd party application, it’s right there all in one convenient location:

~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

A screenshot of a window for DB browser for SQLite

Files downloaded from external sources are embedded with metadata exposing their source of origin and the timestamp of when they were downloaded. The historical record of this embedded metadata is subsequently kept in the aforementioned database QuarantineEvents.

You can inspect this metadata on an individual file within Finder by right-clicking on an item in your Downloads folder and clicking Get Info:

a screenshot of a download of an ubuntu .iso file

What’s more, this metadata, including the Where From, is cached by macOS Spotlight and can be queried against using osquery as in the following example:

SELECT
  f.path,
  f.size,
  datetime(f.btime, 'unixepoch') AS file_created
FROM file f
JOIN mdfind ON mdfind.path = f.path
 AND mdfind.query = "kMDItemWhereFroms = '*ubuntu.com*'"

path = /Users/fritz-imac/Downloads/ubuntu-18.04.1-desktop-amd64.iso
size = 1953349632
file_created = 2018-10-05 13:25:09

Conceivably, we could get a list of all downloaded files on a device by querying the mdfind table for any file where kMDItemWhereFroms is not blank, however, this would only expose files which were still present on disk.

The real beauty of QuarantineEvents is the ability to introspect the historical record of downloads. Unfortunately, there isn’t a quarantine_events table in vanilla osquery… but using a custom ATC configuration, there can be!
Quarantine Events ATC Table Configuration

The basic anatomy of the config block is pretty self explanatory, but we will still break it down for the sake of being thorough:

a screenshot of an atc table configuration

So what does that look like in practice?

Using the example of QuarantineEvents let’s examine a sample osquery configuration file which you can try at home:

{
    "auto_table_construction" : {
        "quarantine_items" : {
          "query" : "SELECT LSQuarantineEventIdentifier as id, LSQuarantineAgentName as agent_name, LSQuarantineAgentBundleIdentifier as agent_bundle_identifier, LSQuarantineTypeNumber as type, LSQuarantineDataURLString as data_url,LSQuarantineOriginURLString as origin_url, LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_address, LSQuarantineTimeStamp as timestamp from LSQuarantineEvent",
          "path" : "/Users/%/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
          "columns" : ["id", "type", "agent_name", "agent_bundle_identifier", "timestamp", "sender_name", "sender_address", "origin_url", "data_url"]
        }
    }
}

Passing the config File to Test in Osqueryi

Because ATC tables are generated based on a configuration file, we need to pass that file to osqueryi. We can run the following command to pass a custom config and return the build process and any errors that might occur:

sudo /usr/local/bin/osqueryi --verbose --config_path**
/Users/fritz/Downloads/ATC-quarantine_items.json

Once the config file has been passed, you should be able to query the table as if it were any other virtual table in osquery (including support for tab completion). So in the case of our earlier example quarantine_items.

SELECT
  agent_name,
  origin_url,
  data_url
FROM quarantine_items
WHERE data_url LIKE '%.dmg'
LIMIT 1;

agent_name = Chrome
origin_url = https://www.hopperapp.com/download.html?
data_url = https://d2ap6ypl1xbe4k.cloudfront.net/Hopper-4.3.16-demo.dmg

And it’s as simple as that! You’ve just extended the data source capabilities of your osquery installation! Let’s go over some of the subsequent things you might want to do.
Closing the Loop: Finding Downloaded Files on Disk

SELECT mdfind.path,
  ROUND((f.size * 10e-7),2) AS size_megabytes,
  datetime(f.btime, 'unixepoch') AS file_created,
  MAX(CASE
        WHEN md.key = 'kMDItemWhereFroms'
        THEN md.value
    END) AS download_source_csv
FROM mdfind
LEFT JOIN mdls md ON mdfind.path = md.path
JOIN file f ON f.path = mdfind.path
AND mdfind.query = "kMDItemWhereFroms == '*google.com*'c"
GROUP BY  f.path;

Using the mdfind table we can procedurally return the paths of any file downloaded from the web, still on disk, by cross referencing three tables:

    mdfind (finding the path of files that have a kMDItemWhereFroms)

    extended_attributes (finding the quarantineeventid)

    quarantine_items (finding the download metadata)

The below query would return the last three items which you downloaded:

SELECT
  mdfind.path,
  f.size,
  datetime(f.btime, 'unixepoch') AS file_created,
  ea.value AS quarantine_event_id,
  (SELECT data_url from quarantine_items WHERE id = ea.value) AS
  data_url
FROM extended_attributes ea
  JOIN mdfind ON mdfind.path = ea.path
  JOIN file f ON f.path = mdfind.path
AND mdfind.query = "kMDItemWhereFroms = 'http*'"
  AND ea.key = 'quarantine_event_id'
  AND data_url != ''
GROUP BY ea.value
ORDER BY f.btime DESC
LIMIT 3;

Caveats to ATC Functionality
Properly formatting the ATC configuration blocks

It’s important to note that due to the JSON formatting of the ATC configuration block, you must adhere to certain idiosyncratic patterns. For example, you cannot include line-breaks in the content of your query section, doing so will produce the following error state:

E1207 09:36:10.862380 249753088 config.cpp:869] updateSource failed to parse config, of source: /Users/fritz/Downloads/quarantine-events.json and content: {...ATC query...}
I1207 09:36:10.862442 249753088 init.cpp:618] Error reading config: Error parsing the config JSON

Likewise, if you mistakenly declare a column that does not exist or select from a table that does not exist you will encounter a rather vague error:

I1207 09:40:43.539501 282201600 virtual_sqlite_table.cpp:111] ATC table: Could not prepare database at path: "/Users/fritz/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
W1207 09:40:43.540674 282201600 auto_constructed_tables.cpp:47] ATC Table: Error Code: 1 Could not generate data: Could not prepare database for path /Users/%/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

Double-checking that your query works in a terminal first is critical to ensuring your configuration block is going to be interpreted as you expect:

sudo sqlite3 -header  ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
"SELECT
  LSQuarantineEventIdentifier as id,
  LSQuarantineAgentName as agent_name,
  LSQuarantineAgentBundleIdentifier as agent_bundle_identifier,
  LSQuarantineTypeNumber as type,
  LSQuarantineDataURLString as data_url,
  LSQuarantineOriginURLString as origin_url,
  LSQuarantineSenderName as sender_name,
  LSQuarantineSenderAddress as sender_address,
  LSQuarantineTimeStamp as timestamp
 FROM LSQuarantineEvent;"

id|agent_name|agent_bundle_identifier|type|data_url|origin_url|sender_name|sender_address|timestamp
2B5CD5A1-C85C-4400-BEC4-469FF01B5CFC|sharingd||6|||Fritz Ifert-Miller||660060258.698253
3863CBCC-3ED5-4000-B127-9D39D5AE718C|sharingd||6|||Fritz Ifert-Miller||660060153.611904
...

Knowing our query actually returns data from the database when queried directly is invaluable!
Windows path nuances

Although ATC works with all of the platforms, you must be mindful of differences in path formatting across operating systems. Unix based systems use the /foo/bar/ convention; whereas, paths defined in your Windows ATC config will need to be formatted with double \ slashes. We use \\ to properly escape the \ character in SQLite. For example:

\\Users\\%\\AppData\\Local\\Google\\Chrome\\User Data\\%\\History

No data-typing

ATC tables do not preserve their respective datatypes when they are parsed and imported by osquery. As a result, all data is stored in the string format and must be CONVERT‘ed or CAST back to the desired datatype (eg. int, float, boolean, etc.) if you would like to interact with it as a specific type.
Sample Osquery ATC Configurations:

I’ve included a few sample configurations here which you can play with in your own osquery instance if you are so inclined.
Privacy Disclaimer:
Some of these configurations expose PII (personally identifiable information) and should only be used for proof-of-concept purposes only. As part of our honest.security philosophy, Kolide does not collect nor does it allow customizations that would enable the agent to collect any data in the examples below.
Google Chrome Login Keychain

Returns a list of all website logins performed within Google Chrome:

{
    "auto_table_construction" : {
         "chrome_login_keychain" : {
            "query" : "SELECT origin_url, action_url, username_value, password_element FROM logins",
            "path" : "/Users/%/Library/Application Support/Google/Chrome/Default/Login Data",
            "columns" : ["origin_url", "action_url", "username_value", "password_element"],
            "platform" : "darwin"
        }
    }
}

Google Chrome Browser History

Returns the browser history stored by Google Chrome

If you would like to try all of the mentioned tables for yourself and merely download the configuration file you can find it at the following Gist:

{
    "auto_table_construction" : {
        "quarantine_items" : {
          "query" : "SELECT LSQuarantineEventIdentifier as id, LSQuarantineAgentName as agent_name, LSQuarantineAgentBundleIdentifier as agent_bundle_identifier, LSQuarantineTypeNumber as type, LSQuarantineDataURLString as data_url,LSQuarantineOriginURLString as origin_url, LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_address, LSQuarantineTimeStamp as timestamp from LSQuarantineEvent",
          "path" : "/Users/%/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
          "columns" : ["id", "type", "agent_name", "agent_bundle_identifier", "timestamp", "sender_name", "sender_address", "origin_url", "data_url"]
        },
        "chrome_browser_history" : {
            "query" : "SELECT urls.id id, urls.url url, urls.title title, urls.visit_count visit_count, urls.typed_count typed_count, urls.last_visit_time last_visit_time, urls.hidden hidden, visits.visit_time visit_time, visits.from_visit from_visit, visits.visit_duration visit_duration, visits.transition transition, visit_source.source source FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id",
            "path" : "/Users/%/Library/Application Support/Google/Chrome/%/History",
            "columns" : ["path", "id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden", "visit_time", "visit_duration", "source"],
            "platform" : "darwin"
        },
        "chrome_login_keychain" : {
            "query" : "SELECT origin_url, action_url, username_value, password_element FROM logins",
            "path" : "/Users/%/Library/Application Support/Google/Chrome/Default/Login Data",
            "columns" : ["origin_url", "action_url", "username_value", "password_element"],
            "platform" : "darwin"
        }
    }
}

How Does Kolide Use ATC?

As we’ve seen in this article, ATC is an incredibly powerful feature of osquery that can be used to dramatically expand the scope of its data collection. To ensure the integrity of privacy promises, we maintain control over which ATC tables are deployed to the agent and use the feature to power our flagship features like inventory and checks.

Kolide’s product uses ATC to enable the following use cases:

    To locate two-factor backup codes downloaded via Chrome and Firefox Windows and Linux Devices
    To enumerate macOS’ permissions database in inventory
    To enumerate Windows Update history
    To verify specific settings in apps that use SQLite DB (like 1Password)

A screenshot of the TCC permissions DB collected by Kolide in the Device Inventory
Additional Reading

If you are interested in some of the other concepts presenting in this post I would strongly encourage you to read my past article:

Spotlight search across every Mac in your fleet Learn how with osquery you can use the native macOS mdfind utility to instantaneously search for the presence of files containing arbitrary strings to locate customer DB backups or other improperly stored sensitive information.

The File Table: Osquery’s Secret Weapon A primer on the capabilities and limitations of osquery’s file table, and how you can use it in conjunction with the concepts discussed in this article and the Spotlight article.

##
##


PoC: Monitoring user browser activity with Osquery

This proof-of-concept (PoC) will demonstrate how to use Osquery to monitor the browser activity of users. Not only will this PoC collect browser activity, but it will also use VirusTotal to rank each URL to detect malicious activity. In addition to VirusTotal, this PoC will utilize Rsyslog, Osquery, Kafka, Splunk, Virustotal, Python3, and Docker as a logging pipeline. Once this pipeline has been implemented, your security team will have the ability to protect your user’s from today’s most serious threats on the web.

Introduction

In this blog post, we will use Osquery to monitor the browser activity of users. Many organizations will monitor the browser activity of their users using a web proxy. However, web proxies are costly [2], they require a cert on every device for SSL termination [3], certificate pinning prevents SSL inspection [4], and a web proxy will only work when devices are on the network [5]. This proof of concept (PoC) uses open-source software, it doesn’t require a certificate on each endpoint, just Osquery, is not affected by certificate pinning, and this PoC will work on or off the network. In addition to URL collection, this PoC will use VirusTotal to enrich the logs with a ranking of the URL to detect malicious activity.
Goals

    Log user browsing activity with Osquery
    Detect malicious URLs that users are browsing too with VirusTotal
    Implement Kafka and Python together
    Deploying and creating a logging pipeline with Kafka, Rsyslog, Python, and Spunk on Docker

Assumptions

This blog post is written to be a proof of concept and not a comprehensive post. This post will NOT cover how Osquery, Kafka, Rsyslog, VirusTotal, Spunk, Homebrew for macOS, or how Docker works, therefore this post assumes you know how these technologies work. Second, this blog post contains setups and configurations that may NOT be production-ready. The “future improvements” section discusses various improvements for this implementation.
Assumptions
Background
What is Osquery?

Osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With Osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.
What are Osquery ATC tables?

ATC (automatic table construction) is a method which can expose the contents of local SQLite database file as an osquery virtual table. ATC was added to osquery by Mitchell Grenier (obelisk) in response to a number of virtual table pull requests which all functioned by parsing SQLite databases. Rather than approving each table as a separate pull request, Mitchell took the opportunity to add a native SQLite parsing method to osquery, which would allow adding any number of new virtual tables on a customizable basis.
What is Rsyslog?

Rsyslog is a rocket-fast system for log processing. It offers high-performance, great security features and a modular design. While it started as a regular syslogd, rsyslog has evolved into a kind of swiss army knife of logging, being able to accept inputs from a wide variety of sources, transform them, and output to the results to diverse destinations.

Rsyslog can deliver over one million messages per second to local destinations when limited processing is applied (based on v7, December 2013). Even with remote destinations and more elaborate processing the performance is usually considered “stunning”.
What is Kafka?

Apache Kafka is a community distributed event streaming platform capable of handling trillions of events a day. Initially conceived as a messaging queue, Kafka is based on an abstraction of a distributed commit log. Since being created and open sourced by LinkedIn in 2011, Kafka has quickly evolved from messaging queue to a full-fledged event streaming platform.
What is VirusTotal?

VirusTotal inspects items with over 70 antivirus scanners and URL/domain blacklisting services, in addition to a myriad of tools to extract signals from the studied content. Any user can select a file from their computer using their browser and send it to VirusTotal. VirusTotal offers a number of file submission methods, including the primary public web interface, desktop uploaders, browser extensions, and a programmatic API. The web interface has the highest scanning priority among the publicly available submission methods. Submissions may be scripted in any programming language using the HTTP-based public API.
What is Splunk?

Splunk is an advanced, scalable, and effective technology that indexes and searches log files stored in a system. It analyzes the machine-generated data to provide operational intelligence. The main advantage of using Splunk is that it does not need any database to store its data, as it extensively makes use of its indexes to store the data. Splunk is a software mainly used for searching, monitoring, and examining machine-generated Big Data through a web-style interface. Splunk performs capturing, indexing, and correlating the real-time data in a searchable container from which it can produce graphs, reports, alerts, dashboards, and visualizations. It aims to build machine-generated data available over an organization and is able to recognize data patterns, produce metrics, diagnose problems, and grant intelligence for business operation purposes. Splunk is a technology used for application management, security, and compliance, as well as business and web analytics.
Using Osquery ATC tables with OSqueryi
Install Osquery on MacOS

    Open a browser
    Browse to https://osquery.io/downloads/official/4.0.2
    Download the latest Osquery installer
    Install Osquery

Osqueryi and ATC table config

    curl https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/osquery-url-monitor/conf/osquery/osquery_chrome_atc_table.conf -o /tmp/osquery_chrome_atc_table.conf
    osqueryi --verbose --config_path /tmp/osquery_chrome_atc_table.conf
    SELECT * FROM chrome_history LIMIT 10;

Network/UML diagram

Install/Setup Osquery + Rsyslog on MacOS
Setup Osquery on MacOS

    curl https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/osquery-url-monitor/conf/osquery/osquery.conf -o /var/osquery/osquery.conf
    curl  https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/osquery-url-monitor/conf/osquery/osquery.flags -o /var/osquery/osquery.flags
    sudo cp /var/osquery/com.facebook.osqueryd.plist /Library/LaunchDaemons/com.facebook.osqueryd.plist
    sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist

Install/Setup Rsylog client on MacOS

    brew install rsyslog
    sudo mkdir /etc/rsyslog.d
    curl https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/osquery-url-monitor/conf/rsyslog-client/rsyslog.conf -o /usr/local/etc/rsyslog.conf
    curl https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/osquery-url-monitor/conf/rsyslog-client/30-output-osquery-to-rsyslog.conf -o /etc/rsyslog.d/30-osquery.conf
        sed -i 's#Target="rsyslog.hackinglab.local"#Target="<FQDN/IP addr of Rsyslog server on Docker server>"#g' /etc/rsyslog.d/30-osquery.conf
    sudo brew services start rsyslog

Setup/Deploy Kafka + Rsyslog + Python client + Splunk on Docker
Obtain VirusTotal API key

    Browse to https://www.virustotal.com/#/home/upload and create an account
    Login into your new account
    Select your profile icon in the top right then select “Settings”
    Select “API key” on the left
        Copy this API key for the next section

Configure Python client

    git clone https://github.com/CptOfEvilMinions/BlogProjects
    cd osquery-url-monitor
    cd app
    mv config/config.ini.example config/config.ini
    vim config/config.ini
    and set:
        vti_api_key
            Paste VirusTotal key from above here
        Save and exit

Deploy Docker stack

    docker-compose up -d
    docker stats

Setup Splunk to ingest logs

    Once Splunk has initialized
    Open a browser to http://<Docker IP address>:8000
    Enter login credentials
        Username: admin
        Password: changeme
    Select “Settings” in the top right then “Data inputs”
    Select “UDP” type under “Local inputs”
    Select “New Local UDP” in the top right
        Select source
            Select “UDP” for protocol
            Enter “1514” into port
        Input settings
            Select “_json” for the source type
            Select “Search and reporting” for “App context”
            Select “IP” for host method
            Under the index section select “Create a new index”
                Enter “osquery” for Index name
                Select “Save”
            Select your newly created index “Osquery” for index
        Review
            Review the settings

Testing setup

    Back to macOS client
    Open the Google Chrome browser
    Browse to https://www.mozilla.org/en-US/firefox/new

Final thoughts/Future improvements
Osquery is detection, not prevention

This proof of concept (PoC) only monitors what URLs users visit with Google Chrome. In addition to monitoring URLs, this PoC is not realtime monitoring because the query used to obtain the user’s browser activity will always be X amount of time after the user accessing the URL. Our configuration scans the user’s browser activity every 10 seconds but in an enterprise environment, this setting is not recommended, and we recommend every 15 minutes. Lastly, if a user browses to https://malware.com, this PoC will not block the user from accessing this website. We recommend using the APIs of your network firewalls to block any current connections to that IP address and any future connections to that IP address. Lastly, you can obtain the domain from the URL and sink-hole the domain so all future connections are unsuccessful.
URL whitelisting

This PoC submits every URL that a user browses too. Not only is this approach wasteful on the VirusTotal API count, but it also leaks internal URLs that users may browse. It is our recommendation to create whitelists for internal URLs/domains. In addition to a whitelist, we also recommend using Alexa’s top million to further reduce wasteful API calls for URLs that include google.com
No visibility with incognito mode or curl

Chrome does not keep track of URLs when using incognito mode. This means that a user can use incognito mode to evade this PoC which is a loss in visibility. In addition to no visibility in incognito mode, the same applies to applications like curl. If a user or an attacker uses curl to download a malicious payload, we will not have a record of the URL. However, Osquery can be used to monitor user commands for this type of threat.
Osquery does not inspect  HTTP payloads

The biggest shortcoming of this PoC is that it doesn’t have the ability to inspect HTTP payloads since this can only be done with a web proxy. Furthermore, as stated above, the operational and hardware costs of a web proxy can be expensive. However, this PoC can be used to demonstrate to your leadership why they should purchase a web proxy to increase visibility. For example, let’s say this PoC detects malware that is known to steal intellectual property. This PoC will NOT give you the proper visibility to determine if and what the malware stole. However, an incident like this would demonstrate the importance of a web proxy in the overall defense strategy to protect users.
References

    [1] Build custom osquery tables using ATC
    [2] Symantec ProxySG S400-20 – Proxy Edition – security appliance
    [3] Sophos UTM: How to Deploy the Web Protection Proxy CA
    [4] Public Key Pinning (PKP) and Zscaler
    [5] SSL Inspection


