# Splunk Queries

I **really** don't like Splunk documentation. Why is it so hard to find out how to do a certain action? So this is a cheatsheet that I constructed to help me quickly gain knowledge that I need.

## Analysis

### Events over time

```
index="my_log"
| bin span=1hr _time
| stats count by _time
```

OR

```
index="my_log"
| timechart count span=1hr
```

## Arrays

### Does an array contain a specific value?

```
"array_name{}"=value

# Nested arrays
"dictionary_name.array_name{}.dictionary2.deep_nested_array{}"=value
```

### Extracting values from an array

```
eval variable_name=mvindex('array_name{}', array_index)
```

## Strings

### String Matching (with whitespace supression)

If you're unable to match field values as you expect, extract the non-whitespace values from the field and compare against that instead.

For example, in the below example, `context.messageStatus` may contain whitespace, so Splunk won't capture them with a standard `=`. Instead, we need to do the following:

```
index="my_log"
| rex field=context.MessageStatus "(?<messageStatus>\w+)"
| eval status=if(messageStatus = "undelivered", "fail", "success")
| search status="success"
```

If you're trying to get multiple matches, use `max_match`, where `max_match=0` finds unlimited matches.

### String Replacement

```
rex mode=sed field=your_field "regex_statement"

# This is especially handy when you want to ignore whitespace!
# Example:
#    rex mode=sed field=my_field "s/ //g"
```

### String Concatenation

```
eval variable_name = "string1" . "string2"

# This is just like PHP
# Example:
#     eval word = "foo" . "bar" | table word
#
# Output:
#    word
#    ----
#    foobar 
```

### Substrings

```
eval variable_name = substr(variable, start_index, length)

# Example:
#    eval word = "foobar" | eval short = substr(word, 1, 3) | table short
#
# Output:
#    short
#    -----
#    oob
```

## eval

Trying to use a nested value in a dictionary, in an eval statement? Use **rename** first!

```
Example Entry:
{
    "signals": {
        "ip_address": "1.2.3.4",
    },
}

Query:
    | rename signals.ip_address as ip_addr
    | eval ip_addr=if(isnull(ip_addr), "null", ip_addr)
```

## Working with Multiple Queries

### Subsearch

This is used for funneling the output of one splunk query, into another query. However, some older splunk versions do not support it. However, there are other ways to formulate your query! See [this link](https://answers.splunk.com/answers/129424/how-to-compare-fields-over-multiple-sourcetypes-without-join-append-or-use-of-subsearches.html) for inspiration.

```
Example Logs:

nginx_logs
----------
{
	"useragent": "Chrome",
	"status":    200,
	"user":      "random-hash",
}

api_logs
--------
{
	"endpoint":   "/userinfo",
	"request-id": "random-hash",
}

Objective: Find out the useragent

Query:
    index=*
        (endpoint="/userinfo" AND request-id="random-hash") OR user="random-hash"
        | stats count by useragent
 
Explanation:
This searches all logs and tries to cross-reference a request-id from `api_logs`, and
searches for its useragent from `nginx_logs`. Note that the search parameters for the
log in `api_logs` should be as unique as possible, so that it won't pull information
from other logs.
```

### Joins

Joins are handy, when they work. This is a semi-complicated example I've used:

```
Example Logs:

suspicious_ips
--------------
{
    "ip_address": "1.2.3.4",
}

valid_ips
-----------
{
    "ip_address": "1.2.3.4",
}

Objective: Determine which IPs in `suspicious_ips` have NOT been logged in `valid_ips`.

Query:
    sourcetype=suspicious_ips
        | join type=left ip_address [
            search search_name=valid_ips
            | stats count by ip_address, search_name
          ]
        | search NOT search_name=valid_ips
```

When doing this, **remember to put `search` in the subsearch**! Otherwise, it won't work at all.

## Filtering

### NOT v !=

This is so lame, and is such a gotcha. [Original source](http://docs.splunk.com/Documentation/Splunk/7.0.2/Search/NOTexpressions).

Turns out, empty string is considered "not existing". Which means, if you have a column of either empty string, or value, and you want to get empty strings only, **use NOT** rather than !=.

## Formatting

I like things looking nice. Often this also means better usability, as it takes less mental energy to parse output
meant for machines. However, Splunk is a **terrible** means to nicely format output, especially when trying to send
this output downstream (like JIRA).

Through lots of trial and error, I have found these patterns to work nicely:

- Use `rex` to extract values

- Use `eval` to assign temporary variables

- Use `mvexpand` to split multiple results from `rex` into their own separate rows

- Use `stats list(<field_to_combine>) as <new_name_for_field> by <params_you_want_to_group_together>`
  to combine rows.
  
- Use `nomv` to teach JIRA to recognize multi-value rows, then use `rex` to replace spaces with new lines.
  IMPORTANT: Even though Splunk does not show the new lines, it will come out as expeected in JIRA!

## Miscellaneous Gotchas

### Using rename

For some wacky reason,

```
stats count by data.user as user
```

is not the same as

```
stats count by data.user | rename data.user to user
```

The **latter** works as expected. I guess learning this method is always better, since it also works
when trying to count by multiple items.

```
stats count by data.user, data.email | rename data.user to user
```

## References

* Useful [other eval functions](http://docs.splunk.com/Documentation/Splunk/6.2.1/SearchReference/CommonEvalFunctions).

# Splunk Queries

## Getting Errors
```
index=<index>
AND CASE("ERROR")
```

## Java Exceptions & Stack Traces
```
index=<index>
| transaction startswith="CASE("ERROR")" maxevents=250 mvlist=true 
| table message
```

## Get Errors group by Count
```
index=<index>
AND (error OR exception)
| table message 
| eval message=replace(message,"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d*\s","")
| stats count by message
| sort -count
```

##
#
https://splunkonbigdata.com/top-10-used-and-popular-splunk-queries/
#
##


In this blog, we gonna show you the top 10 most used and familiar Splunk queries. So let’s start.

    List of Login attempts of splunk local users

Follow the below query to find how can we get the list of login attempts by the Splunk local user using SPL.

index=_audit action="login attempt"
| stats count by user info action _time
| sort - info

2. License usage by index

index=_internal source=*license_usage.log type="Usage" splunk_server=* 
| eval Date=strftime(_time, "%Y/%m/%d") 
| eventstats sum(b) as volume by idx, Date 
| eval MB=round(volume/1024/1024,5) 
| timechart first(MB) AS volume by idx

3. List of Forwarders Installed

index="_internal" sourcetype=splunkd group=tcpin_connections NOT eventType=* 
| eval Hostname=if(isnull(hostname), sourceHost,hostname),version=if(isnull(version),"pre 4.2",version),architecture=if(isnull(arch),"n/a",arch) 
| stats count by Hostname version architecture 
| sort + version

4. Splunk users search activity

index=_audit splunk_server=local action=search (id=* OR search_id=*) 
| eval search_id = if(isnull(search_id), id, search_id) 
| replace '*' with * in search_id 
| rex "search='search\s(?<search>.*?)',\sautojoin" 
| search search_id!=scheduler_* 
| convert num(total_run_time) 
| eval user = if(user="n/a", null(), user) 
| stats min(_time) as _time first(user) as user max(total_run_time) as total_run_time first(search) as search by search_id 
| search search!=*_internal* search!=*_audit* 
| chart sum(total_run_time) as "Total search time" count as "Search count" max(_time) as "Last use" by user 
| fieldformat "Last use" = strftime('Last use', "%F %T.%Q")

5. Search History

index=_audit action=search sourcetype=audittrail search_id=* NOT (user=splunk-system-user) search!="'typeahead*"
| rex "search\=\'(search|\s+)\s(?P<search>[\n\S\s]+?(?=\'))"
| rex field=search "sourcetype\s*=\s*\"*(?<SourcetypeUsed>[^\s\"]+)" 
| rex field=search "index\s*=\s*\"*(?<IndexUsed>[^\s\"]+)"
| stats latest(_time) as Latest by user search SourcetypeUsed IndexUsed
| convert ctime(Latest)

6. Advanced query for saved searches information

index=_internal sourcetype=scheduler result_count 
| extract pairdelim=",", kvdelim="=", auto=f 
| stats avg(result_count) min(result_count) max(result_count), sparkline avg(run_time) min(run_time) max(run_time) sum(run_time) values(host) AS hosts count AS execution_count by savedsearch_name, app 
| join savedsearch_name type=outer 
    [| rest /servicesNS/-/-/saved/searches 
    | fields title eai:acl.owner cron_schedule dispatch.earliest_time dispatch.latest_time search 
    | rename title AS savedsearch_name eai:acl.app AS App eai:acl.owner AS Owner cron_schedule AS "Cron Schedule" dispatch.earliest_time AS "Dispatch Earliest Time" dispatch.latest_time AS "Dispatch Latest Time"] 
| rename savedsearch_name AS "Saved Search Name" search AS "SPL Query" app AS App 
| makemv delim="," values(host) 
| sort - avg(run_time) 
| table "Saved Search Name", App, Owner, "SPL Query" "Cron Schedule" hosts, execution_count, sparkline, *(result_count), sum(run_time) *(run_time)

7. Users detail information

Suggestions: “Metadata vs Metasearch“

| rest splunk_server=local /services/authentication/users | rename title as username | mvexpand roles | table realname, username, roles, email 
| join type=outer roles [ rest splunk_server=local /services/authorization/roles | rename title as roles | eval ir=imported_roles | search srchIndexesAllowed=* | fields roles imported_roles ir srchIndexesAllowed srchIndexesDefault | mvexpand ir]
| foreach srchIndexesAllowed
[ eval srchIndexesAllowed=replace(<<FIELD>>,"^_\*$","[all internal indexes];") 
| eval srchIndexesAllowed=replace(<<FIELD>>,"\*\s_\*","[all internal and non-internal indexes];")
| eval srchIndexesAllowed=replace(<<FIELD>>,"\*\s","[all non-internal indexes];")
| eval srchIndexesAllowed=replace(<<FIELD>>,"\*$","[all non-internal indexes];") 
]
| foreach srchIndexesDefault
[ eval srchIndexesDefault=replace(<<FIELD>>,"_\*","[all internal indexes];") 
| eval srchIndexesDefault=replace(<<FIELD>>,"\*\s_\*","[all internal and non-internal indexes];")
| eval srchIndexesDefault=replace(<<FIELD>>,"\*\s","[all non-internal indexes];") 
| eval srchIndexesDefault=replace(<<FIELD>>,"\*$","[all non-internal indexes];")
]
| join type=outer ir
[ | rest splunk_server=local /services/authorization/roles | fields - imported_roles
| rename title as ir
| mvexpand srchIndexesAllowed
| eval inheritedAllowed=if(idxtype=="Invalid","",srchIndexesAllowed." (by ".ir.");")
| stats values(inheritedAllowed) as inheritedAllowed by ir ]
| fields - ir, splunk_server
| makemv allowempty=t inheritedAllowed delim=";" 
| makemv allowempty=t srchIndexesAllowed delim=";"
| makemv allowempty=t srchIndexesDefault delim=";"
| rename srchIndexesDefault TO "Searched by default", srchIndexesAllowed TO "AllowedIndexes by Role", inheritedAllowed TO "AllowedIndexes by Inheritance", imported_roles TO "Inherited Roles"

8. All props and transforms information in detail

| rest /servicesNS/-/-/admin/directory count=0 splunk_server=local | fields eai:acl.app, eai:acl.owner, eai:acl.perms.*, eai:acl.sharing, title, eai:type, disabled
| foreach eai:*.* 
    [ rename "<<FIELD>>" TO <<MATCHSEG2>> ]
| foreach eai:* 
    [ rename "<<FIELD>>" TO <<MATCHSTR>> ]
| eval attribute=replace(title,"(.*:\s+)(.*)","\2")
| eval st=replace(title,"(.*)(\s+:.*)","\1")
| eval props_sourcetype=if(st==attribute,"",st)
| join type=outer attribute
    [| rest /servicesNS/-/-/admin/props-extract count=0 splunk_server=local | fields attribute value stanza type | rename value TO props_value, stanza to props_stanza, type to props_type ]
| join type=outer attribute
    [| rest /servicesNS/-/-/admin/transforms-extract count=0 splunk_server=local
    | fields REGEX FORMAT disabled eai:acl.app title FIELDS
    | makemv delim="," FIELDS
    | rename FIELDS to tf_fields, disabled to tf_disabled, REGEX to tf_regex, FORMAT to tf_format, title to attribute, eai:acl.app to tf_app]
| fillnull disabled tf_disabled
| table disabled app type attribute props_type props_stanza props_value props_sourcetype tf_disabled tf_format tf_fields tf_regex sharing perms.* location owner |  search (app="*" AND (sharing="*")) AND disabled=*  
| rename attribute TO "Object Name"

9. Dashboards access information

| rest /servicesNS/-/-/data/ui/views splunk_server=* 
| search isDashboard=1 
| rename eai:acl.app as app 
| fields title app 
| join type=left title 
[| search index=_internal sourcetype=splunk_web_access host=* user=* 
| rex field=uri_path ".*/(?<title>[^/]*)$" 
| stats latest(_time) as Time latest(user) as user by title
] 
| where isnotnull(Time) 
| eval Now=now() 
| eval "Days since last accessed"=round((Now-Time)/86400,2) 
| sort - "Days since last accessed" 
| convert ctime(Time) 
| fields - Now

10. Bucket count by index

Follow the below query to find how can we get the count of buckets available for each and every index using SPL.
You can also know about :  How To Track User Activity ( Modifications of dashboards ,  Permission Changes etc)  In Splunk

Suggestions: “dbinspect“

|dbinspect index=*  | chart dc(bucketId) over splunk_server by index

Hope you enjoyed this blog “10 most used and familiar Splunk queries“, see you on the next one. Stay tune.

Happy Splunking!!

8
1
8
Related

How To View Search History In Splunk
January 31, 2019
In "Tips & Tricks"

Base 10 to Base 36 Conversion In Splunk (Part-II)
January 10, 2022
In "Development"

How to View the Current Logged in Users Information in Splunk
March 19, 2019
In "Tips & Tricks"

Spread our blog

    TAGS
    development
    most used
    spliunk spl
    splunk command
    Splunk Development
    top 10
    top 10 query
    top 10 splunk quries

Previous article
Splunk Knowledge Objects: Tag vs EventType
Next article
Usage of Splunk Eval Function: MATCH
admin
https://splunkonbigdata.com
RELATED ARTICLESMORE FROM AUTHOR
Tips & Tricks
How to find a field name if the field value is known?
Dashboard
Change Dashboard Visualization Using Radio Button
Dashboard
Create a Marker Gauges in Splunk Table
Dashboard
How to Add a Disclaimer Button in Splunk Dashboard Without JS
Tips & Tricks
How to Change Default Line Weight of Splunk Line Chart
Dashboard
How to Pass Other Value from a Single Value Trellis Visualization?
LEAVE A REPLY

Save my name, email, and website in this browser for the next time I comment.

Join With Us
Name*
Email*
EDITORS CHOICE
Use Case
Splunk amplifies innovation & perk-up customer experience for BookMyShow
splunkgeek - February 15, 2020 0
Splunk amplifies innovation & perk-up customer experience for BookMyShow The company BookMyShow is currently reputed for being India's biggest ticketing website for entertainment. By using BookMyShow through...
How to Create Splunk User Analysis and Monitoring Dashboard
December 20, 2021
How to Customize a Dashboard using HTML in Splunk
November 13, 2018
Change Table Header Color Based On Values Present In The Table
April 26, 2021
POPULAR POSTS
Commands
Usage OF Stats Function ( [first() , last() ,earliest(), latest()] In...
splunkgeek - July 24, 2020 0
Dashboard
How to Add Dropdown Input option to Splunk Dashboard
splunkgeek - September 18, 2018 12
Tips & Tricks
How To Load Dashboard Faster Using “Base Search”
splunkgeek - October 5, 2020 1
Recent Posts

    How to find a field name if the field value is known? February 5, 2022
    Splunk Child Elements: Set and Unset February 4, 2022
    Splunk Dashboard Tags: Init February 4, 2022
    Splunk Command: FIELDSUMMARY February 3, 2022
    Splunk Dashboard Child Elements: Eval February 3, 2022



