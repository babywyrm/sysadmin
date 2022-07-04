#!/usr/bin/env bash

set -x

# jq Recipes
#    _             _____              _
#   (_)           |  __ \            (_)
#    _   __ _     | |__) | ___   ___  _  _ __    ___  ___
#   | | / _` |    |  _  / / _ \ / __|| || '_ \  / _ \/ __|
#   | || (_| |    | | \ \|  __/| (__ | || |_) ||  __/\__ \
#   | | \__, |    |_|  \_\\___| \___||_|| .__/  \___||___/
#  _/ |    | |                          | |
# |__/     |_|                          |_|
#
# I'm assuming you are following along on the command line as you read
# this: typing or pasting each command in as you go, then taking a few
# minutes to examine the output and/or the files created by the
# commands you have run. I've included the output of some commands for
# reference.
#
# The first thing that's needed in order to experiment with jq is ---
# some data! So now I will create a data file with a few lines of log
# entries. Each log entry contains a severity indicator (wrapped in
# [square brackets]) followed by a message.

echo "[DEBUG] foo
[ERROR] bar
[ERROR] baz
[INFO] boz" > example.log

# That creates a file called example.log in your current working
# directory.
#
# Now you can use cat to verify the contents of example.log

cat example.log

# And you should see that example.log contains the following lines of
# text:
#
#    [DEBUG] foo
#    [ERROR] bar
#    [ERROR] baz
#    [INFO] boz
#
# Now, this is a toy data set but it has the advantage of being easy
# to reason about while learning! Believe me, these four lines
# actually contain enough variation to keep things interesting for the
# rest of this article =D
#
# Now that I have a logfile to analyze, I have many choices as to what
# type of analysis to perform!
#
# First off, why don't I read each line of the file into an
# array. That would be much easier to work with programmatically than a
# plain text file. So I can save myself some coding time later by
# performing this one-time transformation on my log data right now!

jq --slurp --raw-input --raw-output 'split("\n") | .' example.log > log_lines.json

# That command created a new file: log_lines.json which contains the
# same information as our original log, but formatted as a JSON array
# ready for loading into ANY programmatic environment.
#
# Now when I take a look a the newly generated JSON file:

jq . log_lines.json

# I see that it contains a JSON array like this:
#
#    [
#      "[DEBUG] foo",
#      "[ERROR] bar",
#      "[ERROR] baz",
#      "[INFO] boz"
#    ]
#
# Note here a key advantage of working with my own generated "toy"
# data set: it is trivially possible to verify that I (the writer) and
# you (the reader) are definitely working with the exact same data
# set. This confidence in consistency is an invaluable advantage when
# learning the fundamentals of a Turing-complete DSL like jq!
#
# Another thing to note is that I am using jq rather than cat to read
# the contents of JSON files. cat simply reads text files to the
# screen. Everything is plain text as far as cat is concerned -- cat
# has no concept of JSON! So if you have invalid JSON for some reason,
# cat will happily show it to you and never warn you about potential
# problems.
#
# On the other hand, jq CAN NOT output invalid JSON. The output from
# jq is always serialized directly into JSON from an object in memory.
#
# In other words: jq never "just prints" a JSON string. Rather, jq
# ALWAYS validates all JSON before attempting to print it out. JSON
# that cannot be validated causes jq to print nothing and exit with an
# error!
#
# So just by using jq to print out my JSON, I am implicitly testing
# that my JSON is valid!





# Data Analysis
#  _____        _                                  _           _
# |  __ \      | |               /\               | |         (_)
# | |  | | __ _| |_ __ _        /  \   _ __   __ _| |_   _ ___ _ ___
# | |  | |/ _` | __/ _` |      / /\ \ | '_ \ / _` | | | | / __| / __|
# | |__| | (_| | || (_| |     / ____ \| | | | (_| | | |_| \__ \ \__ \
# |_____/ \__,_|\__\__,_|    /_/    \_\_| |_|\__,_|_|\__, |___/_|___/
#                                                     __/ |
#                                                    |___/
#
# Now that the plain text log has been converted to JSON, I can do
# some data mining.
#
# A very common question when looking at an application log is: how
# many and what kind of errors are in this log? So I'll do that
# analysis now on my toy data set...

jq 'map(split(" ") | {severity: "\(.[0])", message: "\(.[1])"})' log_lines.json > severity_index.json

# I've now created a new file: severity_index.json, which contains an
# array of hashes. Each hash has two keys: severity and message.
#
# When I view my newly created index file:

jq . severity_index.json

# Then I see that it contains an array of JSON records; representing
# the original log lines as structured data:
#
#     [
#       {
#         "severity": "[DEBUG]",
#         "message": "foo"
#       },
#       {
#         "severity": "[ERROR]",
#         "message": "bar"
#       },
#       {
#         "severity": "[ERROR]",
#         "message": "baz"
#       },
#       {
#         "severity": "[INFO]",
#         "message": "boz"
#       }
#     ]
#
# Now if I want a count of log lines by severity, I can use the
# following expression:

jq 'group_by(.severity) | map({"\(.[0].severity)" : length})' severity_index.json > totals.json

# When I view the newly generated index of total messages by severity:

jq . totals.json

# Then I can see that it's again an array of JSON records; this time
# providing a lookup table of total message counts:
#
#     [
#       {
#         "[DEBUG]": 1
#       },
#       {
#         "[ERROR]": 2
#       },
#       {
#         "[INFO]": 1
#       }
#     ]
#
# Now the output at this point is JSON but I could be terser if I just
# wanted human-readable output. jq provides a LOT of control over
# output formats!
#
# Here's the same query against severity_index.json, but formatted as
# human-readable plain text. Note I've moved the numbers to the left
# hand side of the output, so that they line up with the left edge of
# the screen. This is helpful when formatting data for humans to
# read.

jq -r 'group_by(.severity) | map("\(length) \(.[0].severity)") | .[]' severity_index.json > totals.txt

# I'll use cat to view the generated file this time, because now I'm
# dealing with plain text and not JSON:

cat totals.txt

# And I can see that totals.txt is suitable for including in an email
# or echo'ing into an IRC chat room!
#
#     1 [DEBUG]
#     2 [ERROR]
#     1 [INFO]





# diff for JSON
#      _ _  __  __    __                  _  _____  ____  _   _
#     | (_)/ _|/ _|  / _|                | |/ ____|/ __ \| \ | |
#   __| |_| |_| |_  | |_ ___  _ __       | | (___ | |  | |  \| |
#  / _` | |  _|  _| |  _/ _ \| '__|  _   | |\___ \| |  | | . ` |
# | (_| | | | | |   | || (_) | |    | |__| |____) | |__| | |\  |
#  \__,_|_|_| |_|   |_| \___/|_|     \____/|_____/ \____/|_| \_|
#
# One of the most exciting applications of jq is in testing data set
# integrity. Historically, data integrity testing has meant working
# with large, relatively static data sets that have been transformed
# and filtered through a complex Extract-Transform-Load pipeline
# (ETL).
#
# However in the Web/Mobile century, every application is having an
# ongoing API conversation with external services. The artifacts
# exchanged during these API transactions constitute a relatively
# small, rapidly changing data set.
#
# jq's "does one thing well" approach to JSON processing makes it
# possible to use a single tool to do both large-scale data integrity
# testing; as well as small-but-rapidly-iterating analysis of API
# transaction artifacts!
#
# First I will create a second data set containing only the non-error
# lines from my original example.log file:

jq 'map(select(.severity != "[ERROR]")) | sort' severity_index.json > for_comparison.json

# I've sorted the keys in the second data set just to make the point
# that using the diff command isn't that useful when dealing with JSON
# data sets.
#
# When I view the file I will be using for comparison with my existing
# severity_index.json data set:


jq . for_comparison.json

# Then I can see that I'm dealing with an array of two records.
#
#     [
#       {
#         "severity": "[DEBUG]",
#         "message": "foo"
#       },
#       {
#         "severity": "[INFO]",
#         "message": "boz"
#       }
#     ]
#
# The simplest test I'd ever want to perform is just finding out if
# two data sets are the same. Here's how jq lets me do that:

jq --slurp --exit-status '.[0] == .[1]' severity_index.json for_comparison.json

# Note the use of the --exit-status flag, which tells jq to return a
# bad exit status if my equality test returns false. With the
# --exit-status flag in place, the code above is sufficient to create
# a Jenkins job that fails if two JSON files are not exactly identical!
#
# So much for exact equality. Moving on to the more interesting
# question of performing a useful diff on two JSON documents.
#
# I can figure out which keys are in the first document but not in the
# second document by using the subtraction operator:

jq --slurp '.[0] - .[1]' severity_index.json for_comparison.json

# This lists out only the error keys, since those are the keys that I
# previously filtered out of the for_comparison.json document:
#
#    [
#      {
#        "severity": "[ERROR]",
#        "message": "bar"
#      },
#      {
#        "severity": "[ERROR]",
#        "message": "baz"
#      }
#    ]
#
# Now I'll set up my data files so that I can try a slightly more complex diff.
#
# I want to see the diff "go in both directions" so to speak --- that
# is, I want to see what happens when BOTH documents contain at least
# one key/value pair that isn't in the other document.
#
# This means I need to generate some test data.  Adding new entries to
# existing JSON documents works like this in jq:

jq '[{severity: "[DEBUG]", message: "hello world!"}] + .' for_comparison.json > advanced_comparison.json

# I'm choosing to prepend to the data set here because I want to drive
# home my point about diff not being a good tool for this sort of
# analysis (even on very small data sets like this one). The "rules"
# for outputting JSON documents are too fast-and-loose for a tool like
# diff which was designed for logfile and plain text analysis.
#
# An interesting capability of jq is the concurrent
# application of multiple filters to the input stream while still
# returning the output as a single JSON document. So if I want to
# produce a third JSON document showing the difference between the two
# documents under comparison, I can do that like so:

jq --slurp '{missing: (.[0] - .[1]), added: (.[1] - .[0])}' severity_index.json advanced_comparison.json > an_actual_diff.json

# Now I have created a new file: an_actual_diff.json. It contains a
# JSON object with two keys: "missing" and "added." Just like a diff!

jq . an_actual_diff.json

# And the output should look like:
#
#    {
#      "missing": [
#        {
#          "severity": "[ERROR]",
#          "message": "bar"
#        },
#        {
#          "severity": "[ERROR]",
#          "message": "baz"
#        }
#      ],
#      "added": [
#        {
#          "severity": "[DEBUG]",
#          "message": "hello world!"
#        }
#      ]
#    }
#
# Now I can easily create different reports. For instance I can easily
# say how many keys present in the original file, were missing from
# the comparison file:

jq '.missing | length | "\(.) keys were not found."' an_actual_diff.json

# This should give you output like "2 keys were not found." Again,
# this sort of output is perfect for echo'ing into a chatroom or
# including in an automated notification email.




# API Testing
#           _____ _____   _______        _   _
#     /\   |  __ \_   _| |__   __|      | | (_)
#    /  \  | |__) || |      | | ___  ___| |_ _ _ __   __ _
#   / /\ \ |  ___/ | |      | |/ _ \/ __| __| | '_ \ / _` |
#  / ____ \| |    _| |_     | |  __/\__ \ |_| | | | | (_| |
# /_/    \_\_|   |_____|    |_|\___||___/\__|_|_| |_|\__, |
#                                                     __/ |
#                                                    |___/
#
# Earlier I said that a jq expression with the --exit-status flag
# enabled is sufficient to fail a Jenkins job if a JSON document
# doesn't meet expectations.
#
# JSON documents come from all kinds of sources but typically when
# someone says "API testing" they mean that they want to craft URLs
# based on some existing, written RESTful API specification, then
# retrieve JSON documents from a remote host by requesting those URLs
# and downloading the (JSON) responses. As a final step, validation is
# performed that demonstrates the JSON document returned by an API
# query matches what one might expect based upon the API specification.
#
# Using curl to retrieve JSON responses is beyond the scope of this
# article. But do consider that there are very many places where Web
# and mobile applications expose their API data --- making a curl
# request is just the tip of the iceberg! Other options include HAR
# capture with Chrome Inspector, network traffic inspection via
# Charles or WireShark and  investigation of JSON documents
# cached in your browser / filesystem.
#
# In any case, the larger point is that comparing JSON documents and
# then failing the build is easy with jq!
#
# Now I will examine some common use cases that come up when testing
# JSON documents retrieved from a remote API.
#
# Just imagine for a moment that the two files we've created (and been
# working with) are the results of two calls to different instances of
# the same API: "foohost/v1/severity_index" and
# "barhost/v2/severity_index" for the sake of pretending =D
#
# So in this imaginary API test scenario I would first go through the
# one-time step of retrieving the remote responses and saving them to
# files, something like:
#
#     curl foohost/v1/severity_index > severity_index.json
#     curl barhost/v2/severity_index > advanced_comparison.json
#
# Then the two API responses are saved in two files, and I can compare
# the two files as just I have been doing above.
#
# Now back to looking at the useful comparisons that jq can perform
# against two JSON documents that (should) have commonalities with
# regard to structure --- such as two "identical" responses from two
# different implementations of the same application server!
#
# The first snag one is likely to run into in data testing is... data
# dependencies that result in fragile tests. An API smoke
# test has to be dependent to some extent on the data returned (that's
# the whole point). But it sucks to have to break the build because
# someone updated the UI copy or because a cached query was
# updated.
#
# Often I can attain a sufficient level of data independence by simply
# validating that a JSON document has a top-level structure that
# matches the API specification.
#
# Here's an example of how to "diff" the top-level keys in a JSON
# document, ignoring the values of those keys:

jq --slurp '{missing_keys: (([.[0][].severity]) - ([.[1][].severity]) | unique), added_keys: (([.[1][].severity]) - ([.[0][].severity]) | unique)}' severity_index.json advanced_comparison.json

# And I can turn that into a test that causes Jenkins to fail the
# build when the file being compared does not use all the same
# top-level keys as the original file.

jq --slurp --exit-status '([.[0][].severity] | unique) - ([.[1][].severity] | unique) == []' severity_index.json advanced_comparison.json





# JSONp with jq
#       _  _____  ____  _   _                  _ _   _         _
#      | |/ ____|/ __ \| \ | |                (_) | | |       (_)
#      | | (___ | |  | |  \| |_ __   __      ___| |_| |__      _  __ _
#  _   | |\___ \| |  | | . ` | '_ \  \ \ /\ / / | __| '_ \    | |/ _` |
# | |__| |____) | |__| | |\  | |_) |  \ V  V /| | |_| | | |   | | (_| |
#  \____/|_____/ \____/|_| \_| .__/    \_/\_/ |_|\__|_| |_|   | |\__, |
#                            | |                             _/ |   | |
#                            |_|                            |__/ |_|
#
# In order to serve JSON documents to client-side JavaScript
# applications, it is convenient to be able to transfer documents
# between hosts on the Internet, outside the limitations imposed by
# the Same-Origin Policy.
#
# JSONp is one such means for transferring JSON documents across
# domains.
#
# The JSONp specification is quite simple. All I need to do to be
# compliant is to wrap a JSON document in a JavaScript function
# call. The JavaScript function in turn must be defined on the client
# side.
#
# On first encounter, JSONp can sound complex. But in practice a client side
# JavaScript implementation with jQuery looks like this:
#
#    var response;
#
#    var jsonpHelper = function(data) {
#        response = data;
#    };
#
#    $.ajax({
#        url: 'foohost/v1/severity_index',
#        dataType: 'jsonp',
#        jsonp: false,
#        jsonpCallback: 'jsonpHelper'
#    });
#
# And that's it.
#
# Once this code executes in the browser, the "response" global
# variable gets "hydrated" with all the data that was in the JSONp
# file from the remote host. This is a general solution for
# cross-domain JSON transfer.
#
# So this is a very convenient way to provide a JSON transaction
# capability in the client, without necessarily changing any
# configuration on the remote host.
#
# Here is how I would go about crafting a JSONp response whose payload
# is the severity_index.json file I generated, above.

jq --raw-output '"jsonpHelper(\(.));"' severity_index.json > jsonp_severity_index.json

# The newly generated file doesn't have any line breaks --- it is
# already minified and ready to serve over http. Now ANY host I choose
# can serve this JSONp response along with JavaScript code above; and
# my data can be loaded into ANY client-side process running in the
# browser!
#
# Although everything-on-one-line formatting is useful for Web
# servers, it does make it hard to read the generated code!
# Optionally I can prettify the generated JSONp code with uglifyjs,
# resulting human-readable JavaScript that I can visually verify has
# got the right data:

cat jsonp_severity_index.json | uglifyjs -b

#    jsonpHelper([ {
#        severity: "[DEBUG]",
#        message: "foo"
#    }, {
#        severity: "[ERROR]",
#        message: "bar"
#    }, {
#        severity: "[ERROR]",
#        message: "baz"
#    }, {
#        severity: "[INFO]",
#        message: "boz"
#    } ]);
#




# Schema Validation
#   _____        _
#  / ____|      | |
# | (___    ___ | |__    ___  _ __ ___    __ _
#  \___ \  / __|| '_ \  / _ \| '_ ` _ \  / _` |
#  ____) || (__ | | | ||  __/| | | | | || (_| |
# |_____/  \___||_| |_| \___||_| |_| |_| \__,_|
#
#
# __      __     _  _      _         _    _
# \ \    / /    | |(_)    | |       | |  (_)
#  \ \  / /__ _ | | _   __| |  __ _ | |_  _   ___   _ __
#   \ \/ // _` || || | / _` | / _` || __|| | / _ \ | '_ \
#    \  /| (_| || || || (_| || (_| || |_ | || (_) || | | |
#     \/  \__,_||_||_| \__,_| \__,_| \__||_| \___/ |_| |_|
#
# Here is a recipe that dumps the schemas (as determined by jq) from a
# JSON document.
#
# I have formatted the schemas as valid jq queries, so that I can feed
# them back into my test harness easily.

jq --raw-output 'paths | map(. as $item | type | if  . == "number" then "[\($item)]" else "[\"" + $item + "\"]" end) | join("") | "." + .' severity_index.json > schema_dump.json

# The output from this command is a list of all the jq queries which
# are valid against the current document:

cat schema_dump.json

# Should produce output like this:
#
#    .[0]
#    .[0]["severity"]
#    .[0]["message"]
#    .[1]
#    .[1]["severity"]
#    .[1]["message"]
#    .[2]
#    .[2]["severity"]
#    .[2]["message"]
#    .[3]
#    .[3]["severity"]
#    .[3]["message"]
#
# This is a very general schema because it doesn't specify the types
# (or any characteristics) of the data *in* the fields. But since I
# have this list of all possible queries against my document, I can
# use that list to generate a script that will drill down to each end
# node in the document, producing a record of the current value of
# each node.

jq -R -r '. + " | type" | @sh "jq \(.) severity_index.json" | .' schema_dump.json > get_types.sh

# Now get_types.sh is a runnable set of jq queries that will produce
# the type of each field for every path in the schema dump!

sh get_types.sh > schema_types.txt

jq -s '.' schema_types.txt > schema_types.json
jq -s --raw-input 'split("\n")' schema_dump.json > clean_schema_dump.json

# Now I can create a config file off which I can generate the
# validation script:

jq -s --raw-output '.[][] | @sh' schema_types.json > clean_schema_types.txt
jq -s --raw-output '.[][] | @sh' clean_schema_dump.json > clean_schema_dump.txt

paste -d' ' clean_schema_dump.txt  clean_schema_types.txt > detailed_schemas.txt

# At this point I have a pretty complete schema specification. It
# would be helpful if the specification were organized as highly
# structured data. Here's how I would structure it:

perl -lwpe "s{' '}{ | type == \"}; s{'$}{\"'}; s{^(.*)$}{jq \$1 severity_index.json}" detailed_schemas.txt > validation.sh

# Now validation.sh is an explicit set of automated checks for fields
# and data types of fields.
#
# There is more that could be done in the way of validation. The first
# thing I want at this point is a way to limit the depth of the tree I
# am validating. Just because an API returns a bazillion levels of
# hierarchy shouldn't mean I have to test all of them!
#
# Probably I can use the jq path command to do that...
