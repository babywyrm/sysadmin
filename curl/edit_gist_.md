Editing GIST with cURL

##
#
https://stackoverflow.com/questions/57634219/editing-gist-with-curl
#
##

```

#!/bin/bash

COMMIT=$(git log -1 --pretty=format:'{"subject": "%s", "name": "xxx", "date": "%cD"}')

curl -X PATCH -d'{"files": {"latest-commit": {"content": "$COMMIT"}}}' -u user:xxxx https://api.github.com/gists/xxx
This just shows $COMMIT in the Gist. I tried playing with ''' and stuff but cannot make this work.

bashcurlgithub-api
Share
Improve this question
Follow
edited Jun 17, 2022 at 1:29
Sunderam Dubey's user avatar
Sunderam Dubey
1
asked Aug 24, 2019 at 0:17
Gabriel's user avatar
Gabriel
5,4731414 gold badges6363 silver badges9292 bronze badges
Add a comment
1 Answer
Sorted by:

Highest score (default)
3

Your $COMMIT variable is not expanded to its value, because it is enclosed in single-quotes.

About an actual implementation in Bash
The GitHub API require you send the file content as a string: https://developer.github.com/v3/gists/#input-1

When file content contains newlines, double quotes or other characters needing an escaping within a string, the most appropriate shell tool to fill-in and escape the content string is jq.

JavaScript provide a JSON.stringify() method, but here in the shell world, we use jq to process JSON data.

If you don't have jq available you can convert the content of the file, to a properly escaped JSON string with GNU sed this way:

# compose the GitHub API JSON data payload
# to update the latest-commit.json file in the $gist_id
# uses sed to properly fill-in and escape the content string
read -r -d '' json_data_payload <<EOF
{
  "description": "Updated from GitHub API call in Bash",
  "files": {
    "latest-commit.json": {
      "filename": "latest-commit.json",
      "content": "$(
  sed ':a;N;$!ba;s/\n/\\n/g;s/\r/\\r/g;s/\t/\\t/g;s/"/\\"/g;' <<<"$latest_commit_json_content"
)"
    }
  }
}
EOF
This is how jq is used to fill the content string with proper escaping:

json_data_payload="$(
jq \
  --arg content "$latest_commit_json_content" \
  --compact-output \
  '.files."latest-commit.json".content = $content' \
<<'EOF'
{
  "files": {
    "latest-commit.json": {
      "filename": "latest-commit.json",
      "content": ""
    }
  }
}
EOF
)"
Detailed and tested ok implementation:
#!/usr/bin/env bash

# Set to the gist id to update
gist_id='4b85f310233a6b9d385643fa3a889d92'

# Uncomment and set to your GitHub API OAUTH token
github_oauth_token='###################'

# Or uncomment this and set to your GitHub username:password
#github_user="user:xxxx"

github_api='https://api.github.com'

gist_description='Gist update with API call from a Bash script'
filename='latest-commit.json'

get_file_content() {
  # Populate variables from the git log of latest commit
  # reading null delimited strings for safety on special characters
  {
    read -r -d '' subject
    read -r -d '' author
    read -r -d '' date
  } < <(
    # null delimited subject, author, date
    git log -1 --format=$'%s%x00%aN%x00%cD%x00'
  )

  # Compose the latest commit JSON, and populate it with the latest commit
  # variables, using jq to ensure proper encoding and formatting of the JSON
  read -r -d '' jquery <<'EOF'
.subject = $subject |
.author = $author |
.date = $date
EOF
  jq \
    --null-input \
    --arg subject "$subject" \
    --arg author "$author" \
    --arg date "$date" \
    "$jquery"
}

# compose the GitHub API JSON data payload
# to update the latest-commit.json file in the $gist_id
# uses jq to properly fill-in and escape the content string
# and compact the output before transmission
get_gist_update_json() {
  read -r -d '' jquery <<'EOF'
.description = $description |
.files[$filename] |= (
  .filename = $filename |
  .content = $content
)
EOF
  jq \
    --null-input \
    --compact-output \
    --arg description "$gist_description" \
    --arg filename "$filename" \
    --arg content "$(get_file_content)" \
    "$jquery"
}

# prepare the curl call with options for the GitHub API request
github_api_request=(
  curl # The command to send the request
  --fail # Return shell error if request unsuccessful
  --request PATCH # The request type
  --header "Content-Type: application/json" # The MIME type of the request
  --data "$(get_gist_update_json)" # The payload content of the request
)

if [ -n "${github_oauth_token:-}" ]; then
  github_api_request+=(
    # Authenticate the GitHub API with a OAUTH token
    --header "Authorization: token $github_oauth_token"
  )
elif [ -n "${github_user:-}" ]; then
  github_api_request+=(
    # Authenticate the GitHub API with an HTTP auth user:pass
    --user "$github_user"
  )
else
  echo 'GitHub API require either an OAUTH token or a user:pass' >&2
  exit 1
fi

github_api_request+=(
  -- # End of curl options
  "$github_api/gists/$gist_id" # The GitHub API url to address the request
)

# perform the GitHub API request call
if ! "${github_api_request[@]}"; then
  echo "Failed execution of:" >&2
  env printf '%q ' "${github_api_request[@]}" >&2
  echo >&2
fi
Here is the generated curl call with my token redacted out:

curl --fail --request PATCH --header 'Content-Type: application/json' \
--data '{"description":"Hello World Examples","files":{"latest-commit.json":{"filename":"latest-commit.json","content":"{\n  \"subject\": \"depricate Phosphor\",\n  \"name\": \"Blood Asp\",\n  \"date\": \"Wed, 12 Dec 2018 18:55:39 +0100\"\n}"}}}' \
--header 'Authorization: token xxxx-redacted-xxxx' \
-- \
https://api.github.com/gists/4b85f310233a6b9d385643fa3a889d92
And the JSON response it replied with:

  "url": "https://api.github.com/gists/4b85f310233a6b9d385643fa3a889d92",
  "forks_url": "https://api.github.com/gists/4b85f310233a6b9d385643fa3a889d92/forks",
  "commits_url": "https://api.github.com/gists/4b85f310233a6b9d385643fa3a889d92/commits",
  "id": "4b85f310233a6b9d385643fa3a889d92",
  "node_id": "MDQ6R2lzdDRiODVmMzEwMjMzYTZiOWQzODU2NDNmYTNhODg5ZDky",
  "git_pull_url": "https://gist.github.com/4b85f310233a6b9d385643fa3a889d92.git",
  "git_push_url": "https://gist.github.com/4b85f310233a6b9d385643fa3a889d92.git",
  "html_url": "https://gist.github.com/4b85f310233a6b9d385643fa3a889d92",
  "files": {
    "latest-commit.json": {
      "filename": "latest-commit.json",
      "type": "application/json",
      "language": "JSON",
      "raw_url": "https://gist.githubusercontent.com/leagris/4b85f310233a6b9d385643fa3a889d92/raw/7cb7f9d4a0170daf5083929858fb7eef706f8b59/latest-commit.json",
      "size": 105,
      "truncated": false,
      "content": "{\n  \"subject\": \"depricate Phosphor\",\n  \"name\": \"Blood Asp\",\n  \"date\": \"Wed, 12 Dec 2018 18:55:39 +0100\"\n}"
    }
  },
...
Share
Improve this answer
Follow

```

##
#
https://superuser.com/questions/1076564/sending-gist-to-github-via-curl-and-issues-with-new-lines-inside-file
#
##

Sending gist to github via cURL and issues with new lines inside file
Asked 7 years, 5 months ago
Modified 6 years, 7 months ago
Viewed 2k times
1

So, let's say I have an index.php file containing this:

 <?= "Hello" ?>

 <?= echo "WORLD" ?>
And I wanted upload the contents of this file to my gists in github, which I am doing via

gist_content=$(cat 'index.php')

curl --user "GITHUB_USER"  -H "Content-Type: application/json; charset=UTF-8" -X POST -d  "{ \"description\": \"Created via API\", \"public\": \"true\", \"files\":{ \"index.php \":{ \"content\": \"$gist_content\"}}\" " https://api.github.com/gists
Now, this script does not work for some reason, and I get error response

{
  "message": "Problems parsing JSON",
  "documentation_url": "https://developer.github.com/v3/gists/#create-a-gist"
}
If I write everything in one line without tags, quotes like hello it works find

linuxbashcurl
Share
Improve this question
Follow
asked May 13, 2016 at 14:33
samayo's user avatar
samayo
15511 gold badge33 silver badges1212 bronze badges
Add a comment
2 Answers
Sorted by:

Highest score (default)
2

You've some syntax error in your JSON string. Please check and correct it. E.g.

$ echo "{ \"description\": \"Created via API\", \"public\": \"true\", \"files\":{ \"index.php \":{ \"content\": \"$gist_content\"}}\" " | python -m json.tool
Expecting ',' delimiter: line 1 column 95 (char 94)
So you're missing one of the curly brackets, you're opening 3, but closing 2.

The simplified syntax should be like:

```
$ echo '{"description": "Created via API", "public": "true", "files": { "index.php": { "content": "foo" } } }' | python -m json.tool
{
    "description": "Created via API",
    "files": {
        "index.php": {
            "content": "foo"
        }
    },
    "public": "true"
}
```
Then it's matter of escaping the quotes, but you're escaping it in the wrong way, see: How to escape single-quotes within single-quoted strings? For example:

$ echo 'abc'\''abc'
abc'abc
$ echo "abc"\""abc"
abc"abc
Since you're importing external file which consist double-quotes as well, you should double quote them as well using tools such as sed, etc. The same with new lines, you should change them into appropriate control characters (either <br> or \n) depending on the expected format.

So your final example would look like:
```
gist_content=$(cat index.php | sed 's/"/\\"/g' | paste -s -d '\\n' -)
curl --user "GITHUB_USER" -H "Content-Type: application/json; charset=UTF-8" -X POST -d "{"\""description"\"": "\""Created via API"\"", "\""public"\"": "\""true"\"", "\""files"\"": { "\""index.php"\"": { "\""content"\"": "\""$gist_content"\"" } } }" https://api.github.com/gists
Share
Improve this answer
Follow
edited May 23, 2017 at 12:41
Community's user avatar
CommunityBot
1
answered May 13, 2016 at 14:55
kenorb's user avatar
kenorb
24.9k2727 gold badges129129 silver badges199199 bronze badges
If I started the JSON request with single quotes, then $gist_content won't be evaluated. – 
samayo
 May 13, 2016 at 14:57
When you use with double-quotes you need to escape it, but your escaping is not correct. Let me update the post, but my computer is bloody slow. You need to do like: " "\"" " to escape a single double-quote. Secondly your JSON has uneven number brackets, or something. – 
kenorb
 May 13, 2016 at 15:03
I am saying, if I use single quotes the bash $variable won't be read. You can try and then let me know, if it works for you – 
samayo
 May 13, 2016 at 15:13
@samayo I know, I'm just saying you've the syntax error in your JSON, so you can do the rest. I just simplified the example for you to show you what is the valid JSON format and I've explained where is the issue, so you can fix it by yourself by understanding the problem. You've just a typo, that's all. –

```
kenorb
 May 13, 2016 at 15:14 
like I said, your final example gives me the same error I posted in the question. It is a tricky situation. – 
samayo
 May 13, 2016 at 15:22
Show 7 more comments
1

You can use this solution to replace new lines, Also you have to escape double quotes in the content & description field :
```
#!/bin/bash

ACCESS_TOKEN="YOUR_ACCESSS_TOKEN"

description="the description for this gist. There are also some quotes 'here' and \"here\" in that description"
public="true"
filename="index.php"

desc=$(echo "$description" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
json=$(cat index.php | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

curl -v -H "Content-Type: text/json; charset=utf-8" \
        -H "Authorization: Token $ACCESS_TOKEN" \
        -X POST https://api.github.com/gists -d @- << EOF
{ 
  "description": "$desc", 
  "public": "$public", 
  "files": { 
      "$filename" : { 
          "content": "$json"
       } 
   } 
}
EOF
