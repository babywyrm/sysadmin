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
