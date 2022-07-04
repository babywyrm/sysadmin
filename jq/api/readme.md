
https://stackoverflow.com/questions/68460308/create-github-gist-using-file-with-gist-api

<br>
<br>

Create Github gist using file, with Gist API
Asked 11 months ago
Modified 3 months ago
Viewed 353 times

Report this ad

1


I am attempting to make a github gist using the following command

curl -X POST -d '{"public":true,"files":{"test.txt":{"content":"String file contents"}}}' -u mgarciaisaia:mypassword https://api.github.com/gists
How should I edit the command such that it uploads a file on my local computer to the new gist, instead of taking content in a string from the command line?

shell
github
github-api
gist
Share
Improve this question
Follow
edited Jul 20, 2021 at 19:39
user avatar
jthill
49.2k44 gold badges7272 silver badges121121 bronze badges
asked Jul 20, 2021 at 19:22
user avatar
Norman
1111 bronze badge
Hi Norman, would this thread help you with your issue? It seems similar and the first answer might help you. – 
GuiFalourd
 Jul 20, 2021 at 21:30 
Add a comment
1 Answer
Sorted by:

Highest score (default)

3

You can use jq to generate a suitable payload. Let's say your file, myfile, looks like this:

#!/usr/bin/env bash

sed '
    s/://            # Drop colon
    s/^/Package: /   # Prepend with "Package: "
    N                # Append next line to pattern space
    s/\n/ | New: /   # Replace newline with " | New: "
    N                # Append next line to pattern space
    s/\n/ | Old: /   # Replace newline with " | Old: "
' updates.txt
A shell script with a sed command, including tab indentation, escaped characters and more. To convert this to a JSON string:

jq --raw-input --slurp '.' myfile
resulting in

"#!/usr/bin/env bash\n\nsed '\n\ts/://            # Drop colon\n\ts/^/Package: /   # Prepend with \"Package: \"\n\tN                # Append next line to pattern space\n\ts/\\n/ | New: /   # Replace newline with \" | New: \"\n\tN                # Append next line to pattern space\n\ts/\\n/ | Old: /   # Replace newline with \" | Old: \"\n' updates.txt\n"
That's a single long string, safely escaped to be used as a JSON string.

Now, to get that into a format we can use as payload in the API call:

jq --raw-input --slurp '{files: {myfile: {content: .}}}' myfile
which prints

{
  "files": {
    "myfile": {
      "content": "#!/usr/bin/env bash\n\nsed '\n\ts/://            # Drop colon\n\ts/^/Package: /   # Prepend with \"Package: \"\n\tN                # Append next line to pattern space\n\ts/\\n/ | New: /   # Replace newline with \" | New: \"\n\tN                # Append next line to pattern space\n\ts/\\n/ | Old: /   # Replace newline with \" | Old: \"\n' updates.txt\n"
    }
  }
}
or, for a public gist:

jq --raw-input --slurp '{public: true, files: {myfile: .}}' myfile
We can pipe this to curl and tell it to read the payload from standard input with @-:

jq --raw-input --slurp '{public: true, files: {myfile: .}}' myfile \
    | curl \
        https://api.github.com/gists \
        --header 'Accept: application/vnd.github.v3+json' \
        --header "Authorization: token $(< ~/.token)" \
        --data @-
This uses a personal access token to authenticate, which is expected to be in the file ~/.token.

If you use the GitHub CLI, it becomes a lot simpler:

gh gist create --public myfile
and done!
