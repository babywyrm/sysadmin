
If you want to get the size of a response from a curl request, you can use the -w (write-out) option to display specific information about the request, including the size of the response. Here's an example:


```
curl -s -o /dev/null -w '%{size_download}\n' <URL>
```

Explanation of the options used:

-s: Silent mode, which suppresses the progress meter and other informational output.
-o /dev/null: Outputs the response body to /dev/null, so it won't be displayed.
-w '%{size_download}\n': Writes out the size of the downloaded data (response size) followed by a newline character.
Replace <URL> with the actual URL you want to make the request to.

This command will display the size of the downloaded content in bytes. If you want the size in kilobytes, you can modify the -w option like this:

bash
Copy code
curl -s -o /dev/null -w '%{size_download} KB\n' <URL>
Remember to replace <URL> with the actual URL you are testing.


##
##
```
https://github.com/egoist/curl-size/blob/master/main.sh

#!/bin/bash

getSizeByDownload() {
  echo `curl ${URL} -sL --write-out '%{size_download}' --output /dev/null`
}

humanlizeSize() {
  local SIZE=$1
  local KB=1024
  local MB=$(( KB * 1024 ))
  
  if (( SIZE > MB )); then
    echo "$(( SIZE / MB )) MB"
  elif (( SIZE > KB )); then
    echo "$(( SIZE / KB )) KB"
  else
    echo "$SIZE Bytes"
  fi
}

URL="$1"

if [ -z "$URL" ]; then
  echo "Please provide a valid URL."
  exit 1
fi

# by Content-Length in header
SIZE=`curl -sLI $URL | grep Content-Length | awk '{print $2}'`
SIZE=${SIZE//$'\r'}

# no Content-Length
# by downloading the whole file
if [ -z "$SIZE" ]; then
  echo "Be patient, downloading the file..."
  SIZE=$(getSizeByDownload)
  echo $(humanlizeSize $SIZE)
  exit
fi

echo $(humanlizeSize $SIZE)
```


##
##
