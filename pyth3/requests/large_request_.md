Download large file in python with requests

#
##
https://stackoverflow.com/questions/16694907/download-large-file-in-python-with-requests/16696317#16696317
##
#

Asked 9 years, 7 months ago
Modified 1 month ago
Viewed 530k times

Report this ad

572


Requests is a really nice library. I'd like to use it for downloading big files (>1GB). The problem is it's not possible to keep whole file in memory; I need to read it in chunks. And this is a problem with the following code:

```
import requests

def DownloadFile(url)
    local_filename = url.split('/')[-1]
    r = requests.get(url)
    f = open(local_filename, 'wb')
    for chunk in r.iter_content(chunk_size=512 * 1024): 
        if chunk: # filter out keep-alive new chunks
            f.write(chunk)
    f.close()
    return 
    
```

For some reason it doesn't work this way; it still loads the response into memory before it is saved to a file.

pythondownloadstreampython-requests
Share
Improve this question
Follow
edited May 19 at 22:15
user17242583
asked May 22, 2013 at 14:47
Roman Podlinov's user avatar
Roman Podlinov
22.7k77 gold badges3939 silver badges5959 bronze badges
Add a comment
8 Answers
Sorted by:

Highest score (default)

910


With the following streaming code, the Python memory usage is restricted regardless of the size of the downloaded file:
```
def download_file(url):
    local_filename = url.split('/')[-1]
    # NOTE the stream=True parameter below
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192): 
                # If you have chunk encoded response uncomment if
                # and set chunk_size parameter to None.
                #if chunk: 
                f.write(chunk)            
    return local_filename
```

Note that the number of bytes returned using iter_content is not exactly the chunk_size; it's expected to be a random number that is often far bigger, and is expected to be different in every iteration.

See body-content-workflow and Response.iter_content for further reference.

Share
Improve this answer
Follow
edited Jan 14, 2021 at 19:02
Jenia's user avatar
Jenia
35411 gold badge44 silver badges1515 bronze badges
answered May 22, 2013 at 15:52
Roman Podlinov's user avatar
Roman Podlinov
22.7k77 gold badges3939 silver badges5959 bronze badges
9
@Shuman As I see you resolved the issue when switched from http:// to https:// (github.com/kennethreitz/requests/issues/2043). Can you please update or delete your comments because people may think that there are issues with the code for files bigger 1024Mb – 
Roman Podlinov
 May 14, 2014 at 18:15
15
the chunk_size is crucial. by default it's 1 (1 byte). that means that for 1MB it'll make 1 milion iterations. docs.python-requests.org/en/latest/api/… – 
Eduard Gamonal
 Mar 25, 2015 at 13:06
13
@RomanPodlinov: f.flush() doesn't flush data to physical disk. It transfers the data to OS. Usually, it is enough unless there is a power failure. f.flush() makes the code slower here for no reason. The flush happens when the correponding file buffer (inside app) is full. If you need more frequent writes; pass buf.size parameter to open(). – 
jfs
 Sep 28, 2015 at 19:08 
5
if chunk: # filter out keep-alive new chunks – it is redundant, isn't it? Since iter_content() always yields string and never yields None, it looks like premature optimization. I also doubt it can ever yield empty string (I cannot imagine any reason for this). – 
y0prst
 Feb 27, 2016 at 5:35
6
@RomanPodlinov And one more point, sorry :) After reading iter_content() sources I've concluded that it cannot ever yield an empty string: there are emptiness checks everywhere. The main logic here: requests/packages/urllib3/response.py. – 
y0prst
 May 21, 2016 at 6:59 
Show 35 more comments

Report this ad

487


It's much easier if you use Response.raw and shutil.copyfileobj():

import requests
import shutil

def download_file(url):
    local_filename = url.split('/')[-1]
    with requests.get(url, stream=True) as r:
        with open(local_filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

    return local_filename
This streams the file to disk without using excessive memory, and the code is simple.

Note: According to the documentation, Response.raw will not decode gzip and deflate transfer-encodings, so you will need to do this manually.

Share
Improve this answer
Follow
edited Oct 28 at 11:31
Shiva's user avatar
Shiva
2,4122323 silver badges3030 bronze badges
answered Aug 30, 2016 at 2:13
John Zwinck's user avatar
John Zwinck
231k3333 gold badges313313 silver badges425425 bronze badges
19
Note that you may need to adjust when streaming gzipped responses per issue 2155. – 
ChrisP
 Sep 29, 2016 at 1:15 
72
THIS should be the correct answer! The accepted answer gets you up to 2-3MB/s. Using copyfileobj gets you to ~40MB/s. Curl downloads (same machines, same url, etc) with ~50-55 MB/s. – 
visoft
 Jul 12, 2017 at 7:05
5
A small caveat for using .raw is that it does not handle decoding. Mentioned in the docs here: docs.python-requests.org/en/master/user/quickstart/… – 
Eric Cousineau
 Dec 17, 2017 at 1:03
8
@EricCousineau You can patch up this behaviour replacing the read method: response.raw.read = functools.partial(response.raw.read, decode_content=True) – 
Nuno André
 Jan 27, 2019 at 12:39
5
Adding length param got me better download speeds shutil.copyfileobj(r.raw, f, length=16*1024*1024) – 
citynorman
 Feb 7, 2020 at 22:27
Show 20 more comments

101


Not exactly what OP was asking, but... it's ridiculously easy to do that with urllib:

from urllib.request import urlretrieve

url = 'http://mirror.pnl.gov/releases/16.04.2/ubuntu-16.04.2-desktop-amd64.iso'
dst = 'ubuntu-16.04.2-desktop-amd64.iso'
urlretrieve(url, dst)
Or this way, if you want to save it to a temporary file:

from urllib.request import urlopen
from shutil import copyfileobj
from tempfile import NamedTemporaryFile

url = 'http://mirror.pnl.gov/releases/16.04.2/ubuntu-16.04.2-desktop-amd64.iso'
with urlopen(url) as fsrc, NamedTemporaryFile(delete=False) as fdst:
    copyfileobj(fsrc, fdst)
I watched the process:

watch 'ps -p 18647 -o pid,ppid,pmem,rsz,vsz,comm,args; ls -al *.iso'
And I saw the file growing, but memory usage stayed at 17 MB. Am I missing something?

Share
Improve this answer
Follow
edited Jun 1 at 0:30
Gringo Suave's user avatar
Gringo Suave
28.7k66 gold badges8484 silver badges7575 bronze badges
answered Jun 5, 2017 at 22:13
x-yuri's user avatar
x-yuri
14.9k1313 gold badges103103 silver badges151151 bronze badges
2
For Python 2.x, use from urllib import urlretrieve – 
Vadim Kotov
 Apr 9, 2018 at 14:19
1
This function "might become deprecated at some point in the future." cf. docs.python.org/3/library/urllib.request.html#legacy-interface – 
Wok
 Apr 8 at 11:28
Add a comment

Report this ad

45


Your chunk size could be too large, have you tried dropping that - maybe 1024 bytes at a time? (also, you could use with to tidy up the syntax)

```
def DownloadFile(url):
    local_filename = url.split('/')[-1]
    r = requests.get(url)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024): 
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
    return 
Incidentally, how are you deducing that the response has been loaded into memory?

It sounds as if python isn't flushing the data to file, from other SO questions you could try f.flush() and os.fsync() to force the file write and free memory;

    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024): 
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
                

```
Community's user avatar
CommunityBot
111 silver badge
answered May 22, 2013 at 15:02
danodonovan's user avatar
danodonovan
19.1k88 gold badges7171 silver badges7676 bronze badges
1
I use System Monitor in Kubuntu. It shows me that python process memory increases (up to 1.5gb from 25kb). – 
Roman Podlinov
 May 22, 2013 at 15:22 
That memory bloat sucks, maybe f.flush(); os.fsync() might force a write an memory free. – 
danodonovan
 May 22, 2013 at 15:39
2
it's os.fsync(f.fileno()) – 
sebdelsol
 Oct 10, 2014 at 23:40
34
You need to use stream=True in the requests.get() call. That's what's causing the memory bloat. – 
Hut8
 May 10, 2015 at 21:59
1
minor typo: you miss a colon (':') after def DownloadFile(url) – 
Aubrey
 Jan 4, 2017 at 15:43
Show 1 more comment


##
##


Based on the Roman's most upvoted comment above, here is my implementation, Including "download as" and "retries" mechanism:

def download(url: str, file_path='', attempts=2):
    """Downloads a URL content into a file (with large file support by streaming)

    :param url: URL to download
    :param file_path: Local file name to contain the data downloaded
    :param attempts: Number of attempts
    :return: New file path. Empty string if the download failed
    """
    if not file_path:
        file_path = os.path.realpath(os.path.basename(url))
    logger.info(f'Downloading {url} content to {file_path}')
    url_sections = urlparse(url)
    if not url_sections.scheme:
        logger.debug('The given url is missing a scheme. Adding http scheme')
        url = f'http://{url}'
        logger.debug(f'New url: {url}')
    for attempt in range(1, attempts+1):
        try:
            if attempt > 1:
                time.sleep(10)  # 10 seconds wait time between downloads
            with requests.get(url, stream=True) as response:
                response.raise_for_status()
                with open(file_path, 'wb') as out_file:
                    for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB chunks
                        out_file.write(chunk)
                logger.info('Download finished successfully')
                return file_path
        except Exception as ex:
            logger.error(f'Attempt #{attempt} failed with error: {ex}')
    return ''
    
Share
Improve this answer
Follow
answered Jul 5, 2020 at 17:15
Ben Moskovitch's user avatar
Ben Moskovitch
13622 silver badges44 bronze badges
Add a comment

0
```

requests is good, but how about socket solution?
def stream_(host):
    import socket
    import ssl
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        context = ssl.create_default_context(Purpose.CLIENT_AUTH)
        with context.wrap_socket(sock, server_hostname=host) as wrapped_socket:
            wrapped_socket.connect((socket.gethostbyname(host), 443))
            wrapped_socket.send(
                "GET / HTTP/1.1\r\nHost:thiscatdoesnotexist.com\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\r\n".encode())

            resp = b""
            while resp[-4:-1] != b"\r\n\r":
                resp += wrapped_socket.recv(1)
            else:
                resp = resp.decode()
                content_length = int("".join([tag.split(" ")[1] for tag in resp.split("\r\n") if "content-length" in tag.lower()]))
                image = b""
                while content_length > 0:
                    data = wrapped_socket.recv(2048)
                    if not data:
                        print("EOF")
                        break
                    image += data
                    content_length -= len(data)
                with open("image.jpeg", "wb") as file:
                    file.write(image)


```

Share
Improve this answer
Follow
answered Oct 2, 2021 at 19:19
r1v3n's user avatar
r1v3n
40444 silver badges99 bronze badges
2
I'm curious what's the advantange of using this instead of a higher level (and well tested) method from libs like requests? – 
tuxillo
 Apr 21 at 22:18
2
Libs like requests are full of abstraction above the native sockets. That's not the best algorithm, but it could be faster because of no abstraction at all. – 
r1v3n
 May 7 at 21:00
Add a comment

0


Here is additional approach for the use-case of async chunked download, without reading all the file content to memory.
It means that both read from the URL and the write to file are implemented with asyncio libraries (aiohttp to read from the URL and aiofiles to write the file).

The following code should work on Python 3.7 and later.
Just edit SRC_URL and DEST_FILE variables before copy and paste.

import aiofiles
import aiohttp
import asyncio

async def async_http_download(src_url, dest_file, chunk_size=65536):
    async with aiofiles.open(dest_file, 'wb') as fd:
        async with aiohttp.ClientSession() as session:
            async with session.get(src_url) as resp:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    await fd.write(chunk)

SRC_URL = "/path/to/url"
DEST_FILE = "/path/to/file/on/local/machine"

asyncio.run(async_http_download(SRC_URL, DEST_FILE))
Share
Improve this answer
