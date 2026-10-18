#http://geekgirl.io/concurrent-http-requests-with-python3-and-asyncio/

Concurrent HTTP Requests with Python3 and asyncio

My friend who is a data scientist had wipped up a script that made lots (over 27K) of queries to the Google Places API. The problem was that it was synchronous and thus took over 2.5hours to complete.

Given that I'm currently attending Hacker School and get to spend all day working on any coding problems that interests me, I decided to go about trying to optimise it.

I'm new to Python so had to do a bit of groundwork first to determine which course of action was best.

Initially I researched using Twisted, then someone told me that Requests allowed async HTTP calls. Lastly I considered the asyncio libraries that are just new to >=Python3.3. I had just heard about the asynio library a couple of days before because I paired on an asynchronous Python terminal chat app. Given that these asyncio libraries are actually now part of core, I felt this approach was the best way forward.

What is asyncio?
Well according to the docs:

This module provides infrastructure for writing single-threaded concurrent code using coroutines, multiplexing I/O access over sockets and other resources, running network clients and servers, and other related primitives.
Well ok, but what does all of that actually mean? Let's break this down:

single-threaded concurrent code using coroutines
One of nicest things about working with asyncio is that it uses an event loop which means that we don't need to worry about dealing with multiple threads. Threads result in context switching which can become prohibitively expensive. The event loop itself is by default single-threaded (it uses the main application thread).

Let's take a look at an example that uses coroutines.

import asyncio

@asyncio.coroutine
def greet_every_two_seconds():  
    while True:
        print('Hello World')
        yield from asyncio.sleep(2)
        print('After back from sleep')

loop = asyncio.get_event_loop()  
loop.run_until_complete(greet_every_two_seconds())  
In this example we create an event loop and tell it to keep running until the greet_every_two_seconds coroutine finishes. In this case it never will due to the while True infinite loop.

Without getting bogged down into details about how generators work, i'll just say that yield from waits until another coroutine (in this case asyncio.sleep()) returns a result. So for example, it won't print "After back from sleep" until asyncio.sleep(2) returns.

We can chain mutiple coroutine's together like so:

import asyncio

@asyncio.coroutine
def compute(x, y):  
    print("Compute %s + %s ..." % (x, y))
    yield from asyncio.sleep(1.0)
    return x + y

@asyncio.coroutine
def print_sum():  
    result = yield from compute(1, 2)
    print("%s + %s = %s" % (x, y, result))

loop = asyncio.get_event_loop()  
loop.run_until_complete(print_sum())  
loop.close()  
So to sum up, coroutines and yield from allows us to write concurrent code in a sequential manner.

What about concurrent HTTP requests?
multiplexing I/O access over sockets and other resources
Asyncio also allows us to make non-blocking calls to I/O. To achieve this, we will use a library called aiohttp.

$ pip3.4 install aiohttp (pip might be differnt for you)
Let's take a look at a simple example which attempts to concurrently fetch 100 urls.

import asyncio  
import aiohttp

def fetch_page(url, idx):  
    url = 'https://yahoo.com'
    response = yield from aiohttp.request('GET', url)

    if response.status == 200:
        print("data fetched successfully for: %d" % idx)
    else:
        print("data fetch failed for: %d" % idx)
        print(response.content, response.status)

def main():  
    url = 'https://yahoo.com'
    urls = [url] * 100

    coros = []
    for idx, url in enumerate(urls):
        coros.append(asyncio.Task(fetch_page(url, idx)))

    yield from asyncio.gather(*coros)

if __name__ == '__main__':  
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
What is this program doing?
1. It creates a list of 100 urls 
2. It then creates a new Task for each url and adds it to coros array 
3. asyncio.gather(*coros) executes each Task which is to fetch each page 
3. When asyncio.gather(*coros) returns (eg. all pages have been fetched) the program exits.

If you run this program you will see that the order of the asynio.Task coroutines is not sequential.

So we introduced two new concepts: 
1. asyncio.gather which returns when the list of futures/coroutines passed in all return. 
2. asynio.Task. A Task is a coroutine object wrapped in a future.

Using a combination of the asynio and aiohttp libraries I was able to reduce the running time of 27K API calls from over 2.5hours to aroun 7 minutes.

Asyncio Glossary
Coroutine 
* generator function which can receive values 
* decorated with @coroutine

Future 
* promise of a result/error

Task 
* Future which runs a coroutine
