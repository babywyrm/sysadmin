
#########
#########

##
##

from requests import async
# If using requests > v0.13.0, use
# from grequests import async

urls = [
    'http://python-requests.org',
    'http://httpbin.org',
    'http://python-guide.org',
    'http://kennethreitz.com'
]

# A simple task to do to each response object
def do_something(response):
    print response.url

# A list to hold our things to do via async
async_list = []

for u in urls:
    # The "hooks = {..." part is where you define what you want to do
    # 
    # Note the lack of parentheses following do_something, this is
    # because the response will be used as the first argument automatically
    action_item = async.get(u, hooks = {'response' : do_something})

    # Add the task to our list of things to do via async
    async_list.append(action_item)

# Do our list of things to do via async
async.map(async_list)

##

import grequests

urls = [
    'http://www.heroku.com',
    'http://tablib.org',
    'http://httpbin.org',
    'http://python-requests.org',
    'http://kennethreitz.com'
]

rs = (grequests.get(u) for u in urls)


##

import requests
import concurrent.futures

def get_urls():
    return ["url1","url2"]

def load_url(url, timeout):
    return requests.get(url, timeout = timeout)

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:

    future_to_url = {executor.submit(load_url, url, 10): url for url in     get_urls()}
    for future in concurrent.futures.as_completed(future_to_url):
        url = future_to_url[future]
        try:
            data = future.result()
        except Exception as exc:
            resp_err = resp_err + 1
        else:
            resp_ok = resp_ok + 1

            
##


import asyncio

loop = asyncio.get_event_loop()

def do_thing(params):
    async def get_rpc_info_and_do_chores(id):
        # do things
        response = perform_grpc_call(id)
        do_chores(response)

    async def get_httpapi_info_and_do_chores(id):
        # do things
        response = requests.get(URL)
        do_chores(response)

    async_tasks = []
    for element in list(params.list_of_things):
       async_tasks.append(loop.create_task(get_chan_info_and_do_chores(id)))
       async_tasks.append(loop.create_task(get_httpapi_info_and_do_chores(ch_id)))

    loop.run_until_complete(asyncio.gather(*async_tasks))
    
######

import asyncio

@asyncio.coroutine
def greet_every_two_seconds():  
    while True:
        print('Hello World')
        yield from asyncio.sleep(2)
        print('After back from sleep')

loop = asyncio.get_event_loop()  
loop.run_until_complete(greet_every_two_seconds())

######

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
    
#####


# http://geekgirl.io/concurrent-http-requests-with-python3-and-asyncio/

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
    
    
    
#########
##
##


