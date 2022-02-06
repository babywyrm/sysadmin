###############################
###############################

    def _github(url: str, mode: str = "private"):
        url = url.replace("/blob/", "/")
        url = url.replace("/raw/", "/")
        url = url.replace("github.com/", "raw.githubusercontent.com/")

        if mode == "public":
            return requests.get(url)
        else:
            token = os.getenv('GITHUB_TOKEN', '...')
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3.raw'}
            return requests.get(url, headers=headers)
         
###############################
###############################

import numpy as np

import pandas as pd
import requests
from io import StringIO

# Create CSV file
df = pd.DataFrame(np.random.randint(2,size=10_000).reshape(1_000,10))
df.to_csv('filename.csv') 

# -> now upload file to private github repo

# define parameters for a request
token = 'paste-there-your-personal-access-token' 
owner = 'repository-owner-name'
repo = 'repository-name-where-data-is-stored'
path = 'filename.csv'

# send a request
r = requests.get(
    'https://api.github.com/repos/{owner}/{repo}/contents/{path}'.format(
    owner=owner, repo=repo, path=path),
    headers={
        'accept': 'application/vnd.github.v3.raw',
        'authorization': 'token {}'.format(token)
            }
    )

# convert string to StringIO object
string_io_obj = StringIO(r.text)

# Load data to df
df = pd.read_csv(string_io_obj, sep=",", index_col=0)

# optionally write df to CSV
df.to_csv("file_name_02.csv")

###############################
###############################

  import json, requests, urllib, io

    user='my_github_username'
    pao='my_pao'

    github_session = requests.Session()
    github_session.auth = (user, pao)

    # providing raw url to download csv from github
    csv_url = 'https://raw.githubusercontent.com/user/repo/master/csv_name.csv'

    download = github_session.get(csv_url).content
    downloaded_csv = pandas.read_csv(io.StringIO(download.decode('utf-8')), error_bad_lines=False)
    
###############################
###############################    


