# first: mkdir user && cd user && cp /path/to/get_gists.py .
# python3 get_gists.py user
import requests
import sys
from subprocess import call

user = sys.argv[1]

r = requests.get('https://api.github.com/users/{0}/gists'.format(user))

for i in r.json():
	call(['git', 'clone', i['git_pull_url']])

	description_file = './{0}/description.txt'.format(i['id'])
	with open(description_file, 'w') as f:
		f.write('{0}\n'.format(i['description']))
        
##
##
##############
##############

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

##
##
