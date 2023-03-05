#!/usr/bin/python3

##
##

"""
wm-docker-tags.py
~~~~~~~~~~~~~~~~~
Quick python script to try to get some visibility
into the Wikimedia Docker registry.
"""

import argparse
import json
import os
import re

import requests

class DockerRegistry(object):
    def __init__(self, url, version='v2'):
        self.registry = url
        self.version = version
        self._pagination_re = re.compile('<([^>]*)>')
        self.repos = self.get_repos()

    def _query_repo(self, endpoint):
        base_path = self.registry

        if not endpoint.startswith('v2'):
            base_path = os.path.join(self.registry, self.version)

        r = requests.get(os.path.join(base_path, endpoint))
        r.raise_for_status()
        return r

    def _page_repos(self, query, repos):
        response = self._query_repo(query)
        repos += response.json().get('repositories')

        # Docker registry paginates and sends continuation header 'Link'
        next_link = response.headers.get('link')
        if not next_link:
            return repos

        page = self._pagination_re.search(next_link)
        page = page.group(1)
        if page.startswith('/'):
            return self._page_repos(page[1:], repos)

        return self._page_repos(page, repos)

    def get_repos(self):
        repos = []
        return self._page_repos('_catalog', repos)

    def __getitem__(self, image):
        response = self._query_repo(os.path.join(image, 'tags', 'list'))
        return response.json()

def parse_args():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--repos', action='store_true')
    g.add_argument('--image-tags', metavar='IMAGE_NAME')
    return ap.parse_args()

def main():
    args = parse_args()
    registry = DockerRegistry('https://docker-registry.wikimedia.org')
    if args.repos:
        print('\n'.join(registry.repos))
        return 0
    tags = registry[args.image_tags]
    print('Tags for "{image_name}"\n---\n{image_tags}'.format(
        image_name=tags['name'],
        image_tags='\n'.join(tags['tags']),
    ))
    return 0

if __name__ == '__main__':
    main()
    
##########
##
##    
