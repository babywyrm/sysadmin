#!/bin/env python3

##
## https://gist.github.com/kwk/c89b6a3e5eb40487fed78f226e982fcc
##

import argparse
import datetime
import os
from string import Template
import requests
from pprint import pprint
import logging
import contextlib
from http.client import HTTPConnection


class IssueComment:
    """
    An IssueComment defines the minimum information we need from a comment.
    """

    def __init__(
            self,
            id: str,
            body: str,
            url: str,
            author: str,
            issue_id: str) -> None:
        self._id = id
        self._body = body
        self._url = url
        self._author = author
        self._issue_id = issue_id

    @property
    def id(self) -> str:
        return self._id

    @property
    def body(self) -> str:
        return self._body

    @property
    def url(self) -> str:
        return self._url

    @property
    def author(self) -> str:
        return self._author

    @property
    def issue_id(self) -> str:
        return self._issue_id


class GithubGraphQL:
    """
    The GithubGraphQL class helps performing tasks against the github GraphQL API.

    For Github's GraphQL API, see
    https://docs.github.com/en/github-ae@latest/graphql/reference

    For finding information by global id in github see:
    https://docs.github.com/en/graphql/guides/using-global-node-ids#2-find-the-object-type-in-graphql

    For the GraphQL explorer:
    https://docs.github.com/en/graphql/overview/explorer
    """

    def __init__(self, token: str, verbose: bool = False) -> None:
        """
        :param str token: the github access token to use
        :param bool verbose: whether to print debug information (DANGER: prints secret tokens!)
        """
        self.__token = token
        self.__verbose = verbose

        if self.__verbose:
            # Enable logging (see: https://stackoverflow.com/a/24588289)
            HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def __run_query(self, query: str, variables: dict) -> dict:
        """
        Runs a GraphQL query against the Github GraphQL API and return the result as a dictionary.
        The variables are meant to act as placeholders in the query.

        :param str query: the GraphQL query to run (can be query or mutation)
        :param dict variables: the variables to pass to the query
        """
        headers = {
            'Authorization': 'Bearer %s' % self.__token,
            # See
            # https://github.blog/2021-11-16-graphql-global-id-migration-update/
            'X-Github-Next-Global-ID': '1'
        }

        request = requests.post(
            'https://api.github.com/graphql',
            json={
                'query': query,
                'variables': variables},
            headers=headers)
        if request.status_code == 200:
            return request.json()
        else:
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query))

    def get_pr_id(self, owner: str, repo: str, pr_num: int) -> str:
        """
        Returns the global ID of a pull request.
        This is needed when adding a comment to a pull request for example.

        :param str owner: the owner of the repository
        :param str repo: the name of the repository
        :param int pr_num: the number of the pull request
        """
        query = """
            query($owner: String!, $reponame: String!, $pr_id: Int!) {
                repository(owner: $owner, name:$reponame) {
                    pullRequest(number: $pr_id) {
                        id
                    }
                }
            }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'pr_id': pr_num
        }
        res = self.__run_query(query=query, variables=variables)
        return res['data']['repository']['pullRequest']['id']

    def add_issue_comment(
            self,
            issue_node_id: str,
            comment_body: str) -> IssueComment:
        """
        Adds a comment to the globally identified issue / pull request and returns the id of the newly added comment.

        :param str issue_node_id: the id of the issue or pull request to add the comment to
        :param str comment_body: the body of the comment to add
        """
        query = """
            mutation($issue_node_id:String!, $comment_body:String!) {
                addComment(input: {
                    subjectId: $issue_node_id,
                    body: $comment_body
                }) {
                    commentEdge {
                        node {
                            id
                        }
                    }
                }
            }
        """
        variables = {
            'issue_node_id': issue_node_id,
            'comment_body': comment_body
        }
        res = self.__run_query(query=query, variables=variables)
        return IssueComment(
            issue_id=res['data']['addComment']['commentEdge']['node']['id'])

    def get_comment(self, comment_id: str) -> IssueComment:
        """
        Returns the comment body, author, URL and issue ID for a given global comment ID.

        :param str comment_id: the id of the comment to get
        """
        query = """
            query($comment_id:String!) {
                node(id: $comment_id) {
                    ... on IssueComment {
                        id
                        body
                        url
                        author {
                            login
                        }
                        issue {
                            id
                        }
                    }
                }
            }
        """
        variables = {
            'comment_id': comment_id
        }
        res = self.__run_query(query=query, variables=variables)
        return IssueComment(
            id=res['data']['node']['id'],
            body=res['data']['node']['body'],
            url=res['data']['node']['url'],
            author=res['data']['node']['author']['login'],
            issue_id=res['data']['node']['issue']['id']
        )




##
##
