import random, json
import os,sys,re

########
########

## edit the file count env lol
## how many files

count = int(os.getenv("FILE_COUNT") or 100)
words = [word.strip() for word in open('/usr/share/dict/words').readlines()]

for ident in range(count):
	amount = random.uniform(1.0, 1000.00)
	content = {
		'topic': random.choice(words),
		'value': "%.2f" % amount
	}
	with open (f'./new/receipt-{ident}.json', 'w') as f:
		json.dump(content, f)


##########################
##
##
