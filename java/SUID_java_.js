How to execute shell command in Javascript

##
##

I want to write a JavaScript function which will execute the system shell commands (ls for example) and return the value.

How do I achieve this?

javascriptshellcommand-line
Share
Improve this question
Follow
edited Sep 20, 2021 at 17:49
Pavel Fedotov's user avatar
Pavel Fedotov
51711 gold badge55 silver badges2020 bronze badges
asked Dec 10, 2009 at 10:54
Sunil Kumar Sahoo's user avatar
Sunil Kumar Sahoo
52.4k5454 gold badges177177 silver badges243243 bronze badges
5
where would you like to execute this command, on the client or on the server? – 
Jan Hančič
 Dec 10, 2009 at 10:56
8
Why did you choose the most disliked answer as the best answer? o.0 – 
André Levy
 Jun 27, 2018 at 0:02
For anyone who wants to execute a command on button click, check the next.js way here: stackoverflow.com/questions/71646984/… – 
user1506104
 Mar 29, 2022 at 20:19
Add a comment
15 Answers
Sorted by:

Highest score (default)

184


I'll answer assuming that when the asker said "Shell Script" he meant a Node.js backend JavaScript. Possibly using commander.js to use frame your code :)

You could use the child_process module from node's API. I pasted the example code below.

```
var exec = require('child_process').exec;

exec('cat *.js bad_file | wc -l',
    function (error, stdout, stderr) {
        console.log('stdout: ' + stdout);
        console.log('stderr: ' + stderr);
        if (error !== null) {
             console.log('exec error: ' + error);
        }
    });

```
Share
Improve this answer
Follow
edited Dec 23, 2022 at 9:04
starball's user avatar
starball
3,59655 gold badges1717 silver badges3232 bronze badges
answered Dec 17, 2013 at 15:33
Josh's user avatar
Josh
1,97711 gold badge1111 silver badges55 bronze badges
21
Except for one thing. You'll get the error "child is not a function". The call to exec() executes the command - no need to call child(). Unfortunately, the callback isn't called whenever the child process has something to output - it is called only when the child process exits. Sometimes that's OK and sometimes it's not. – 
John Deighan
 Apr 26, 2016 at 12:52
7
To avoid callbacks, you can use execSync. – 
Dan Dascalescu
 Sep 30, 2018 at 6:10
3
Who talked about a browser ? It only says JavaScript, nothing more. – 
Virus721
 Mar 10, 2020 at 9:14
@Josh How to pass credentials here (user name and password)? – 
Shabar
 Dec 11, 2022 at 9:51
Add a comment

118


I don't know why the previous answers gave all sorts of complicated solutions. If you just want to execute a quick command like ls, you don't need async/await or callbacks or anything. Here's all you need - execSync:

const execSync = require('child_process').execSync;
// import { execSync } from 'child_process';  // replace ^ if using ES modules

const output = execSync('ls', { encoding: 'utf-8' });  // the default is 'buffer'
console.log('Output was:\n', output);
For error handling, add a try/catch block around the statement.

If you're running a command that takes a long time to complete, then yes, look at the asynchronous exec function.

Share
Improve this answer
Follow
edited Dec 25, 2021 at 7:05
Alex Hurst's user avatar
Alex Hurst
17488 bronze badges
answered Sep 30, 2018 at 6:06
Dan Dascalescu's user avatar
Dan Dascalescu
136k5050 gold badges309309 silver badges395395 bronze badges
3
Does execSync works with Mac, Linux and Windows commands? – 
Naazneen Jatu
 Sep 11, 2020 at 15:15
Confirmed for windows. Also, I see that there's a shell option for specifying "Shell to execute the command with." Default: '/bin/sh' on Unix, process.env.ComSpec on Windows. – 
Kerry Randolph
 Jun 18, 2021 at 20:44
Please do not use synchronous external operations, because your server will not be able to serve other requests until it is finished. – 
sarkiroka
 Jun 16, 2022 at 7:58
Add a comment

67


...few year later...

ES6 has been accepted as a standard and ES7 is around the corner so it deserves updated answer. We'll use ES6+async/await with nodejs+babel as an example, prerequisites are:

nodejs with npm
babel
Your example foo.js file may look like:
```
import { exec } from 'child_process';

/**
 * Execute simple shell command (async wrapper).
 * @param {String} cmd
 * @return {Object} { stdout: String, stderr: String }
 */
async function sh(cmd) {
  return new Promise(function (resolve, reject) {
    exec(cmd, (err, stdout, stderr) => {
      if (err) {
        reject(err);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

async function main() {
  let { stdout } = await sh('ls');
  for (let line of stdout.split('\n')) {
    console.log(`ls: ${line}`);
  }
}
```
main();
Make sure you have babel:

npm i babel-cli -g
Install latest preset:

npm i babel-preset-latest
Run it via:

babel-node --presets latest foo.js
Share
Improve this answer
Follow
edited Oct 11, 2016 at 13:24
answered Aug 8, 2015 at 19:48
Mirek Rusin's user avatar
Mirek Rusin
18.5k33 gold badges4343 silver badges3636 bronze badges
5
If you only need to execute a quick command, all the async/await is overkill. You can just use execSync. – 
Dan Dascalescu
 Sep 30, 2018 at 6:10
2
No one asked for a Node.js solution. It only says JavaScript. – 
Virus721
 Mar 10, 2020 at 9:13
5
@Virus721: in which JavaScript runtime do you want to execute a shell command? – 
Dan Dascalescu
 Aug 17, 2021 at 19:43
Add a comment

29


This depends entirely on the JavaScript environment. Please elaborate.

For example, in Windows Scripting, you do things like:

var shell = WScript.CreateObject("WScript.Shell");
shell.Run("command here");
Share
Improve this answer
Follow
answered Dec 10, 2009 at 10:58
Matt's user avatar
Matt
43.1k66 gold badges9696 silver badges101101 bronze badges
20
Is it possible to do the same thing in a Unix-like operating system such as Linux? – 
Anderson Green
 Sep 5, 2012 at 16:21
6
That's what I was looking for. It's annoying all those people talking about their Node.js. Who asked for Node.js here ? No one did. – 
Virus721
 Mar 10, 2020 at 9:12
Add a comment

20


In a nutshell:
```
// Instantiate the Shell object and invoke its execute method.
var oShell = new ActiveXObject("Shell.Application");

var commandtoRun = "C:\\Winnt\\Notepad.exe";
if (inputparms != "") {
  var commandParms = document.Form1.filename.value;
}

// Invoke the execute method.  
oShell.ShellExecute(commandtoRun, commandParms, "", "open", "1");

```







With NodeJS is simple like that! And if you want to run this script at each boot of your server, you can have a look on the forever-service application!

var exec = require('child_process').exec;

exec('php main.php', function (error, stdOut, stdErr) {
    // do what you want!
});
Share
Improve this answer
Follow
answered Dec 7, 2016 at 2:31
keupsonite's user avatar
keupsonite
38933 silver badges1515 bronze badges
1
To avoid callbacks, for quick commands you can use execSync. – 
Dan Dascalescu
 Sep 30, 2018 at 6:09
what if want to run sudo  mysql .?? is it possible ?? if yes, how the password, it is going to ask after this command. – 
Aman Deep
 Sep 8, 2021 at 16:21
Add a comment

```


function exec(cmd, handler = function(error, stdout, stderr){console.log(stdout);if(error !== null){console.log(stderr)}})
{
    const childfork = require('child_process');
    return childfork.exec(cmd, handler);
}
This function can be easily used like:

exec('echo test');
//output:
//test

exec('echo test', function(err, stdout){console.log(stdout+stdout+stdout)});
//output:
//testtesttest
```
Share
Improve this answer
Follow
answered Apr 27, 2019 at 17:25
AliFurkan's user avatar
AliFurkan
45744 silver badges1111 bronze badges
Add a comment

5


Here is simple command that executes ifconfig shell command of Linux

var process = require('child_process');
process.exec('ifconfig',function (err,stdout,stderr) {
    if (err) {
        console.log("\n"+stderr);
    } else {
        console.log(stdout);
    }
});
Share
Improve this answer
Follow
edited Jan 17, 2017 at 16:43
Piotr Wittchen's user avatar
Piotr Wittchen
3,73544 gold badges2727 silver badges3535 bronze badges
answered Sep 16, 2015 at 8:06
Anup Panwar's user avatar
Anup Panwar
29333 silver badges1111 bronze badges
To avoid callbacks, you can use execSync. – 
Dan Dascalescu
 Sep 30, 2018 at 6:07
Add a comment

3


If you are using npm you can use the shelljs package

To install: npm install [-g] shelljs

var shell = require('shelljs');
shell.ls('*.js').forEach(function (file) {
// do something
});
See more: https://www.npmjs.com/package/shelljs

Share
Improve this answer
Follow
answered May 4, 2020 at 4:55
Emma's user avatar
Emma
14922 silver badges88 bronze badges
Add a comment

2


Another post on this topic with a nice jQuery/Ajax/PHP solution:

shell scripting and jQuery

Share
Improve this answer
Follow
edited May 23, 2017 at 11:47
Community's user avatar
CommunityBot
111 silver badge
answered Apr 5, 2012 at 18:37
August's user avatar
August
68833 gold badges1212 silver badges2020 bronze badges
the question specifies javascript. – 
Inigo
 Dec 13, 2021 at 18:09
Add a comment

2


In IE, you can do this :

var shell = new ActiveXObject("WScript.Shell");
shell.run("cmd /c dir & pause");
Share
Improve this answer
Follow
answered Mar 21, 2014 at 7:18
nonozor's user avatar
nonozor
82022 gold badges1313 silver badges2424 bronze badges
ActiveXObject is available only for IE browser. – 
Inigo
 Dec 13, 2021 at 18:10
Add a comment

1


With nashorn you can write a script like this:

$EXEC('find -type f');
var files = $OUT.split('\n');
files.forEach(...
...
