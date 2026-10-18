# SecNotes' 2nd order SQL injection
##
##


##
#
https://infosecwriteups.com/the-wrath-of-second-order-sql-injection-c9338a51c6d
#
##


What is a Second-Order SQL Injection and how can you exploit it successfully?
Second-Order SQL Injection with a demonstration
Fiddly Cookie
InfoSec Write-ups

Fiddly Cookie
·

Follow
Published in

InfoSec Write-ups
·
7 min read
·
Jan 24, 2019

Credit: pixabay.com
What is SQL Injection

SQL Injection — the process of injecting SQL language code within data requests that result in application backend database server either surrendering confidential data or cause the execution of malicious scripting content on the database that could result in a complete compromise of the host.
Understanding Second-Order Code Injection

Imagine a scenario wherein a malicious code injected into an application by an attacker which does not get immediately get executed in the application.
Yes, you read that right. It’s a familiar story and it usually goes like this, user-provided data becomes a threat when it is utilized by the application or any other application wherein the injected code provided by the attacker gets activated resulting in successful exploitation.

First -order and Second-order SQL Injection differ primarily in the way that the attacker can simply enter a malicious string and cause the modified code to be executed immediately.

See the difference?

The attacker injects into persistent storage (such as a table row) which is deemed as a trusted source. An attack is subsequently executed by another activity.
Credit: portswigger.net
Testing Challenge

The attacking nature of common code injection allows an attacker to discover the vulnerability by observing the application response.

Testing for Second Order SQL Injection is slightly difficult because it requires the attacker to have the knowledge of backend operation of the application.

How can you beat that?

Automated web-application assessment tools are not adequate to identify these vulnerabilities. An automated tool is not smart enough to identify the change in application behavior in any of the subsequent responses caused by the malicious injection in one of the previous queries.
What makes an application vulnerable to Second-order SQL Injection

This kind of vulnerability happens because a good programmer maybe will patch his code to prevent SQL injections in forms where the user can input something BUT he will not do the same thing where a user doesn’t have any sort of interaction with the application database.
Exploit Scenario

A second-order SQL Injection, on the other hand, is a vulnerability exploitable in two different steps:

    Firstly, we STORE a particular user-supplied input value in the DB and
    Secondly, we use the stored value to exploit a vulnerability in a vulnerable function in the source code which constructs the dynamic query of the web application.

So let’s get down to business and look at how a vulnerable application could be exploited in more detail with the help of a hypothetical scenario:
Example 1

CREATE TABLE USERS ( userId serial PRIMARY KEY, firstName TEXT )

Suppose you have some SAFE code like this, receiving firstName from a form:

$firstname = someEscapeFunction($_POST[“firstName”]);$SQL = “INSERT INTO USERS (firstname) VALUES (‘{$firstName }’);”;someConnection->execute($SQL);

So far so good, assuming that someEscapeFunction() does a fine job. It isn’t possible to inject SQL. If I would now send my payload as a value for firstname, you wouldn’t mind:

Payload : bla’); DELETE FROM USERS; //

Now, suppose somebody on the same system wants to transport firstName from USERS to SOME, and does that like this:

$userid = 42; $SQL = “SELECT firstname FROM USERS WHERE (userId={$userid})”; $RS = con->fetchAll($SQL); $firstName = $RS[0][“firstName”];

And then inserts it into SOME table without escaping:

$SQL = “INSERT INTO SOME VALUES (‘{$firstName}’);”;

Malicious query becomes like this:

INSERT INTO SOME VALUES (‘ bla’); DELETE FROM USERS; //

At this point you realise that if the firstname contains some delete command, it will still be executed.
Example 2

It could be possible to exploit some functions that don’t need user input and uses data already saved in the DB, that retrieves when needed. The password reset functionality!

A victim user “User123” could be registered on the website with a very strong and secure password but we still really want to get his account. In a second order SQL Injection we should be able to do something like:

Register a new account. We want to name this new user as “User123' — “ and password “UserPass@123”

Payload: “User123' — “

Then we can reset our password and set a new one in the appropriate form.

The legit query will be:

$pwdreset = mysql_query(“UPDATE users SET password=’getrekt’ WHERE username=’User123' — ‘ and password=’UserPass@123'”);

BUT since — is the character used to comment in SQL, the query will result being this:

$pwdreset = mysql_query(“UPDATE users SET password=’getrekt’ WHERE username=’User123'”);

And boom! You’re there. This will set a new password chosen by us for the victim user account!
Demonstration

I was working on SecNotes machine on HTB and encountered a login form as shown in Figure 1. Gotta try SQL Injection, right? Duh! I tried inserting SQL injection queries in the login parameters but nothing showed up.
Figure 1

I created a user user123 and logged into the account wherein I could see some notes as shown in Figure 2 and Figure 3.
Figure 2
Figure 3

If we recall how SQL Injection exploits works, we STORE a particular value in the DB and the stored value becomes a part of the query in an unfiltered or bugged function in the source code of the web application.

What if the application is fetching the notes from the database using the username of the application. Let’s create a user with a username containing ‘ and hoping that we might encounter an SQL error
Figure 4

Woah! The server responds with 500 internal server error as shown in Figure 5. Once I was able to make the server respond with an error (mostly HTTP 500 status), I had to confirm that it is the SQL command that is causing the error and not something else.
Figure 5

I created an account with username ‘ or ‘asd’=’asd as shown in Figure 6. So, the username ‘ or ‘asd’=’asd gets STORED in the database.
Figure 6

Then, I logged into the account with the same username as shown in Figure 7.
Figure 7

Bingo! Now I was able to see three notes from the database as shown in Figure 8. It was confirmed that the heading was causing this 2nd order SQL injection vulnerability. The dynamic query that was constructed would look something like this,

SELECT * from notes WHERE username = ‘’ or ‘asd’ = ‘asd’;

Figure 8
Attack Probability

The success rate of identifying a classical (first-order) SQL Injection is common in comparison with the second-order SQL injection. The First-order Injections often referred to as ‘low hanging fruit’ can be observed directly whereas the relative probability of second-order SQL Injection is low.

The Second-order SQL Injection attack has to be performed “blind” in a majority of the cases because the attacker performs the attack on the backend functionality without any prior knowledge of the system.
Protection Against Second-Order SQL Injection

Use a white-list approach to sanitizing data (i.e. disallow everything by default, and explicitly enumerate data characters that are allowed or deemed “safe”).

Beware that data marked “SAFE” for one application may not be safe for another application/component.

    Each application that retrieves stored data (especially if the data is likely to have been supplied by users) must apply its own data sanitization processes before processing it further. Before any user-supplied data should undergo sanitization process before it is being processed further
    All data processed within and between the application components should be validated.

Language specific recommendations:

    Java EE — use PreparedStatement()
    .NET — use parameterized queries like SqlCommand() or OleDbCommand()
    PHP — use PDO with strongly typed parameterized queries (using bindParam())
    Hibernate — use createQuery() (called named parameters in Hibernate)
    SQLite — use sqlite3_prepare()

Now I’m going to stop right there and leave you to discover more about Second-order SQL Injection.

If you want to know more about advanced code injection and testing procedure, do check out this article.
References

https://www.owasp.org/index.php/SQL_Injection

https://portswigger.net/kb/issues/00100210_sql-injection-second-order

https://www.researchgate.net/publication/290768140_Detection_Method_of_the_Second-Order_SQL_Injection_in_Web_Applications

##
##


```
SQL injection (second order)
Description: SQL injection (second order)
SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.

A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server.

Second-order SQL injection arises when user-supplied data is stored by the application and later incorporated into SQL queries in an unsafe way. To detect the vulnerability, it is normally necessary to submit suitable data in one location, and then use some other application function that processes the data in an unsafe way.

Remediation: SQL injection (second order)
The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize every variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.

You should be aware that some commonly employed and recommended mitigations for SQL injection vulnerabilities are not always effective:

One common defense is to double up any single quotation marks appearing within user input before incorporating that input into a SQL query. This defense is designed to prevent malformed data from terminating the string into which it is inserted. However, if the data being incorporated into queries is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in which case only a space is required to break out of the data context and interfere with the query. Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted into the database is subsequently read from the database and then passed back to it again. Quotation marks that have been doubled up initially will return to their original form when the data is reused, allowing the defense to be bypassed.
Another often cited defense is to use stored procedures for database access. While stored procedures can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise if the procedure is invoked in an unsafe manner using user-controllable data.
References
Web Security Academy: SQL injection
Using Burp to Test for Injection Flaws
Web Security Academy: SQL Injection Cheat Sheet
Vulnerability classifications
CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
CWE-94: Improper Control of Generation of Code ('Code Injection')
CWE-116: Improper Encoding or Escaping of Output
CAPEC-66: SQL Injection
Typical severity
High
```

Type index (hex)
0x00100210

Type index (decimal)
1049104

##
##

0xdf explains how it [works here](https://0xdf.gitlab.io/2019/01/19/htb-secnotes.html) and IppSec covers it at the end of [his video](https://www.youtube.com/watch?v=PJXb2pK8K84). Here's my understanding of how it works. These PHP files are all found in **C:\inetpub\wwwroot**

Once you login to the Web app, these lines in [home.php](home.php) is run to retrieve the notes.

```php
$sql = "SELECT id, title, note, created_at FROM posts WHERE username = '" . $username . "'";
$res = mysqli_query($link, $sql);
```

Note for $username there is no checking whether $username contains SQL commands which will try to alter the statement. If you inject $username as `' or 1=1;` which you can [try here](https://www.w3schools.com/sql/trysql.asp?filename=trysql_select_where_number), everything gets retrieved with the query

```sql
SELECT * FROM Customers WHERE CustomerName = '' OR 1=1;
```

This is in contrast to [login.php](login.php) where we see lines like

```php
$sql = "SELECT username, password FROM users WHERE username = ?";
        
if($stmt = mysqli_prepare($link, $sql)){
```

where the username variable is being prepared undergoes **mysqli_prepare()**. What is **mysqli_prepare()**? This [answer](https://stackoverflow.com/questions/46159964/what-does-mysqli-prepare-really-do-why-should-it-be-called-by-user-and-not-hax) helps to explain it but the gist is

> The point of prepared statements is that the values/arguments/variables for the SQL query are send separated from the actual SQL query to the MySQL server. This way the values/arguments/variables cannot change the SQL query you are trying to send. This prevents SQL injections where the inputs contain values like `"='' OR 1 = 1 --"`.

Remember in SQL injection we are trying to modify the Web app's SQL statements so that it retrieves information it shouldn't be. But if the inputs are strictly treated as variables we can have a username like **' or 1=1;-- -** without it being mistaken as part of an SQL query. For more examples see the procedural-style ones [here](https://www.tutorialspoint.com/php/php_function_mysqli_stmt_execute.htm) and [here](https://www.php.net/manual/en/mysqli-stmt.execute.php).

Ok now let's see where the **$username** in home.php comes from and how it is handled for SQL injection checking. In login.php we see

```php
    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = 'Please enter username.';
    } else{
        $username = trim($_POST["username"]);
    }
```

where [trim() without arguments](https://www.w3schools.com/php/func_string_trim.asp) removes all the newlines and whitespaces and these HTML elements where $username is entered by POST requests

```html
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username"class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>    
```

In login.php once the password is verified, and the input clears the **mysqli_prepare()** statement above, it then sets the SESSION variable for **username**

```php
if(password_verify($password, $hashed_password)){
	/* Password is correct, so start a new session and
	save the username to the session */
	session_start();
	$_SESSION['username'] = $username;      
	header("location: home.php");
}
```

So the upshot is that any input for username like `'or 1=1;-- -` is treated as a username instead of modifying the SQL statements in login.php but since home.php doesn't use mysqli_prepare() it becomes possible to modify the SQL query there to retrieve everything.
