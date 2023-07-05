# SecNotes' 2nd order SQL injection
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
