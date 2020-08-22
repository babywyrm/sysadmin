### HTTP Basics
##### Excerise #2
- Solution: Inpect Post request in dev tools and you will see magic number at bottom with the post data.

### SQL Lesson 
##### String injection
- Goal: Return all users from the user table in the db via string injection
- Enter Smith will give you single record
- Solution: ```Fart' OR '1'='1```
- The above will return all users in the db even though their is no user named Fart. This is because every record will return with a true value hence the OR statement('1'='1 or true), therefore return the whole users table.

##### Numeric Injection
- Goal: Return all users from the user table in the db via numeric injection
- Much like string injection, want to force a TRUE statement on the user table
- Solution: ```101 OR TRUE```

##### SQL Injection Advanced
- Goal: Query user_system_data to reteive daves password
- Solution: Chaining ```Dave'; select * from user_system_data;--```
- The ; allows you to chain queries

### XSS

##### XSS Reflected
- Goal: Identify which field is susceptible to XSS
- Solution: drop a script tag in each field. The access code field is vulnerable ```<script>alert('hello')</script>```
- Note: Solution passes but most browsers protect from alert being executed, so you won't see the alert message.

##### XSS Stored
- Goal: Add a comment with a javascript payload invoking the webgoat.customjs.phoneHome function
- Solution: Thad<script>webgoat.customjs.phoneHome()</script>. Inspect post request response and input random number sent from the server.

### Access Control Flaws
- Goal #3: List two attributes that are in the server response and not displayed on the website. Make sure you are logged in as user: tom pass: cat in the step before.
- Solution: Click on view profile button and inspect the server respose. You will see two attributes not displayed on the screen (role, userId).

#### Missing function level access control
- Goal: Find two links that are not in the menu
- Solution: Inspect the menu and look for hidden elements. You will find a hidden section with two links (Users, Config)
