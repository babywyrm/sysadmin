# MySQL



<h1>MYSQL CHEAT SHEET</h1>
<p>All the help you need to kick off your SQL journey</p>

<p>This gist doesn't teach you to download and install MYSQL, so I'm assuming you already have it installed</p>

<h2>LOGIN FROM TERMINAL</h2>
<div class="highlight highlight-source-shell">
<pre>mysql -u root -p</pre>
</div>

<h2>SHOW USERS</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">SELECT</span> User, Host <span class="pl-k">FROM</span> mysql.user;</pre>
</div>

<h2>CREATE A NEW USER</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">CREATE USER</span> 'johnDoe'@'localhost' <span class="pl-k">IDENTIFIED BY</span> 'somepassword';</pre>
</div>

<h2>GRANT ALL PRIVELEGES ON ALL DATABASES TO USER</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">GRANT ALL PRIVILEGES ON * . * TO</span> 'johnDoe'@'localhost';</pre>
</div>
<p>
  Here we granted the user permission to ALL the database functionalities, i.e CREATE, DELETE, INSERT, UPDATE, SELECT     etc. We could also decide what type of permission(s) we wish to grant a user;
</p>

<h2>GRANT PRIVELEGE(S) TO USER</h2>
<div class="highlight highlight-source-shell">
  <pre><span class="pl-k">GRANT SELECT, INSERT, DELETE ON *.* TO</span> 'johnDoe'@'localhost';</pre>
</div>
<p>
  Above is a sample syntax where only three privileges are granted to the user.
  <br>
  We then use the "FLUSH PRIVILEGES;" command In order for the changes to take effect and the privileges to be saved.
  <br>
  <hr>
  <strong>NOTE: </strong>All SQL commands must end in a semicolon ;
  <br>
  <hr>
  Here is a list of the MySQL privileges which are most commonly used:
  <ul>
    <li>ALL PRIVILEGES – grants all privileges to the MySQL user</li>
    <li>CREATE – allows the user to create databases and tables</li>
    <li>DROP - allows the user to drop databases and tables</li>
    <li>DELETE - allows the user to delete rows from specific MySQL table</li>
    <li>INSERT - allows the user to insert rows into specific MySQL table</li>
    <li>SELECT – allows the user to read the database</li>
    <li>UPDATE - allows the user to update table rows</li>
  </ul>
</p>

<h2>IN ORDER FOR THE CHANGES TO TAKE EFFECT</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">FLUSH PRIVILEGES;</span></pre>
</div>

<h2>SHOW GRANTS GIVEN TO A USER</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-sk">SHOW GRANTS FOR</span> 'johnDoe'@'localhost';</pre>
</div>

<h2>REMOVE GRANTS GIVEN TO USER</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">REVOKE ALL PRIVILEGES, GRANT OPTION FROM</span> 'someuser'@'localhost';</pre>
</div>

<h2>DELETE USER</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">DROP USER</span> 'johnDoe'@'localhost';</pre>
</div>

<h2>EXIT</h2>
<div class="highlight highlight-source-shell">
<pre>Exit;</pre>
</div>

<h2>LOGIN AS USER YOU CREATED</h2>
<div class="highlight highlight-source-shell">
<pre>mysql -u johnDoe -p</pre>
</div>

<h2>SHOW ALL DATABASE YOUR USER HAS</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">SHOW DATABASES;</span></pre>
</div>

<h2>CREATE A DATABASE</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">CREATE DATABASE</span> sql_class;</pre>
</div>

<h2>DELETE A DATABASE</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">DROP DATABASE</span> sql_class;</pre>
</div>

<h2>SELECT A DATABASE</h2>
<div class="highlight highlight-source-shell">
<pre><span class="pl-k">USE</span> sql_class;</pre>
</div>

<h2>CREATE TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">CREATE TABLE</span> users(
id <span class="pl-s">INT AUTO_INCREMENT</span>,
first_name <span class="pl-s">VARCHAR(100)</span>,
last_name <span class="pl-s">VARCHAR(100)</span>,
email <span class="pl-s">VARCHAR(50)</span>,
password <span class="pl-s">VARCHAR(20)</span>,
location <span class="pl-s">VARCHAR(100)</span>,
dept <span class="pl-s">VARCHAR(100)</span>,
is_admin <span class="pl-s">TINYINT(1)</span>,
register_date <span class="pl-s">DATETIME</span>,
<span class="pl-s">PRIMARY KEY(id)</span>
);
</pre>
</div>

<h2>DELETE TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">DROP TABLE</span> table_name;
</pre>
</div>

<h2>SHOW TABLES</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">SHOW TABLES</span>;
</pre>
</div>

<h2>INSERT ROW/RECORDS</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">INSERT INTO</span> users (first_name, last_name, email, password, location, dept, is_admin, register_date) <span class="pl-k">VALUES</span> (<span class="pl-s">'Justice', 'Eziefule', 'justice@gmail.com', '123456','Florida', 'development', 1, now()</span>);
</pre>
</div>

<h2>INSERT MULTIPLE ROW/RECORDS</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">INSERT INTO</span> users (first_name, last_name, email, password, location, dept, is_admin, register_date) <span class="pl-k">VALUES</span> (<span class="pl-s">'Fred', 'Smith', 'fred@gmail.com', '123456', 'New York', 'design', 0, now()</span>), (<span class="pl-s">'Sara', 'Watson', 'sara@gmail.com', '123456', 'New York', 'design', 0, now()</span>),(<span class="pl-s">'Will', 'Jackson', 'will@yahoo.com', '123456', 'London', 'development', 1, now()</span>),(<span class="pl-s">'Paula', 'Johnson', 'paula@yahoo.com', '123456', 'Massachusetts', 'sales', 0, now()</span>),(<span class="pl-s">'Tom', 'Spears', 'tom@yahoo.com', '123456', 'Manchester', 'sales', 0, now()</span>);
</pre>
</div>

<h2>SELECT ALL DATA FROM TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
<span class="pl-k">SELECT * FROM</span> users;
</pre>
<p><strong>*</strong> is a syntax that represents <strong>ALL</strong>
</div>

<h2>SELECT SPECIFIC DATA FROM TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
   SELECT first_name, last_name FROM users;
</pre>
<p>
 <pre>
  SELECT location FROM users;
</pre>
</p>
</div>

<h2>WHERE CLAUSE</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM users WHERE location='Massachusetts';
SELECT * FROM users WHERE location='Massachusetts' AND dept='sales';
SELECT * FROM users WHERE is_admin = 1;
SELECT * FROM users WHERE is_admin > 0;
</pre>
</div>

<h2>DELETE ROW</h2>
<div class="highlight highlight-source-shell">
<pre>
   DELETE FROM users WHERE id = 6;
</pre>
</div>


<h2>UPDATE ROW</h2>
<div class="highlight highlight-source-shell">
<pre>
   UPDATE users SET email = 'freddy@gmail.com' WHERE id = 2;
</pre>
</div>

<h2>ADD NEW COLUMN</h2>
<div class="highlight highlight-source-shell">
<pre>
 ALTER TABLE users ADD date_of_birth DATETIME;
</pre>
</div>

<h2>MODIFY COLUMN</h2>
<div class="highlight highlight-source-shell">
<pre>
 ALTER TABLE users MODIFY COLUMN date_of_birth DATE;
</pre>
</div>

<h2>DELETE ROW</h2>
<div class="highlight highlight-source-shell">
<pre>
DELETE FROM users WHERE id = 6;
</pre>
</div>

<h2>CONCATENATE COLUMNS</h2>
<p>With concatenate comes the AS syntax</p>
<div class="highlight highlight-source-shell">
<pre>
SELECT CONCAT(first_name, ' ', last_name) AS 'Name', dept FROM users;
</pre>
</div>

<h2>SELECT DISTINCT LOCATION</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT DISTINCT location FROM users;
</pre>
</div>

<h2>BETWEEN (SELECT RANGE)</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM users WHERE age BETWEEN 20 AND 25;
</pre>
</div>

<h2>LIKE (SEARCHING)</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM users WHERE dept LIKE 'd%';
SELECT * FROM users WHERE dept LIKE 'dev%';
SELECT * FROM users WHERE dept LIKE '%t';
SELECT * FROM users WHERE dept LIKE '%e%';
</pre>
</div>

<h2>NOT LIKE (SEARCHING)</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM users WHERE dept NOT LIKE 'd%';
</pre>
</div>

<h2>IN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM users WHERE dept IN ('design', 'sales');
</pre>
</div>

<h2>CREATE TABLE FOR posts</h2>
<div class="highlight highlight-source-shell">
<pre>
CREATE TABLE posts(
id INT AUTO_INCREMENT,
   user_id INT,
   title VARCHAR(100),
   body TEXT,
   publish_date DATETIME DEFAULT CURRENT_TIMESTAMP,
   PRIMARY KEY(id),
   FOREIGN KEY (user_id) REFERENCES users(id)
);
</pre>
</div>

<h2>ADD DATA TO posts</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO posts(user_id, title, body) VALUES (1, 'Post One', 'This is post one'),(3, 'Post Two', 'This is post two'),(1, 'Post Three', 'This is post three'),(2, 'Post Four', 'This is post four'),(5, 'Post Five', 'This is post five'),(4, 'Post Six', 'This is post six'),(2, 'Post Seven', 'This is post seven'),(1, 'Post Eight', 'This is post eight'),(3, 'Post Nine', 'This is post none'),(4, 'Post Ten', 'This is post ten');
</pre>
</div>

<h2>ADD DATA TO posts</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO posts(user_id, title, body) VALUES (1, 'Post One', 'This is post one'),(3, 'Post Two', 'This is post two'),(1, 'Post Three', 'This is post three'),(2, 'Post Four', 'This is post four'),(5, 'Post Five', 'This is post five'),(4, 'Post Six', 'This is post six'),(2, 'Post Seven', 'This is post seven'),(1, 'Post Eight', 'This is post eight'),(3, 'Post Nine', 'This is post none'),(4, 'Post Ten', 'This is post ten');
</pre>
</div>

<h2>INNER JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT
  users.first_name,
  users.last_name,
  posts.title,
  posts.publish_date
FROM users
INNER JOIN posts
ON users.id = posts.user_id
ORDER BY posts.title;
</pre>
</div>

<h2>INNER JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
CREATE TABLE comments(
	id INT AUTO_INCREMENT,
  post_id INT,
  user_id INT,
  body TEXT,
  publish_date DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(id),
  FOREIGN KEY(user_id) references users(id),
  FOREIGN KEY(post_id) references posts(id)
);
</pre>
</div>

<h2>ADD DATA TO comments TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO comments(post_id, user_id, body) VALUES (1, 3, 'This is comment one'),(2, 1, 'This is comment two'),(5, 3, 'This is comment three'),(2, 4, 'This is comment four'),(1, 2, 'This is comment five'),(3, 1, 'This is comment six'),(3, 2, 'This is comment six'),(5, 4, 'This is comment seven'),(2, 3, 'This is comment seven');
</pre>
</div>

<h2>LEFT JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT
comments.body,
posts.title
FROM comments
LEFT JOIN posts ON posts.id = comments.post_id
ORDER BY posts.title;
</pre>
</div>

<h2>JOIN MULTIPLE TABLES</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT
comments.body,
posts.title,
users.first_name,
users.last_name
FROM comments
INNER JOIN posts on posts.id = comments.post_id
INNER JOIN users on users.id = comments.user_id
ORDER BY posts.title;
</pre>
</div>

<h2>JOIN MULTIPLE TABLES</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT
comments.body,
posts.title,
users.first_name,
users.last_name
FROM comments
INNER JOIN posts on posts.id = comments.post_id
INNER JOIN users on users.id = comments.user_id
ORDER BY posts.title;
</pre>
</div>

<hr>
<h1>WELCOME TO MARS</h1>

<h2>CREATE base TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
CREATE TABLE base(
base_id INT AUTO_INCREMENT,
base_name VARCHAR(100),
founded VARCHAR(100),
PRIMARY KEY(base_id)
);
</pre>
</div>

<h2>CREATE martian TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
CREATE TABLE martian(
martian_id INT AUTO_INCREMENT,
first_name VARCHAR(100),
last_name VARCHAR(100),
base_id INT,
FOREIGN KEY(base_id) REFERENCES base(base_id),
PRIMARY KEY(martian_id)
);
</pre>
</div>

<h2>INSERT INTO base</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO base (base_name, founded)
VALUES 
('Tharsisland', '2037-06-03'),
('Valles Marineris 2.0', '2040-12-01'),
('Gale Cratertown', '2041-08-15'),
('New Harmony', '2042-07-03'),
('Olympus Mons', null);
</pre>
</div>

<h2>INSERT INTO martian</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO martian (
first_name, last_name, base_id
) 
VALUES (
'Ray', 'Bradbury', 1
), (
'John', 'Oyakilome', 4
), (
'Samuel', 'White', 4
), (
'Justice', 'Henry', 1
), (
'Beth', 'Simeon', 1
), (
'Elma', 'Parkhill', 3
), (
'Jeff', 'Spender', 1
), (
'Melissa', 'Chinda', 2
), (
'Nath', 'Cena', 2
), (
'Chris', 'Beck', 4
), (
'Friday', 'Newday', 3
), (
'John', 'George', 2
), (
'Amaka', 'Henry', 4
), (
'Sam', 'Parkhill', 2
), (
'Oluchi', 'Love', null
);
</pre>
</div>

<h2>SELECT INNER JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT first_name, last_name, base_name
FROM martian
INNER JOIN base
ON martian.martian_id = base.base_id;
</pre>
</div>

<h2>CREATE visitor TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
CREATE TABLE visitor(
visitor_id INT AUTO_INCREMENT,
host_id INT,
first_name VARCHAR(100),
last_name VARCHAR(100),
FOREIGN KEY(host_id) REFERENCES martian(martian_id),
PRIMARY KEY(visitor_id)
);
</pre>
</div>

<h2>CREATE visitor TABLE</h2>
<div class="highlight highlight-source-shell">
<pre>
INSERT INTO visitor (
host_id,
first_name,
last_name)
VALUES 
(7, 'George', 'Ambrose'),
(1, 'Priscillia', 'Lane'),
(9, 'Jane', 'Long'),
(null, 'Doug', 'Stavenger'),
(null, 'Jamie', 'Waterman'),
(8, 'Martin', 'Humphries'),
(11, 'Pane', 'King');
</pre>
</div>

<h2>ALTER martian TABLE ADD super_id</h2>
<div class="highlight highlight-source-shell">
<pre>
ALTER TABLE martian ADD super_id INT;
</pre>
</div>

<h2>SELF JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT * FROM martian AS m
LEFT JOIN martian AS s
ON m.super_id = s.martian_id
ORDER BY m.martian_id;
</pre>
</div>
	
<h2>SELF JOIN</h2>
<div class="highlight highlight-source-shell">
<pre>
SELECT m.first_name AS fn, m.last_name AS ln,
       s.first_name AS super_fn, s.last_name AS super_ln
FROM martian AS m
LEFT JOIN martian AS s
ON m.super_id = s.martian_id
ORDER BY m.martian_id;
</pre>
</div>


# NORMALIZATION


When developing the schema of a relational database, one of the most important aspects to be taken into account is to ensure that the duplication is minimized. This is done for 2 purposes:

* Reducing the amount of storage needed to store the data.

* Avoiding unnecessary data conflicts that may creep in because of multiple copies of the same data getting stored.


Database Normalization is a technique that helps in designing the schema of the database in an optimal manner so as to ensure the above points. The core idea of database normalization is to divide the tables into smaller subtables and store pointers to data rather than replicating it. For a better understanding of what we just said, here is a simple DBMS Normalization example:

To understand (DBMS)normalization in the database with example tables, let's assume that we are supposed to store the details of courses and instructors in a university. Here is what a sample database could look like:

**Course Code** | **Course Venue** | **Lecturer Name** | **Lecturer's Phone Number**
----------------|------------------|---------------------|------------------------------
CSC301 | Lecture hall 2 | Prof. Nnamdi | 08130783998
CSC321 | Lecture hall 14 | Prof. George | 08035116534
CSC303 | Lecture hall 4 | Prof. Wale | 08033846527
CSC311 | Lecture hall 12 | Prof. Nnamdi | 08130783998


Here, the data basically stores the course code, course venue, instructor name, and instructor’s phone number. At first, this design seems to be good. However, issues start to develop once we need to modify information. For instance, suppose, if Prof. Nnamdi changed his mobile number. In such a situation, we will have to make edits in 2 places. What if someone just edited the mobile number against CSC301, but forgot to edit it for CSC311? This will lead to stale/wrong information in the database.

This problem, however, can be easily tackled by dividing our table into 2 simpler tables:

### Table 1 (Lecturer):

* Instructor_id

* Instructor Name

* Instructor Phone Number


### Table 2 (Course):

* Course Code

* Course Venue

* Instructor_id


Now, our data will look like the following:

### Table 1(Instructor)

**Lecturer_id** | **Lecturer Name** | **Lecturer Phone Number** |
------------------|---------------------|------------------------------
1 | Prof. Nnamdi | 08130783998
2 | Prof. George | 08035116534
3 | Prof. Wale | 08033846527


### Table 2(Course)

**Course Code** | **Course Venue** | **Lecturer_id** |
----------------|------------------|--------------------
CSC301 | Lecture Hall 2 | 1
CSC321 | Lecture hall 14 | 2
CSC303 | Lecture hall 4 | 3
CSC311| Lecture hall 12 | 1


Basically, we store the instructors separately and in the course table, we do not store the entire data of the instructor. We rather store the ID of the instructor. Now, if someone wants to know the mobile number of the instructor, he/she can simply look up the instructor table. Also, if we were to change the mobile number of Prof. Nnamdi, it can be done in exactly one place. This avoids the stale/wrong data problem.


Further, if you observe, the mobile number now need not be stored 2 times. We have stored it at just 1 place. This also saves storage. This may not be obvious in the above simple example. However, think about the case when there are hundreds of courses and instructors and for each instructor, we have to store not just the mobile number, but also other details like office address, email address, specialization, availability, etc. In such a situation, replicating so much data will increase the storage requirement unnecessarily.

The above is a simplified example of how database normalization works. We will now more formally study it.


## Types of DBMS Normalization

There are various database “Normal” forms. Each normal form has an importance which helps in optimizing the database to save storage and to reduce redundancies


### First Normal Form (1NF)

The First normal form simply says that each cell of a table should contain exactly one value. Let us take an example. Suppose we are storing the courses that a particular instructor takes, we can store it like this:


**Instructor's Name** | **Course Code** |
----------------------|------------------
Justice | MYSQL, JavaScript
Ebuka | Graphics
Chichi | Digital Marketting


Here, the issue is that in the first column, we are storing 2 courses against Justice. This isn’t the optimal way since that’s not how SQL databases are designed to be used. A better method would be to store the courses separately. For instance:


**Instructor's Name** | **Course Code** |
----------------------|------------------
Justice | MYSQL
Justice | JavaScript
Ebuka | Graphics
Chichi | Digital Marketting


This way, if we want to edit some information related to MYSQL, we do not have to touch the data corresponding to JavaScript. Also, observe that each column stores unique information. There is no repetition. This is called the First Normal Form.


## Second Normal Form (2NF)

For a table to be in second normal form, the following 2 conditions are to be met:

1. The table should be in the first normal form.

2. The primary key of the table should compose of exactly 1 column.


The first point is obviously straightforward since we just studied 1NF. Let us understand the second point; 1 column primary key. Well, a primary key is a set of columns that uniquely identifies a row. Basically, no 2 rows have the same primary keys. Let us take an example.


**Course Code** | **Course Venue** | **Lecturer Name** | **Instructor Phone Number**|
----------------|------------------|---------------------|-----------------------------
CSC301 | Lecture Hall 2 | Prof. Nnamdi | 08120813721
CSC321 | Lecture hall 14 | Prof. George | 08217382334
CSC303 | Lecture hall 4 | Prof. Wale | 09032347774
CSC311| Lecture hall 12 | Prof. Nnamdi | 08120813721


Here, in this table, the course code is unique. So, we can choose to use that as our primary key. Let us take another example of storing student enrollment in various courses in a university. Each student may enroll in multiple courses. Similarly, each course may have multiple enrollments. A sample table may look like this (student name and course code):


**Student Name** | **Course Code** |
----------------|------------------
John | MATH101 
Promise | PHY101 
Benita | CHM101 
John | PHY101 


Here, the first row is the student name and the second row is the course taken by the student. Clearly, the student name column isn’t unique as we can see that there are 2 entries corresponding to the name ‘John’ in row 1 and row 4. Similarly, the course code column is not unique as we can see that there are 2 entries corresponding to course code PHY101 in column 2 and column 4. However, the tuple (student name, course code) is unique since a student cannot enroll in the same course more than once. So, these 2 rows when combined form the primary key for the database.

As per the second normal form definition, our enrollment table above isn’t in the second normal form. To achieve the same (1NF to 2NF), we can rather break it into 2 tables:


**Student Name** | **Enrollment Number** |
-----------------|-------------------------
John | 1
Promise | 2
Benita | 3


Here the second row is unique and it indicates the enrollment number for the student. Clearly, the enrollment number is unique. Now, we can attach each of these enrollment numbers with course codes.


**Enrollment Number** | **Course Code** |
----------------------|------------------
1 | MATH101 
2 | PHY101 
3 | CHM101 
1 | PHY101 


These 2 tables together provide us with the exact same information as our original table.


## Third Normal Form (3NF)

Before we delve into details of third normal form, let us understand the concept of a functional dependency on a table.

Column A is said to be functionally dependent on column B if changing the value of A may require a change in the value of B. As an example, consider the following table:


**Course Code** | **Course Venue** | **Lecturer's Name** | **Department**|
----------------|------------------|---------------------|---------------
CSC301 | Lecture Hall 2 | Prof. Nnamdi | Computer Science
MTH321 | Lecture hall 14 | Prof. George | Mathematics


Here, the department column is dependent on the professor name column. This is because if in a particular row, we change the name of the professor, we will also have to change the department value. As an example, suppose MTH321 is now taken by Prof. Ronald who happens to be from the Statistics department, the table will look like this:


**Course Code** | **Course Venue** | **Lecturer's Name** | **Department**|
----------------|------------------|---------------------|---------------
CSC301 | Lecture Hall 2 | Prof. Nnamdi | Computer Science
MTH321 | Lecture hall 14 | Prof. Ronald | Statistics


Here, when we changed the name of the professor, we also had to change the department column. This is not desirable since someone who is updating the database may remember to change the name of the professor, but may forget updating the department value. This can cause inconsistency in the database.

Third normal form avoids this by breaking this into separate tables:

**Lecturer_id | **Lecturer's Name** | **Department**|
--------------|---------------------|----------------
1 | Prof. Nnamdi | Computer Science
2 | Prof. Ronald | Statistics


**Course Code | **Course Venue** | **Lecturer_id**|
--------------|------------------|-----------------
CSC301 | Lecture Hall 2 | 1
MTH321 | Lecture Hall 14 | 2

Here, the third row is the ID of the professor who’s taking the course. In the above table, we store the details of the professor against his/her ID. This way, whenever we want to reference the professor somewhere, we don’t have to put the other details of the professor in that table again. We can simply use the ID.

Therefore, in the third normal form, the following conditions are required:

* The table should be in the second normal form.
* There should not be any functional dependency.


# RELATIONSHIPS IN A RELATIONAL DATABASE

There are 3 types of relationships in database designs

1. One-to-One

2. One-to-Many (or Many-to-One)

3. Many-to-Many


## ONE-to-ONE (1:1)

<img src="https://database.guide/wp-content/uploads/2016/05/relationship-diagram-one-to-one.png" alt="Image example of a 1:1 relationship" />

This is not a common relationship type, as the data stored in table pay could just have easily been stored in table Employee. However, there are some valid reasons for using this relationship type. A one-to-one relationship  can be used for security purposes, to divide a large table, and various other specific purposes.

In the above example, we could just as easily have put an HourlyRate field straight into the Employee table and not bothered with the Pay table. However, hourly rate could be sensitive data that only certain database users should see. So, by putting the hourly rate into a separate table, we can provide extra security around the Pay table so that only certain users can access the data in that table.


## ONE-to-MANY (1:n)

This is the most common relationship type. In this type of relationship, a row in table A can have many matching rows in table B, but a row in table B can have only one matching row in table A.

<img src="https://database.guide/wp-content/uploads/2016/05/relationship-diagram-one-to-many.png" alt="Image example of 1:n relationship" />

One-to-Many relationships can also be viewed as Many-to-One relationships, depending on which way you look at it.

In the above example, the Customer table is the “many” and the City table is the “one”. Each customer can only be assigned one city,. One city can be assigned to many customers.


## MANY-to-MANY (n:m)

In a many-to-many relationship, a row in table A can have many matching rows in table B, and vice versa.

A many-to-many relationship could be thought of as two one-to-many relationships, linked by an intermediary table.

The intermediary table is typically referred to as a “junction table” (also as a “cross-reference table”). This table is used to link the other two tables together. It does this by having two fields that reference the primary key of each of the other two tables.

The following is an example of a many-to-many relationship:

<img src="https://database.guide/wp-content/uploads/2016/05/create_a_relationship_in_access_2013_5.png" alt="Image example of a n:m relationship" />

So in order to create a many-to-many relationship between the Customers table and the Products table, we created a new table called Orders.

In the Orders table, we have a field called CustomerId and another called ProductId. The values that these fields contain should correspond with a value in the corresponding field in the referenced table. So any given value in Orders.CustomerId should also exist in the Customer.CustomerId field.


## Getting started
- http://www.sqlteaching.com/
- https://www.codecademy.com/learn/learn-sql
- https://www.codecademy.com/catalog/language/sql

### Related tutorials
- [MySQL-CLI](https://www.youtube.com/playlist?list=PLfdtiltiRHWEw4-kRrh1ZZy_3OcQxTn7P)
- [Analyzing Business Metrics](https://www.codecademy.com/learn/sql-analyzing-business-metrics)
- [SQL joins infografic](https://www.codeproject.com/Articles/33052/Visual-Representation-of-SQL-Joins)

## Tools
- [TablePlus](https://tableplus.io/)
- [DataGrip](https://www.jetbrains.com/datagrip/)
- [Sequel Pro](http://www.sequelpro.com/) (abandoned)

## Commands
Access monitor: `mysql -u [username] -p;` (will prompt for password)

Show all databases: `show databases;`

Access database: `mysql -u [username] -p [database]` (will prompt for password)

Create new database: `create database [database];`

Select database: `use [database];`

Determine what database is in use: `select database();`

Show all tables: `show tables;`

Show table structure: `describe [table];`

List all indexes on a table: `show index from [table];`

Create new table with columns: `CREATE TABLE [table] ([column] VARCHAR(120), [another-column] DATETIME);`

Adding a column: `ALTER TABLE [table] ADD COLUMN [column] VARCHAR(120);`

Adding a column with an unique, auto-incrementing ID: `ALTER TABLE [table] ADD COLUMN [column] int NOT NULL AUTO_INCREMENT PRIMARY KEY;`

Inserting a record: `INSERT INTO [table] ([column], [column]) VALUES ('[value]', '[value]');`

MySQL function for datetime input: `NOW()`

Selecting records: `SELECT * FROM [table];`

Explain records: `EXPLAIN SELECT * FROM [table];`

Selecting parts of records: `SELECT [column], [another-column] FROM [table];`

Counting records: `SELECT COUNT([column]) FROM [table];`

Counting and selecting grouped records: `SELECT *, (SELECT COUNT([column]) FROM [table]) AS count FROM [table] GROUP BY [column];`

Selecting specific records: `SELECT * FROM [table] WHERE [column] = [value];` (Selectors: `<`, `>`, `!=`; combine multiple selectors with `AND`, `OR`)

Select records containing `[value]`: `SELECT * FROM [table] WHERE [column] LIKE '%[value]%';`

Select records starting with `[value]`: `SELECT * FROM [table] WHERE [column] LIKE '[value]%';`

Select records starting with `val` and ending with `ue`: `SELECT * FROM [table] WHERE [column] LIKE '[val_ue]';`

Select a range: `SELECT * FROM [table] WHERE [column] BETWEEN [value1] and [value2];`

Select with custom order and only limit: `SELECT * FROM [table] WHERE [column] ORDER BY [column] ASC LIMIT [value];` (Order: `DESC`, `ASC`)

Updating records: `UPDATE [table] SET [column] = '[updated-value]' WHERE [column] = [value];`

Deleting records: `DELETE FROM [table] WHERE [column] = [value];`

Delete *all records* from a table (without dropping the table itself): `DELETE FROM [table];`
(This also resets the incrementing counter for auto generated columns like an id column.)

Delete all records in a table: `truncate table [table];`

Removing table columns: `ALTER TABLE [table] DROP COLUMN [column];`

Deleting tables: `DROP TABLE [table];`

Deleting databases: `DROP DATABASE [database];`

Custom column output names: `SELECT [column] AS [custom-column] FROM [table];`

Export a database dump (more info [here](http://stackoverflow.com/a/21091197/1815847)): `mysqldump -u [username] -p [database] > db_backup.sql`

Use `--lock-tables=false` option for locked tables (more info [here](http://stackoverflow.com/a/104628/1815847)).

Import a database dump (more info [here](http://stackoverflow.com/a/21091197/1815847)): `mysql -u [username] -p -h localhost [database] < db_backup.sql`

Logout: `exit;`

## Aggregate functions
Select but without duplicates: `SELECT distinct name, email, acception FROM owners WHERE acception = 1 AND date >= 2015-01-01 00:00:00`

Calculate total number of records: `SELECT SUM([column]) FROM [table];`

Count total number of `[column]` and group by `[category-column]`: `SELECT [category-column], SUM([column]) FROM [table] GROUP BY [category-column];`

Get largest value in `[column]`: `SELECT MAX([column]) FROM [table];`

Get smallest value: `SELECT MIN([column]) FROM [table];`

Get average value: `SELECT AVG([column]) FROM [table];`

Get rounded average value and group by `[category-column]`: `SELECT [category-column], ROUND(AVG([column]), 2) FROM [table] GROUP BY [category-column];`

## Multiple tables
Select from multiple tables: `SELECT [table1].[column], [table1].[another-column], [table2].[column] FROM [table1], [table2];`

Combine rows from different tables: `SELECT * FROM [table1] INNER JOIN [table2] ON [table1].[column] = [table2].[column];`

Combine rows from different tables but do not require the join condition: `SELECT * FROM [table1] LEFT OUTER JOIN [table2] ON [table1].[column] = [table2].[column];` (The left table is the first table that appears in the statement.)

Rename column or table using an _alias_: `SELECT [table1].[column] AS '[value]', [table2].[column] AS '[value]' FROM [table1], [table2];`

## Users functions
List all users: `SELECT User,Host FROM mysql.user;`

Create new user: `CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';`

Grant `ALL` access to user for `*` tables: `GRANT ALL ON database.* TO 'user'@'localhost';`

## Find out the IP Address of the Mysql Host
`SHOW VARIABLES WHERE Variable_name = 'hostname';` ([source](http://serverfault.com/a/129646))
