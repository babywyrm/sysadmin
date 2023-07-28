

# The Java Code Review Checklist

A code review guide and checklist when working with Java and related technologies. The following should really help when writing new code in Java applications after upgrading to Java 8 or refactoring code that is < Java8

# Core Java 

## Prefer Lambdas

Instead of 

```
Runnable runner = new Runnable(){
    public void run(){
        System.out.println("I am running");
    }
};
```

do...

```
Runnable running = () -> {
    System.out.println("I am running");
};
```

## Refactor interfaces with default methods

Instead of 

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
  public void saySomething(); 
 
}
```

Use default methods. Make sure you do not do this as a a habit because this pattern pollutes interfaces.

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
 
    public void saySomething();
 
    default public void sayHi() {
      System.out.println("Hi");
    }
 
}
```

## Prefer Streams to reduce code.

```
private static void printNames(List persons, Predicate predicate) {
            persons.stream()
                    .filter(predicate)
                    .map(p -> p.getName())
                    .forEach(name -> System.out.println(name));
        }
}
```

## Use Parallel sorting

Instead of 

```
Array.sort(myArray);
```

Use...

```
Arrays.parallelSort(myArray);
```

## Depend on parameter reflection

Instead of...

```
Person getEmployee(@PathParam("dept") Long dept, @QueryParam("id") Long id)
```

Do...

```
Person getEmployee(@PathParam Long dept, @QueryParam Long id)
```

Since params names as same as var names.

## Prefer to use "filter / map / reduce" approach

```
List<String> names = Arrays.asList("Smith", "Adams", "Crawford"); 
List<Person> people = peopleDAO.find("London"); 
  
// Using anyMatch and method reference 
List<Person> anyMatch = people.stream().filter(p -> (names.stream().anyMatch(p.name::contains))).collect(Collectors.toList()); 
  
// Using reduce 
List<Person> reduced = people.stream().filter(p -> names.stream().reduce(false (Boolean b, String keyword) -> b || p.name.contains(keyword), (l, r) -> l | r)).collect(Collectors.toList()); 
```

# Use new data-time api

```
Clock clock = Clock.systemUTC(); //return the current time based on your system clock and set to UTC. 

Clock clock = Clock.systemDefaultZone(); //return time based on system clock zone 

long time = clock.millis(); //time in milliseconds from January 1st, 1970
```


##
##

Code reviews, or peer reviews, can sometimes feel like an unnecessary chore, especially when there is a backlog of features to work on, leaving very little time for these reviews. However, manual or automated reviews are essential to delivering quality code that provides a great customer experience.

This guide covers some of the most common items to check in a Java code review to ensure your code is reliable and easy to read, maintain and scale.

1. Ensure the code follows standard naming conventions
Meaningful naming conventions help ensure the readability and maintainability of the application.

As such, ensure variable, method, and class names convey the subject:

addPerson()
Could be clarified to:

addEmployee()
Use all lower cases for package names and use reversed Internet domain naming conventions:

org/companyname/appname
Class names should start with Capitals:

Employee, Student,
Variable and method names should use CamelCase:

employeeList, studentName, displayEmployees()
2. Make sure it handles constants efficiently
Constants help improve memory as they are cached by the JVM. For values that are reused across multiple places, create a constant file that holds static values.

Favor database-driven values over dynamic values. Also, use ENUMs to group constants.

3. Check for proper clean Up
It is common during development to use procedures that help with your coding and debugging (hard coded variables, for example). It is good practice to remove these items and others such as:

Console print statements
Unnecessary comments
Use @deprecated on method/variable names that aren’t meant for future use
4. Handle strings appropriately
If you need to perform a lot of operations on a String, use StringBuilder or StringBuffer.

Strings are immutable, whereas StringBuilder and StringBuffer are mutable and can be changed. Additionally, a new String object is created for every concatenation operation.

Rather than creating multiple items, using a mutable object is preferred.

5. Optimize to use switch-case over multiple If-Else statements
Rather than using multiple if-else conditions, use the cleaner and more readable switch-case.

Doing so makes the logic cleaner and optimizes the app's performance.

switch(expression) {

 case x:

// code block

   break;

case y:

  // code block

   break;

 default:

   // code block

}

6. Ensure the code follows appropriate error handling procedures
The NullPointerException is one of the most common and frustrating exceptions.

However, they can be avoided by performing a null check on a variable before operating on it.

The best practice is to use checked exceptions for recoverable operations and use runtime exceptions for programming errors.

Another area to evaluate during a Java code review is to ensure all exceptions are wrapped in custom exceptions.

In this way, the stack trace is preserved, making it easier to debug when things go wrong.

Also, it should declare specific checked exceptions that the method throws rather than generic ones. Doing so doesn’t give you the option to handle and debug the issue appropriately.

Avoid this:

public void hello() throws Exception { //Incorrect way

}

Try this instead:

public void hello() throws SpecificException1, SpecificException2 { //Correct way

}

Use the try-catch block for exception handling with appropriate actions taken in the catch block.

Also, use a finally block to release resources, such as database connections, in the finally block. This allows you to close the resource gracefully.

7. Avoid unnecessary comments in code?
Comments should not be used to explain code. If the logic is not intuitive, it should be rewritten. Use comments to answer a question that the code can’t.

Another way to state it is that the comment should explain the “why” versus “what” it does.

8. Validate that the code follows separation of concerns
Ensure there is no duplication. Each class or method should be small and focus on one thing.

For example:

EmployeeDao.java - Data access logic

Employee.java - Domain Logic

EmployeerService.java - Business Logic

EmployeeValidator.java - Validating Input Fields

9. Does the code rely on frameworks rather than custom logic when possible?
When time is of the essence, reinventing the wheel is time wasted. There are plenty of proven frameworks and libraries available for the most common use cases you may need.

Examples include Apache Commons libraries, Spring libraries, and XML/JSON libraries.

10. Make sure variables don’t cause memory leaks
Creating a bunch of unnecessary variables can overwhelm the heap and lead to memory leaks and cause performance problems. This occurs when an object is present in the heap but is no longer used, and the garbage collection cannot remove it from memory.

Example:

Avoid This

boolean removed = myItems.remove(item); return removed;
Try This Instead

return myItems.remove(item);
Performing regular Java code reviews can help identify issues before the application makes it to production.

The more thorough you are about the process, the less chance you’ll miss anything that could be added to your backlog.




# The Java Code Review Checklist

A code review guide and checklist when working with Java and related technologies. The following should really help when writing new code in Java applications after upgrading to Java 8 or refactoring code that is < Java8

# Core Java 

## Prefer Lambdas

Instead of 

```
Runnable runner = new Runnable(){
    public void run(){
        System.out.println("I am running");
    }
};
```

do...

```
Runnable running = () -> {
    System.out.println("I am running");
};
```

## Refactor interfaces with default methods

Instead of 

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
  public void saySomething(); 
 
}
```

Use default methods. Make sure you do not do this as a a habit because this pattern pollutes interfaces.

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
 
    public void saySomething();
 
    default public void sayHi() {
      System.out.println("Hi");
    }
 
}
```

## Prefer Streams to reduce code.

```
private static void printNames(List persons, Predicate predicate) {
            persons.stream()
                    .filter(predicate)
                    .map(p -> p.getName())
                    .forEach(name -> System.out.println(name));
        }
}
```

## Use Parallel sorting

Instead of 

```
Array.sort(myArray);
```

Use...

```
Arrays.parallelSort(myArray);
```

## Depend on parameter reflection

Instead of...

```
Person getEmployee(@PathParam("dept") Long dept, @QueryParam("id") Long id)
```

Do...

```
Person getEmployee(@PathParam Long dept, @QueryParam Long id)
```

Since params names as same as var names.

## Prefer to use "filter / map / reduce" approach

```
List<String> names = Arrays.asList("Smith", "Adams", "Crawford"); 
List<Person> people = peopleDAO.find("London"); 
  
// Using anyMatch and method reference 
List<Person> anyMatch = people.stream().filter(p -> (names.stream().anyMatch(p.name::contains))).collect(Collectors.toList()); 
  
// Using reduce 
List<Person> reduced = people.stream().filter(p -> names.stream().reduce(false (Boolean b, String keyword) -> b || p.name.contains(keyword), (l, r) -> l | r)).collect(Collectors.toList()); 
```

# Use new data-time api

```
Clock clock = Clock.systemUTC(); //return the current time based on your system clock and set to UTC. 

Clock clock = Clock.systemDefaultZone(); //return time based on system clock zone 

long time = clock.millis(); //time in milliseconds from January 1st, 1970
```


```
package java.snippet.account;

import java.util.*;

public class Account {
	public long id;
	public double balance;
	public Map transactions;

	public Account() {
		this.id = System.currentTimeMillis();
		this.balance = 0;
		this.transactions = new TreeMap();
	}

	public void deposit(double amount) {
		balance += amount;
		transactions.put(new Date(), amount);
	}

	public void withdraw(double amount) {
		balance -= amount;
		transactions.put(new Date(), -amount);
	}

	public void chargeFee(double amount) {
		balance -= amount;
		transactions.put(new Date(), -amount);
	}
	
	public String transactionsAsString(){
		String strTransactions = "";
		for(Iterator itr = transactions.keySet().iterator(); itr.hasNext();){
			Object when = itr.next();
			strTransactions += " - " + when + " : " + transactions.get(when) + "\n";
		}	
		return strTransactions;		
	}

	public static void main(String[] args) {
		Account account = new Account();
		account.deposit(100);
		account.withdraw(70);
		account.chargeFee(5.50);

		System.out.println("id : " + account.id);			// is non-zero?
		System.out.println("balance : " + account.balance);	// equals 24.50?
		System.out.println("transactions : ");
		System.out.println(account.transactionsAsString());	// shows 3 transactions
	}
}
```

##
##

To use grep to search for sensitive strings, passwords, and usernames in Java files within a directory and its subdirectories, you can combine it with find to traverse the directory tree. The -r (or --recursive) option is used to search recursively. Please keep in mind that searching for sensitive information like passwords or usernames in code files should only be done on your own codebase or with explicit permission from the code owner.

Here's the command you can use:

bash
Copy code
find /path/to/your/directory -type f -name "*.java" -exec grep -Ei "(password|username|sensitive_string)" {} +
Explanation:

find /path/to/your/directory: This starts the search from the specified directory and its subdirectories.
-type f: This option makes find search only for regular files (not directories or other file types).
-name "*.java": This specifies that find should only look for files with the ".java" extension.
-exec grep -Ei "(password|username|sensitive_string)" {} +: This tells find to execute grep on the found files. The -E option enables extended regular expressions (to use the | for multiple patterns), and the -i option makes the search case-insensitive. The {} is a placeholder for the file name, and + at the end ensures that multiple file names are passed to a single grep command to improve efficiency.
Please replace /path/to/your/directory with the actual path to the directory you want to search in. The command will display any lines in the Java files that match the specified patterns. Double-check the results before taking any actions, as some legitimate code constructs might also contain these keywords. Always be careful when handling potentially sensitive information.






##
##
##


grep all .java files in a directory for a particular string
Asked 14 years ago
Modified 3 years, 1 month ago
Viewed 20k times
13

How would I search all .java files for a simple string (not a regex) in the current directory and all sub-directories on Mac OS X? I just want to print a list of file and directory names that match.

macosmacunixgrep
Share
Improve this question
Follow
edited Aug 6, 2009 at 16:51
John T's user avatar
John T
163k2727 gold badges340340 silver badges347347 bronze badges
asked Jul 15, 2009 at 20:06
John Topley's user avatar
John Topley
1,72833 gold badges1818 silver badges2222 bronze badges
Thanks for asking this so I don't have to. Now I just have to figure out how to exclude ".git" and I'm done for a bit. – 
Dan Rosenstark
 Nov 16, 2010 at 21:13
I think js's answer is more concise, still sucks you have to type out --include, but still. Could probably just write an alias to hide that – 
Craig Tataryn
 Jul 5, 2011 at 16:14
Add a comment
9 Answers
Sorted by:

Highest score (default)
19

And the always popular

find . -name '*.java' | xargs grep -l 'string'
EDIT (by Frank Szczerba):

If you are dealing with filenames or directories that have spaces in them, the safest way to do this is:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
There's always more than one way to do it.

Share
Improve this answer
Follow
edited Aug 13, 2011 at 5:56
Tamara Wijsman's user avatar
Tamara Wijsman
57.1k2727 gold badges185185 silver badges256256 bronze badges
answered Jul 15, 2009 at 20:13
David Mackintosh's user avatar
David Mackintosh
3,93477 gold badges3333 silver badges4242 bronze badges
mdfind is a more OSXy way to do this! – 
user22908
 Oct 10, 2011 at 20:43
Add a comment
11

The traditional UNIX answer would be the one that was accepted for this question:

find . -name '*.java' | xargs grep -l 'string'
This will probably work for Java files, but spaces in filenames are a lot more common on Mac than in the traditional UNIX world. When filenames with spaces are passed through the pipeline above, xargs will interpret the individual words as different names.

What you really want is to nul-separate the names to make the boundaries unambiguous:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
The alternative is to let find run grep for you, as Mark suggests, though that approach is slower if you are searching large numbers of files (as grep is invoked once per file rather than once with the whole list of files).

Share
Improve this answer
Follow
answered Jul 31, 2009 at 15:24
Frank Szczerba's user avatar
Frank Szczerba
51544 silver badges1111 bronze badges
You can also use the "--replace" option in xargs to deal with filenames having spaces in them: ... | xargs --replace grep 'string' '{}' ({} would be replaced by the filename) – 
arathorn
 Aug 6, 2009 at 15:41
1
Modern versions of find (including the one installed on OS X) support "-exec <command> {} +" where the plus sign at the end (instead of \;) tells find to replace {} with "as many pathnames as possible... This is is similar to that of xargs(1)" (from the man page). – 
Doug Harris
 Aug 6, 2009 at 16:23
Add a comment
8

Use the grep that is better than grep, ack:

ack -l --java  "string" 
Share
Improve this answer
Follow
edited Jul 16, 2009 at 6:49
answered Jul 15, 2009 at 20:23
bortzmeyer's user avatar
bortzmeyer
1,1711111 silver badges1111 bronze badges
3
ack isn't installed on Mac OS X by default. – 
John Topley
 Jul 15, 2009 at 20:25
I don't know what "by default" means. On many OS, you choose what you install so it is difficult to find programs which are always present. At a time, a C compiler was always there and Perl was uncommon... – 
bortzmeyer
 Jul 15, 2009 at 20:34
1
It means that it's part of the standard OS install. I have the developer tools installed on my Mac and they don't install ack. You have to install it yourself. If you have it, then it's a nice syntax. – 
John Topley
 Jul 15, 2009 at 20:41
In the case of ack, it's a single Perl program with no module dependencies. If you can "install" programs in your ~/bin directory, then you can just as easily "install" ack. – 
Andy Lester
 May 3, 2010 at 18:53
Add a comment
6

grep -rl --include="*.java" simplestring *
Share
Improve this answer
Follow
edited Jul 6, 2011 at 14:39
answered Aug 6, 2009 at 22:31
js.'s user avatar
js.
17311 silver badge44 bronze badges
2
This seems to be the best answer here - if grep does it all, why use find & xargs? – 
Peter Gibson
 Jul 13, 2010 at 2:05
FYI, given what's asked in the question, it should be small "l" not big "L" in that command – 
Craig Tataryn
 Jul 5, 2011 at 16:18
Craig is right, I corrected my answer. – 
js.
 Jul 6, 2011 at 14:40
Add a comment
4

This will actually use a regex if you want, just stay away from the metacharacters, or escape them, and you can search for strings.

find . -iname "*.java" -exec egrep -il "search string" {} \;
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:10
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
1

Since this is an OSX question, here is a more OSX specific answer.
Skip find and use Spotlight from the command line. Much more powerful!

COMMAND LINE SPOTLIGHT – FIND MEETS GREP

Most people don’t know you can do Spotlight searches from the command line. Why remember all the arcane find and grep options and what not when you can let Spotlight do the work for you. The command line interface to Spotlight is called mdfind. It has all the same power as the GUI Spotlight search and more because it is scriptable at the command line!

Share
Improve this answer
Follow
edited Jun 12, 2020 at 13:48
Community's user avatar
CommunityBot
1
answered Oct 10, 2011 at 20:41
user22908
Add a comment
0

Give this a go:

grep -rl "string" */*java
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:09
dwj's user avatar
dwj
1,44455 gold badges2121 silver badges2626 bronze badges
1
This gives "grep: */*java: No such file or directory" on Mac OS X. – 
John Topley
 Jul 15, 2009 at 20:12
The problem here is that it will only find *.java files one level deep. See Mark Thalman's answer for IMHO the proper way to do it. – 
Ludwig Weinzierl
 Jul 15, 2009 at 20:17
Sorry, not at my Mac. Doesn't the Mac version of grep have the -r (recursive) flag? – 
dwj
 Jul 15, 2009 at 20:36
It does, but that was the output that I got when searching for a string that I know is in the files. – 
John Topley
 Jul 15, 2009 at 20:40
Add a comment
0

You could also use a GUI program like TextWrangler to do a more intuitive search where the options are in the interface.

Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:13
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
0

grep "(your string)" -rl $(find ./ -name "*.java")
If you want to ignore case, replace -rl with -irl. (your string) may also be a regex if you ever see the need.

Share
Improve this answer
Follow
