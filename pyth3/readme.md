
#
##
https://levelup.gitconnected.com/30-python-hacks-every-developer-should-know-11d4b5f95be5
##
#

According to the latest survey done by StackOverflow, python is the most searched and tagged programming language in the world. It has one of the biggest active communities of developers. Python is so famous among beginners because of its simple syntax and easy-to-learn fundamentals. It is a versatile language that can be used to create almost everything in the software industry. One of the biggest advantages of python is its one-liners and packages that can do any task with few lines of code. Having so many built-in functionalities, there are some hacks that you should remember while coding in python. In this blog, I will be sharing 30 Python Hacks Every Developer Should Know.
1. Generating a File Sharing Server

Python offers a very simple way to share files from your computer to another computer or mobile by creating a free online FTP server.

```
python -m http.server 5000
```

You can choose the port range from 0 to 65353. Once the code gets executed you will see your server is running at 127.0.0.1:5000

Now open chrome or any browser on your mobile phone and simply type YOUR_COMPUTER_IP_ADDRESS:PORT_NUMBER

To get the IP address you can do ipconfig on the terminal of your computer. Below you, will see the IPv4 address. For example, if your IP address is 192.168.39.145 and Port Number is 5000 then the file-sharing server will be running at 192.168.39.145:5000
2. Passing Multiple Arguments Without Declaration

In Python, with the help of *args you can pass any number of arguments to a function without specifying the number.
```
def add_numbers(*numbers):
       sum = 0
       for number in numbers:
           sum += number
       return sum
print(add_numbers(5,6,233,56,3,5,2,5)) ## 315
```

By specifying **kwargs you can pass any number of keyword arguments to a function.
3. Creating List Elements Smartly

A List in Python is similar to an array. It is mutable, can store heterogeneous elements, and is easy to use. Now to add elements to an array you need to run a loop and then add elements one by one. Also If there are any conditionals involved then the size of the code increases. Python provides a more efficient way of doing it combining all the steps in a one-liner called List comprehension.
4. Type Checking 2.0

Checking the type of a variable is a task that you will perform again and again to gain knowledge. isinstance()function in python returns a boolean depending on whether the given object is an instance of the specified class. It takes two parameters object and the class itself. It can also be used for normal type checking.
5. Trimming Scraped Data

When we scrape some text, heading there is a lot of unwanted text (\t, \n, \t, etc.) also get scraped. Trimming is a way to getting rid of that unwanted data. There is a method in python named strip() that will trim all the scraped data.

-------------- Trimming A String ----------- 
data = "\n\n\n \t  David's Foord and Restaurant \t \n\n\n    "
print(data.strip())
--o/p-----
David's Foord and Restaurant--------- Trimming List of Strings ---------
data = ["\n\n\n Burger \t   ","\n\t Pizza \t  "]
cleaned_data = [i.strip() for i in data]
print(cleaned_data)
---o/p----
["Burger","Pizza"]

6. The _ Operator

Single underscore _ is a valid character in python. It can be used as a variable name. It is a special character that is used to store the result of the previous evaluation according to python docs.

---------- As a Variable -----------
_ = 10
b = 20
sum = _+b
print(sum)
------
30------------ Restoring The Previous Evaluation Result ------
>>> 200+400
600
>>> _*5
3000

7. Shorter Names

One of the biggest features of python is its vast amount of libraries. The problem comes when you have to use them again and again in your program because some of them have bigger and non-English friendly names. Python offers a simpler way to shorten the name of the library with the help of as keywords.

## Normal Way 
import numpy 
import speech_recognition## Shorten Name
import numpy as np
import speech_recognition as sr

8. Iterating Multiple Lists Professionally

Most of the time when you scrape data from the web, you store it in a different list. This hack lets you print each element of the list corresponding to each element of another list.
9. Slicing For Advantage

Slicing is a built-in feature of python that allows you to access certain parts of a sequence. It can also be used to modify, or delete items from them. There are tons of examples where you can use slicing to reduce the size of code.

''' Checking For Palindrome '''
name = "wow"
print(name==name[::-1])
-----------
True''' Retriving Even Numbers From a Natural Sequence '''
natural_numbers = [1,2,3,4,5,6,7,8,9,10]
even_numbers = natural_numbers[1::2]
print(even_numbers)
-------------
[2,4,6,8,10]

10. Breaking Long Lines With \

One of the biggest reasons a code becomes unreadable is because of the long file address, links, or list elements.

url = 'https://medium.com/pythoneers/10-underrated-python-packages-every-data-scientist-should-know-86b4355cc35e'

You can change the point of wrap with the help of a backslash \

url = 'https://medium.com/pythoneers/'\
       '10-underrated-python-packages-every-'\
       'data-scientist-should-know-86b4355cc35e'
print(url)
----------------
https://medium.com/pythoneers/10-underrated-python-packages-every-data-scientist-should-know-86b4355cc35e

    Become a Genuine Medium Member With The Cost of One Pizza. It’s Just 5$ a month. You Can Use My Referral Link To Become One. “Don’t Just Read, Support The Writers Too”

11. Count Occurrence of Elements

It is good to have an idea of the number of times elements occurred in your data structure.

from collections import Counter
data= [96,95,96,87,87,88,56,57,57]occurences = Counter(data)
print(occurences)
---------------
Counter({96: 2, 87: 2, 57: 2, 95: 1, 88: 1, 56: 1})

12. Taking Multiple Inputs (The Pythonic Way 😎)

Python provides a simpler way to take multiple inputs using one line of code. You can also define multiple variables in one line.

x, y = input().split()## Interger Inputs
x, y = map(int, input().split())## Space Seperated Inputs
data = list(map(int, input().split()))

13. One Liner Functions

Python offers a one-liner function that is called the lambda function. It is also referred to as “Anonymous Function”. The reason is that it doesn’t require def keywords for definition. It can take any number of arguments but only one expression at a time. A good practice is to use it as an expression rather than binding it to a variable.
14. Applying a Function To Each Element of the list

Use the map function to apply the same transformation to every element in a List.

ID = ["R72345","R72345&"]
results = list(map(str.isalnum, ID))
print(results)
-----------------
[True, False]

15. Calculate Execution Time of a Program

It is a major task in Machine learning. It is important to know the time taken by your code or function to run so that you can improve it later with some tricks.

''' The Simplest Way '''
import time
start_time = time.time()
...
func()
...
end_time = time.time()
print("Execution Time: ",(end_time-start_time))Check Out This StackOver Flow Discussion For More Examples On How To Calculate Execution Time.

8 High Paying Careers To Choose After Learning Python
Choose a job you love, and you will never have to work a day in your life

medium.com
16. Use Get Method Over Square Brackets

Most Python developers are in a habit of using square brackets when accessing an element from a data structure like Dictionaries. There is no issue with square brackets but when it comes to a value that doesn’t exit it shows an ugly error. Now, to save yourself from that error you can use get method.

data_dict = {a:1, b:2,c:3}print(data_dict['d']) ## KeyError: 'd'print(data_dict.get('d')) ## None 

17. Handling Exceptions At Runtime

An Exception is a condition that occurs during the execution of the program due to some reason and interrupts the execution. To handle exceptions in python we use try and except block. try block contains the code that needs to be executed and except block contains the code that will execute if some error occurred in the try block.

''' Exception '''
a = 5
b = 0
print(a/b) ## ZeroDivisionError: division by zero''' Exception Handling '''
try:
    a = 5
    b = 0
    print(a/b)
except:
    print("Can't Divide Number With 0")
-----------------------
Can't Divide Number With 0

18. Converting a Normal Method onto a Static One

A Static Method is a type of method in python classes that is bound to a particular state of the class. They can not access or update the state of the class. You can convert a normal method or instance method to a static method with the help of staticmethod(function)

class ABC:
    def abc(num1,num2):
        print(num1+numn2)


# changing torture_students into static method
ABC.abc = staticmethod(ABC.abc)

ABC.abc(4,5) ## 9

To know the reason why you should convert a normal or instance method into a static one check out this discussion.
19. Printing Readable Results

The normal print statement works fine in most situations but when the output is in the form of tables, JSON, or contains multiple results then you have to add some functionality to it or use some external package.
20. Division Version 2.0

The divmod() is a kind of inbuilt function in python that takes two numbers as input and returns the remainder and quotient both in a tuple.

a = 2560
b = 27result = divmod(a,b)
print(result)
--------------------
(94, 22)

21. Solving Expressions In One Line

Python provides a very useful function eval()for solving expressions. It takes three parameters as input — the mathematical expression to be evaluated, reference to a variable, direct value reference.
22. For Else Method

You can use else keyword inside a for loop. It will specify a block of code that will run after the successful execution of your for loop. This block can be used to specify any end condition or message for the loop.

for x in range(9):
  print(x)
else:
  print("Finally finished!")

7 Must-Try Python Projects To Improve Your Freelancing Gigs
Projects That Provide Real Values

levelup.gitconnected.com
23. Casting a Mutable To Immutable

Type casting is a feature of Python that lets you convert one data structure into another. With the help of it, you can also change a mutable into an immutable data structure.

''' Mutable List '''
lst = [1,2,3,4,5]
lst[0] = 6
print(lst)
------------
[6,2,3,4,5]''' Converting It to Immutable '''
lst = [1,2,3,4,5]
lst2 = tuple(lst)
lst[0] = 6
--------------
TypeError: 'tuple' object does not support item assignment

24. Generating Sequence As Per Requiment

Generator in python is a type of function that returns an object that can be iterated over. In simple words generator lets to generate a sequence when required. They are very memory efficient. Generators allow you to create iterators and perform lazy evaluations.

def fibo(limit):
    a,b = 0,1
    while a<limit:
       yield a
       a, b = b, a+b
series = fibo(10)print(next(series)) ## 0
print(next(series)) ## 1
print(next(series)) ## 1

25. Logging Instead of Print For Debugging

Logging is the process of capturing the flow of code when it executes. It is very helpful in debugging the code easily. One of the major advantages of logging over print is that even after the application is closed the logs are saved in a file to review later, which comes with log messages and other records like line number and module name. Print only save and show the data until the application is alive and running. Python provides a module name logging to generate and write logs.
26. Adding New Functionalities Smartly

Decorator is a feature of Python that lets you add new functionality to an existing code without explicitly modifying it. A great application of decorator is adding average functionality to a function that calculates addition and percentage without modifying the function.
27. Use Context Managers For Resource Handling

Context Manager is a great tool in python that lets you allocate and release resources when you want. The most used and recognized example of context manager is with statement. with is mostly used to open and close a file. One of the biggest advantages of using with is that it makes sure the files get closed after use.

with open ('content.txt','w') as f:
    f.write("Hello Python")

28. PyForest (Lazy Developers Only)

This Hack is literally one of my favorite and I use it in every project. Most of the time it happened you spend a lot of time importing the basic libraries Like Numpy, Pandas, Etc. To save time and remove the headache pyforest is a library for you. It imports all the necessary libraries automatically that are required for a machine learning project.

from pyforest import *

29. Itetools

This module implements a number of iterator building blocks inspired by constructs from APL, Haskell, and SML. It provides many amazing functions that make this library a gem of python. Check the Documentation for different functions available in this library.
30. Collections In Python

Collection in python are containers that are used to store the collection of data. Python provides a package collection that contains different types of useful containers that can be used for different purposes.
For Example:
Counter — Takes an iterable and returns a dictionary where Keys = elements and Value = their count in the iterable.
namedtuple — Returns a tuple with names for each position in the tuple.
Ordered Dict — Type of dictionary where the order is maintained at any cost.
Default Dict — Contains default values for each key if not assigned.

#
#
#


#
##
##
#

# Functions

Functions are a way to organize code into reusable blocks. As a reminder, functions in Python are "first class objects."

Several built-in functions have been discussed and used previous examples. Just as important is the ability for users to define their own functions.

##### Resources

https://docs.python.org/3/reference/compound_stmts.html#function-definitions

### Defining Functions

https://docs.python.org/3/tutorial/controlflow.html#defining-functions

We can create a function that writes the Fibonacci series to an arbitrary boundary:
```
>>> def fib(n):    # write Fibonacci series up to n
...     """Print a Fibonacci series up to n."""
...     a, b = 0, 1
...     while a < n:
...         print(a, end=' ')
...         a, b = b, a+b
...     print()
...
>>> # Now call the function we just defined:
... fib(2000)
0 1 1 2 3 5 8 13 21 34 55 89 144 233 377 610 987 1597
```
The keyword def introduces a function definition. It must be followed by the function name and the parenthesized list of formal parameters. The statements that form the body of the function start at the next line, and must be indented.

https://docs.python.org/3/reference/compound_stmts.html#def

The first statement of the function body can optionally be a string literal; this string literal is the function’s documentation string, or docstring. (More about docstrings can be found in the section Documentation Strings.) There are tools which use docstrings to automatically produce online or printed documentation, or to let the user interactively browse through code; it’s good practice to include docstrings in code that you write, so make a habit of it.

### Calling Functions

A function definition statement does not execute the function. Executing (calling) a function is done by using the name of the function followed by parenthesis enclosing required arguments (if any).

```
>>> def say_hello():
...     print('Hello')
...
>>> say_hello()
Hello
```
The execution of a function introduces a new symbol table used for the local variables of the function. More precisely, all variable assignments in a function store the value in the local symbol table; whereas variable references first look in the local symbol table, then in the local symbol tables of enclosing functions, then in the global symbol table, and finally in the table of built-in names. Thus, global variables cannot be directly assigned a value within a function (unless named in a global statement), although they may be referenced.

```
>>> a = 1
>>> b = 10
>>> def fn():
...     print(a)    # local a is not assigned, no enclosing function, global a referenced.
...     b = 20      # local b is assigned in the local symbol table for the function.
...     print(b)    # local b is referenced.
...
>>> fn()
1
20
>>> b               # global b is not changed by the function call.
10
```

The actual parameters (arguments) to a function call are introduced in the local symbol table of the called function when it is called; thus, arguments are passed using call by value (where the value is always an object reference, not the value of the object). [1] When a function calls another function, a new local symbol table is created for that call.

```
>>> def greet(s):
...     s = "Hello " + s    # s in local symbol table is reassigned.
...     print(s)
...
>>> person = "Bob"
>>> greet(person)
Hello Bob
>>> person                  # person used to call remains bound to original object, 'Bob'.
'Bob'
```
The arguments used to call a function cannot be reassigned by the function, but arguments that reference mutable objects can have their values changed:

```
>>> def fn(arg):
...     arg.append(1)
...
>>> a = [1, 2, 3]
>>> fn(a)
>>> a
[1, 2, 3, 1]
```

### `return` Statement

https://docs.python.org/3/reference/simple_stmts.html#the-return-statement

All functions return a value when called.

If a return statement is followed by an expression list, that expression list is evaluated and the value is returned:

```
>>> def greater_than_1(n):
...     return n > 1
...
>>> print(greater_than_1(1))
False
>>> print(greater_than_1(2))
True
```

If no expression list is specified, None is returned:

```
>>> def no_expression_list():
...     return    # No return expression list.
...
>>> print(no_expression_list())
None

If a return statement is reached during the execution of a function, the current function call is left at that point:

>>> def return_middle():
...     a = 1
...     return a
...     a = 2     # This assignment is never reached.
...
>>> print(return_middle())
1
```

If there is no return statement the function returns None when it reaches the end:

```
>>> def no_return():
...     pass     # No return statement.
...
>>> print(no_return())
None
```

### Name binding and Aliasing Functions

A function definition introduces the function name in the current symbol table. The value of the function name has a type that is recognized by the interpreter as a user-defined function.

```
>>> something = 1
>>> type(something)
<type 'int'>
>>> def something():
...     pass
...
>>> type(something)
<type 'function'>
>>> something = []
>>> type(something)
<type 'list'>
```

This value can be assigned to another name which can then also be used as a function. This serves as a general renaming mechanism:

```
>>> fib
<function fib at 10042ed0>
>>> f = fib
>>> f(100)
0 1 1 2 3 5 8 13 21 34 55 89
```

### Coding Style

https://docs.python.org/3/tutorial/controlflow.html#intermezzo-coding-style

### Default Argument Values

https://docs.python.org/3/tutorial/controlflow.html#default-argument-values

### Keyword Arguments

https://docs.python.org/3/tutorial/controlflow.html#keyword-arguments

### Arbitrary Arguments

https://docs.python.org/3/tutorial/controlflow.html#unpacking-argument-lists

### Nested functions

```
>>> def outside_fn():
...     def inside_fn():
...         print('inside')
...     print('outside')
...     inside_fn()
...
>>> outside_fn()
outside
inside
>>> inside_fn()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name 'inside_fn' is not defined
```

### `global` and `nonlocal`

#### `global`


https://docs.python.org/3/reference/simple_stmts.html#the-global-statement

#### `nonlocal`

https://docs.python.org/3/reference/simple_stmts.html#the-nonlocal-statement
https://www.python.org/dev/peps/pep-3104/

### Lambda Expressions

### Anonymous functions
https://docs.python.org/3/tutorial/controlflow.html#lambda-expressions
https://docs.python.org/3/reference/expressions.html#lambda

### Decorators

https://www.python.org/dev/peps/pep-0318/
https://docs.python.org/3/whatsnew/2.4.html?highlight=decorator
