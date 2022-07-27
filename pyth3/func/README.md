#	Jun 26, 2021 - Jun 28, 2021

First seven days of 100 days of code.

- Variables
- Input & Print Functions
- Primitive Data Types
- Mathematical Operations in Python
- Strings
- Number Manipulation and String Formatting in Python
- Control Flow with if / else and Conditional Operators
- Nested if statements and elif statements
- Logical Operators
- Random Module
- Understanding the Offset and Appending Items to Lists
- Index Errors and Working with Nested Lists
- [Mini Project] Rock Paper Scissors
- Using the for loop with Python Lists
- for loops and the range() function
- [Mini Project] The Fizz Buzz Job Interview Question
- [Mini Project] Create a Password Generator
- Defining and Calling Python Functions
- While Loops
- ~~[Mini Project] Hangman~~

---

##	Variables
```python
var1 = 20		#	<class 'int'>
var2 = "Text"		#	<class 'str'>
var3 = 1.5		#	<class 'float'>
var4 = []		#	<class 'list'>
var5 = {}		#	<class 'dict'>
var6 = ()		#	<class 'tuple'>
```
++ [Tutorials point](https://www.tutorialspoint.com/python/python_variable_types.htm)

---

##	Input & Print Functions

```python
reply = input("Some random text here: ")
print("Your input: " + reply)	#	str + str

reply = input("Give me a number: ")
reply = int(reply)
print("My favorite number is also " + str(reply))

#	Output:
#>> Some random text here: Hex
#>> Your input: Hex
#>> Give me a number: 6
#>> My favorite number is also 6
```

- Input can also output the argument string.
- Input always returns string.
- int() and str() can be used to interchange variable types.
- ( “” + str_var ) is string concatenation.
- ( “” + int_var ) is not possible.

---

##	Primitive Data Types and Mathematical Operations

```python
#	Boolean
bool_var1 = True
bool_var2 = False
print(bool_var1 == bool_var2)	#	False
print(bool_var1 != bool_var2)	#	True
print(not bool_var2)		#	True

#	Int
int_var1 = 200
int_var2 = 100
print(int_var1 + int_var2)	#	300
print(int_var1 - int_var2)	#	100
print(int_var1 * int_var2)	#	20000
print(int_var1 / int_var2)	#	2.0 (Float)
print(int_var1 % int_var2)	#	0

#	Float
float_var1 = 65.0
float_var2 = 15.0
print(float_var1 + float_var2)	#	80.0
print(float_var1 - float_var2)	#	50.0
print(float_var1 * float_var2)	#	975.0
print(float_var1 / float_var2)	#	4.333_
print(float_var1 % float_var2)	#	5.0
```

### Bool

- True and False are case sensitive.
- Not has less priority than other controls. (X == not Y) is illegal.
- bool() can be used on other types. These return false:
    - constants defined to be false: `None` and `False`.
    - zero of any numeric type: `0`, `0.0`, `0j`, `Decimal(0)`, `Fraction(0, 1)`
    - empty sequences and collections: `''`, `()`, `[]`, `{}`, `set()`, `range(0)`

---

### Operation table

| Operation         | Result                                                       | Notes  | Full documentation                                           |
| :---------------- | :----------------------------------------------------------- | :----- | :----------------------------------------------------------- |
| `x + y`           | sum of *x* and *y*                                           |        |                                                              |
| `x - y`           | difference of *x* and *y*                                    |        |                                                              |
| `x * y`           | product of *x* and *y*                                       |        |                                                              |
| `x / y`           | quotient of *x* and *y*                                      |        |                                                              |
| `x // y`          | floored quotient of *x* and *y*                              | (1)    |                                                              |
| `x % y`           | remainder of `x / y`                                         | (2)    |                                                              |
| `-x`              | *x* negated                                                  |        |                                                              |
| `+x`              | *x* unchanged                                                |        |                                                              |
| `abs(x)`          | absolute value or magnitude of *x*                           |        | [`abs()`](https://docs.python.org/3/library/functions.html#abs) |
| `int(x)`          | *x* converted to integer                                     | (3)(6) | [`int()`](https://docs.python.org/3/library/functions.html#int) |
| `float(x)`        | *x* converted to floating point                              | (4)(6) | [`float()`](https://docs.python.org/3/library/functions.html#float) |
| `complex(re, im)` | a complex number with real part *re*, imaginary part *im*. *im* defaults to zero. | (6)    | [`complex()`](https://docs.python.org/3/library/functions.html#complex) |
| `c.conjugate()`   | conjugate of the complex number *c*                          |        |                                                              |
| `divmod(x, y)`    | the pair `(x // y, x % y)`                                   | (2)    | [`divmod()`](https://docs.python.org/3/library/functions.html#divmod) |
| `pow(x, y)`       | *x* to the power *y*                                         | (5)    | [`pow()`](https://docs.python.org/3/library/functions.html#pow) |
| `x ** y`          | *x* to the power *y*                                         | (5)    |                                                              |

Notes:

1. Also referred to as integer division. The resultant value is a whole integer, though the result’s type is not necessarily int. The result is always rounded towards minus infinity: `1//2` is `0`, `(-1)//2` is `-1`, `1//(-2)` is `-1`, and `(-1)//(-2)` is `0`.
2. Not for complex numbers. Instead convert to floats using [`abs()`](https://docs.python.org/3/library/functions.html#abs) if appropriate.
3. Conversion from floating point to integer may round or truncate as in C; see functions [`math.floor()`](https://docs.python.org/3/library/math.html#math.floor) and [`math.ceil()`](https://docs.python.org/3/library/math.html#math.ceil) for well-defined conversions.
4. float also accepts the strings “nan” and “inf” with an optional prefix “+” or “-” for Not a Number (NaN) and positive or negative infinity.
5. Python defines `pow(0, 0)` and `0 ** 0` to be `1`, as is common for programming languages.
6. The numeric literals accepted include the digits `0` to `9` or any Unicode equivalent (code points with the `Nd` property).

++ [Python Doc](https://docs.python.org/3/library/stdtypes.html)

---

## Strings

- Ways of defining strings:
    - Single quotes: `'allows embedded "double" quotes'`
    - Double quotes: `"allows embedded 'single' quotes"`.
    - Triple quoted: `'''Three single quotes'''`, `"""Three double quotes"""` (This is a multi-line string)

### Flags in Strings

| Flag  | Meaning                                                      |
| :---- | :----------------------------------------------------------- |
| `'#'` | The value conversion will use the “alternate form” (where defined below). |
| `'0'` | The conversion will be zero padded for numeric values.       |
| `'-'` | The converted value is left adjusted (overrides the `'0'` conversion if both are given). |
| `' '` | (a space) A blank should be left before a positive number (or empty string) produced by a signed conversion. |
| `'+'` | A sign character (`'+'` or `'-'`) will precede the conversion (overrides a “space” flag). |

A length modifier (`h`, `l`, or `L`) may be present, but is ignored as it is not necessary for Python – so e.g. `%ld` is identical to `%d`.

```python
print('%(language)s has %(number)03d quote types.' %{'language': "Python", "number": 2})
#	Python has 002 quote types.
```

### Conversions in Strings

| Conversion | Meaning                                                      | Notes |
| :--------- | :----------------------------------------------------------- | :---- |
| `'d'`      | Signed integer decimal.                                      |       |
| `'i'`      | Signed integer decimal.                                      |       |
| `'o'`      | Signed octal value.                                          | (1)   |
| `'u'`      | Obsolete type – it is identical to `'d'`.                    | (6)   |
| `'x'`      | Signed hexadecimal (lowercase).                              | (2)   |
| `'X'`      | Signed hexadecimal (uppercase).                              | (2)   |
| `'e'`      | Floating point exponential format (lowercase).               | (3)   |
| `'E'`      | Floating point exponential format (uppercase).               | (3)   |
| `'f'`      | Floating point decimal format.                               | (3)   |
| `'F'`      | Floating point decimal format.                               | (3)   |
| `'g'`      | Floating point format. Uses lowercase exponential format if exponent is less than -4 or not less than precision, decimal format otherwise. | (4)   |
| `'G'`      | Floating point format. Uses uppercase exponential format if exponent is less than -4 or not less than precision, decimal format otherwise. | (4)   |
| `'c'`      | Single character (accepts integer or single character string). |       |
| `'r'`      | String (converts any Python object using [`repr()`](https://docs.python.org/3/library/functions.html#repr)). | (5)   |
| `'s'`      | String (converts any Python object using [`str()`](https://docs.python.org/3/library/stdtypes.html#str)). | (5)   |
| `'a'`      | String (converts any Python object using [`ascii()`](https://docs.python.org/3/library/functions.html#ascii)). | (5)   |
| `'%'`      | No argument is converted, results in a `'%'` character in the result. |       |

Notes:

1. The alternate form causes a leading octal specifier (`'0o'`) to be inserted before the first digit.

2. The alternate form causes a leading `'0x'` or `'0X'` (depending on whether the `'x'` or `'X'` format was used) to be inserted before the first digit.

3. The alternate form causes the result to always contain a decimal point, even if no digits follow it.

    The precision determines the number of digits after the decimal point and defaults to 6.

4. The alternate form causes the result to always contain a decimal point, and trailing zeroes are not removed as they would otherwise be.

    The precision determines the number of significant digits before and after the decimal point and defaults to 6.

5. If precision is `N`, the output is truncated to `N` characters.

6. See [**PEP 237**](https://www.python.org/dev/peps/pep-0237).

++ [Python Doc](https://docs.python.org/3/library/stdtypes.html)

---

## Number Manipulation and F Strings in Python

### Number Manipulation

```python
#	Int
x = 1
y = 35656222554887711
z = -3255522

#	Float
x = -35.59
y = 35e3
z = 12E4
k = -87.7e100

#	Complex
x = 3+5j
y = 5j
z = -5j

x = 1    # Int
y = 2.8  # Float
z = 1j   # Complex

#	Convert from int to float:
a = float(x)

#	Convert from float to int:
b = int(y)

#	Convert from int to complex:
c = complex(x)

print(a)	#	1.0
print(b)	#	2
print(c)	#	(1+0j)
print(type(a))	#	Float
print(type(b))	#	Int
print(type(c))	#	Complex

```

### String Formatting

```python
quantity = 3
itemno = 567
price = 49.95

myorder = "I want {} pieces of item {} for {} dollars."
print(myorder.format(quantity, itemno, price))
#	Output: I want 3 pieces of item 567 for 49.95 dollars.

myorder = "I want to pay {2} dollars for {0} pieces of item {1}."
print(myorder.format(quantity, itemno, price))
#	Output: I want to pay 49.95 dollars for 3 pieces of item 567.

name = 'Hex'
age = 24
print(f"Hello, My name is {name} and I'm {age} years old.")
#	Output: Hello, My name is Hex and I'm 24 years old.
```

- F Strings are the shortcut to String.Format() function.

---

## Control Flow with if / else and Conditional Operators

### Conditinal Operators:

- Equals: a == b
- Not Equals: a != b
- Less than: a < b
- Less than or equal to: a <= b
- Greater than: a > b
- Greater than or equal to: a >= b

```python
a = 200
b = 33
if b > a:
  print("b is greater than a")
elif a == b:
  print("a and b are equal")
else:
  print("a is greater than b")

if a > b: print("a is greater than b")

print("A") if a > b else print("B")
print("A") if a > b else print("=") if a == b else print("B")

'''
Output:
a is greater than b
a is greater than b
A
A
'''

```

- Multi-line string do not generate code unless they are docstrings. Good for multi-line comments.  [Source](https://twitter.com/gvanrossum/status/112670605505077248)

### Logical Operators

| Operator | Description                                             | Example               |
| :------- | :------------------------------------------------------ | :-------------------- |
| and      | Returns True if both statements are true                | x < 5 and x < 10      |
| or       | Returns True if one of the statements is true           | x < 5 or x < 4        |
| not      | Reverse the result, returns False if the result is true | not(x < 5 and x < 10) |

### Identity Operators

| Operator | Description                                            | Example    |
| :------- | :----------------------------------------------------- | :--------- |
| is       | Returns True if both variables are the same object     | x is y     |
| is not   | Returns True if both variables are not the same object | x is not y |

### Membership Operators

| Operator | Description                                                  | Example    |
| :------- | :----------------------------------------------------------- | :--------- |
| in       | Returns True if a sequence with the specified value is present in the object | x in y     |
| not in   | Returns True if a sequence with the specified value is not present in the object | x not in y |

### Bitwise Operators

| Operator | Name                 | Description                                                  |
| :------- | :------------------- | :----------------------------------------------------------- |
| &        | AND                  | Sets each bit to 1 if both bits are 1                        |
| \|       | OR                   | Sets each bit to 1 if one of two bits is 1                   |
| ^        | XOR                  | Sets each bit to 1 if only one of two bits is 1              |
| ~        | NOT                  | Inverts all the bits                                         |
| <<       | Zero fill left shift | Shift left by pushing zeros in from the right and let the leftmost bits fall off |
| >>       | Signed right shift   | Shift right by pushing copies of the leftmost bit in from the left, and let the rightmost bits fall off |

++ [W3](https://www.w3schools.com/python/python_operators.asp)

---

## Random Module

```python
import random as rand

rand_var = rand.random()		#	Returns Float
print(rand_var)				#	0.7862125697867911

rand_var = rand.randint(0, 1000)	#	Return Int between
print(rand_var)				#	654

rand_var = rand.randrange(100)		#	Max value is the given argument
print(rand_var)				#	25
```

- randint() is an alias for `randrange(start, stop+1)` .

++ [W3](https://www.w3schools.com/python/ref_random_randint.asp)

---

## Offset and Appending Items to Lists

```python
thislist = ["apple", "banana", "cherry", "orange", "kiwi", "melon", "mango"]
print(thislist[0])		#	apple
print(thislist[-1])		#	mango
print(thislist[1:4])		#	['banana', 'cherry', 'orange']
print(thislist[:4])		#	['apple', 'banana', 'cherry', 'orange']
print(thislist[2:])		#	['cherry', 'orange', 'kiwi', 'melon', 'mango']

thislist.append(15)
print(thislist)
#	Output: ['apple', 'banana', 'cherry', 'orange', 'kiwi', 'melon', 'mango', 15]

thislist = ["apple", "banana", "cherry"]
thislist.insert(2, "watermelon")
print(thislist)
#	Output: 'apple', 'banana', 'watermelon', 'cherry']

thislist = ["apple", "banana", "cherry"]
tropical = ["mango", "pineapple", "papaya"]
thislist.extend(tropical)
print(thislist)
#	Output: ['apple', 'banana', 'cherry', 'mango', 'pineapple', 'papaya']

thistuple = ("kiwi", "orange")
thislist.extend(thistuple)
print(thislist)
#	Output: ['apple', 'banana', 'cherry', 'mango', 'pineapple', 'papaya', 'kiwi', 'orange']
```

- List items are ordered, changeable, and allow duplicate values.
- The list is changeable, meaning that we can change, add, and remove items in a list after it has been created.
- Lists elements can be anything. There is no set data type.
- List.extend() takes any iterable.

++ [W3](https://www.w3schools.com/python/python_lists.asp)

---

## Index Errors and Working with Nested Lists

```python
lst = [
	["element", 0, (1+3j)],
	[-12345, 13e10],
	[],
	[-85e-10],
	100000
]
print(lst)
#	Output: [['element', 0, (1+3j)], [-12345, 130000000000.0], [], [-8.5e-09], 100000]

print(lst[2][0])	#	Error. Index out of range.
print(lst[4][0])	#	Error. Index out of range.
print(lst[0][2])	#	(1+3j)
print(lst[1][1])	#	130000000000.0
print(lst[3][0])	#	-8.5e-09
print(lst[4])		#	100000
```

- Python does not have built-in support for Arrays, but Lists can be used instead.

---

## Rock Paper Scissors

```python
import random as rand

options = ["rock", "scissors", "paper"]

user_option = input("Roll for it. ")
user_option = user_option.lower()

comp_option = options[ rand.randint(-1,2) ]
print(f"Computer has chosen {comp_option}.")

if user_option == comp_option:
	print("It is a draw!")
elif options[ options.index(user_option) - 1 ] == comp_option:
	print("Computer wins!")
else:
	print("You win!")

```

- The string lower() method converts all uppercase characters in a string into lowercase characters and returns it.

---

## For loops with lists and the range() function

```python
fruits = ["apple", "banana", "cherry"]
for x in fruits:
	if x == "banana":
		continue
	if x == "cherry":
		break
	print(x)
else:
	print("We have reached the end.")
#	Output: apple

for x in range(6):
	print(x)
else:
	print("Finally finished!")
"""
Output:
0
1
2
3
4
5
Finally finished!
"""
```

- The `else` block will NOT be executed if the loop is stopped by a `break` statement.

---

## The FizzBuzz Question

Description of the question: “Write a program that prints the numbers from 1 to 100. But for multiples of three print “Fizz” instead of the number and for the multiples of five print “Buzz”. For numbers which are multiples of both three and five print “FizzBuzz”.” [Source](https://www.tomdalling.com/blog/software-design/fizzbuzz-in-too-much-detail/)

```python
for i in range(1, 100):
	x = ""
	if i % 3 == 0:
		x += "Fizz"
	if i % 5 == 0:
		x += "Buzz"
	if i % 3 != 0 and i % 5 != 0:
		x += str(i)
	print(x)


"""
Output:
1
2
Fizz
4
Buzz
Fizz
7
8
Fizz
Buzz
11
Fizz
13
14
FizzBuzz
...
"""
```

---

## Password Generator

```python
import random as rand
import string as str

accepted_characters = str.ascii_lowercase + str.ascii_uppercase + str.digits

request = input("Add extra fuckery? (y) or (n)")
if (request == "y"):
	accepted_characters += str.punctuation

rand_max = len(accepted_characters)

request = input("Give me the length: ")
request = int(request)

out = ""
for i in list(range(request)):
	out += accepted_characters[ rand.randint(-1, rand_max) ]

print(out)
```

- String.punctuation: String of ASCII characters which are considered punctuation characters in the `C` locale: `!"#$%&'()*+,-./:;<=>?@[\]^_``{|}~`.

++ [Python Docs](https://docs.python.org/3/library/string.html)

---

## Defining and Calling Functions

```python
def my_function(fname):
	print(fname + " and me")
my_function("Linux")
#	Output: Linux and me

#	Arbitrary Arguments
def arb_func(*args):
	print("Fine with " + args[0])	#	Valid
	print("Error on " + args[2])	#	Error
arb_func("Emil", "Tobias")
#	Output: Fine with Emil

#	Keyword Arguments
def kw_func(child3, child2, child1):
	print("The youngest child is " + child3)
kw_func(child1 = "Emil", child2 = "Tobias", child3 = "Linux")
#	Output: The youngest child is Linux

#	Arbitrary Keyword Arguments
def arb_kw_func(**kwargs):
	print("His last name is " + kwargs["lname"])
arb_kw_func(fname = "Tobias", lname = "Refsnes")
#	Output: His last name is Refsnes

#	Arbitrary Keyword Arguments 2
def illust(**kwargs):
    print(kwargs)
	for key, value in kwargs.items():
		print("%s is %s" % (key, value))
illust(this="random", that="valid")
"""
Output:
{'this': 'random', 'that': 'valid'}
this is random
that is valid
"""

#	Anonymous Functions
square = lambda x: x*x
print(square(5))
#	Output: 25
```

- Asterisk(*): Used when the number of arguments are unknown. The function will receive a *tuple* of arguments, and can access the items accordingly.
- *Arbitrary Arguments* are often shortened to **args* in Python documentations.
- The phrase *Keyword Arguments* are often shortened to *kwargs* in Python documentations.
- Lambda: Lambda keyword is used to create anonymous functions.

++ [W3](https://www.w3schools.com/python/python_functions.asp)

++ [GfG](https://www.geeksforgeeks.org/functions-in-python/)

---

## While Loops

```python
count = 0
while count < 3:
	count = count + 1	#	There is no ++ operator.
	print("Hello Mortal")
"""
Output:
Hello Mortal
Hello Mortal
Hello Mortal
"""

a = [1, 2, 3, 4]
while a:
	print(a.pop())	#	Removes and returns the last element in list.
"""
Output:
4
3
2
1
"""

count = 0
while count < 5: count += 1; print("This is a one liner!")
"""
Output:
This is a one liner!
This is a one liner!
This is a one liner!
This is a one liner!
This is a one liner!
"""

i = 0
while i < 4:
	i += 1
	print(i)
	break
else:	#	Not executed as there is a break
	print("No Break")
"""
Output:
1
"""
```

- The `else` block will NOT be executed if the loop is stopped by a `break` statement.

++ [W3](https://www.w3schools.com/python/python_while_loops.asp)

++ [GfG](https://www.geeksforgeeks.org/python-while-loop/)

---

Finished up at 17:48 on  June 27, 2021.
