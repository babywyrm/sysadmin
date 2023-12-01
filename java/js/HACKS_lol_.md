##
#
https://gist.github.com/nurmdrafi/b45e3ecbcca28c44480960bf523e2d39
#
##

# {JavaScript Hacks}

### Index

- [Comments](#comments)
- [var vs let vs const](#var-vs-let-vs-const)
- [Data Types](#data-types)
- [Typeof](#typeof)
- [Type Conversion](#type-conversion)
- [Operators](#operators)
- [Functions](#functions)
  - [this Keyword](#this-keyword)
- [Strings](#strings)
- [Numbers](#numbers)
- [Arrays](#arrays)
  - [Sort](#sort)
  - [Methods](#methods)
  - [map vs forEach & filter vs find](#map-vs-forEach--filter-vs-find)
- [Objects](#Objects)
- [Date](#date)
- [Maths](#maths)
- [Boolean](#boolean)
- [Switch](#switch)
- [Loops](#loops)
  - [Iterables](#Iterables)
  - [Break & Continue](#break--continue)
- [Sets & Maps](#sets--maps)
- [Scope & Hoisting](#scope--hoisting)
- [Strict Mode](#strict-mode)
- [Classes](#classes)
- [Asynchronous JavaScript](#asynchronous-javaScript)
- [ES6](#es6)
  - [Modern Operators](#modern-operaors)
  - [Destructuring](#destructuring)
- [Regex](#regex)
- [API - Application Programming Interface](#api)
  - [JSON - JavaScript Object Notation](#json)
  - [Fetch](#fetch)
- [Web API](#web-api)
  - [Cookies](#cookies)
  - [localStorage](#localstorage)
  - [sessionStorage](#sessionstorage)
  - [IndexedDB](#indexeddb)
  - [History API](#history-api)
- [DOM - Document Object Model](#dom-document-object-model)
- [Object Oriented Programming](#object-oriented-programming)
- [Prototype](#prototype)
- [Interview Preparation](#interview-preparation)

# Comments

```js
// This is a single line comment.

/*
This is a
multi-line
comment.
*/

{
  /* A JSX comment wrapped with curly bracket */
}
```

# Var vs Let vs Const

**Variables** in JavaScript are containers that hold reusable data. It is the basic unit of storage in a program.

- The value stored in a variable can be changed during program execution.
- A variable is only a name given to a memory location, all the operations done on the variable effects that memory location.
- In JavaScript, all the variables must be declared before they can be used.

**Declaration:** Variable is registered using a given name within the corresponding scope (e.g., inside a function).

**Initialization:** When you declare a variable it is automatically initialized, which means memory is allocated for the variable by the JavaScript engine.

**Assignment:** This is when a specific value is assigned to the variable.

```js
let x; // Declaration and initialization with undefined
x = "Hello World"; // Assignment

// Or all in one
let y = "Hello World";
```

🎯 [Variables and Datatypes in JavaScript](https://www.geeksforgeeks.org/variables-datatypes-javascript/?ref=gcse)

```js
[var]
✔ reassign
✔ redeclare
- function scope
- hoisted

var a; // Declaration and initialization
var a; // ✔ Re-declaration and re-initialization
var x = 5; // Declaring, initializing and assigning
var x = 10; // ✔ Re-declaring and re-assigning


[let]
✔ reassign
❌ redeclare
⭐ primitive data
      > number
      > string
- block scope
- hoisted (Temporal Death Zone)

let a; // Declaration and initialization
let a; // ❌ Re-declaration and Re-initialization
let x = 5; // Initializing and declaring variable.
let x = 10; //  Error:- cannot redeclare a value but we re-assign the value.


[const]
❌ reassign
❌ redeclare
⭐ non-primitive data
      > array
      > object
      > function
      > document.getElementById
- block scope
- hoisted (Temporal Death Zone)

const a = 10; // Initializing and declaring a variable at a time.
const b; // Error:- const should be declared and initialized.
const a = 11 // Error:- cannot redeclare the variable again.
```

```js
var message = "hello"; // Set Variable (Can be updated). // Window or Global variable.
let message = "hello"; // Set Fixed Variable (Can be change outside scope, eg within a function).
const message = "hello"; // Set Constant (Can't be redeclared or reassigned).

let name, age, country;

let output = `${message} world`; // Call variable within a String (Need back ticks).
let output = message + "world"; // Attach variable to a String (Using plus sign).

let car = { type: "Fiat", model: "500", color: "white" }; // Create Variable JSON
car.type; // Output: Fiat
car.type = "Ford"; // Updates type to "Ford"
car.type; // Output: Ford
car["type"]; // Output: Ford

let person = {
  firstName: "John",
  lastName: "Doe",
  id: 5566,
  fullName: function () {
    // function within a object is called "Method"
    return this.firstName + " " + this.lastName;
  },
};
person.fullName; // Output: John Doe

let x, y, z; // Declare multiple variables at once.
x = 5; // Set x value.
y = 6; // Set y value.
z = x + y; // Set z value with operation.
```

# Data Types

🎯 [JavaScript Data Types](https://www.programiz.com/javascript/data-types)

There are eight8️⃣ basic data types in JavaScript. They are:

| No   | Data Types  | Description                                        | Example                           |
| ---- | ----------- | -------------------------------------------------- | --------------------------------- |
| [01] | `String`    | represents textual data                            | `'hello'`, `"hello world!" etc`   |
| [02] | `Number`    | an integer or a floating-point number              | `3`, `3.234`, `3e-2` etc.         |
| [03] | `BigInt`    | an integer with arbitrary precision                | `900719925124740999n` , `1n` etc. |
| [04] | `Boolean`   | Any of two values: true or false                   | `true` and `false`                |
| [05] | `undefined` | a data type whose variable is not initialized      | `let a;`                          |
| [06] | `null`      | denotes a `null` value                             | `let a = null;`                   |
| [07] | `Symbol`    | data type whose instances are unique and immutable | `let value = Symbol('hello');`    |
| [08] | `Object`    | key-value pairs of collection of data              | `let student = { };`              |

Here, all data types except `Object` are primitive data types, whereas `Object` is non-primitive.

I. Primitive data type

1. Number
2. String
3. Boolean
4. Undefined
5. Null
6. BigInt
7. Symbol

II. Non-primitive (reference) data type

1. Booleans can be objects (if defined with the `new` keyword)
2. Numbers can be objects (if defined with the `new` keyword)
3. Strings can be objects (if defined with the `new` keyword)
4. Dates are always objects
5. Maths are always objects
6. Regular expressions are always objects
7. Arrays are always objects
8. Functions are always objects
9. Objects are always objects

## Primitive Value vs Reference Value

- `Primitive values` are immutable[Non Changeable]
- `Reference values` are mutable[Changeable]

🎯 [What Does it Mean that Primitive Values are Immutable in JavaScript?](https://techstacker.com/what-does-it-mean-that-primitive-values-are-immutuable-in-javascript/)

🎯 [[JavaScript] Mutable vs. Immutable](https://dev.to/yukiki/mutable-vs-immutable-in-javascript-24o4)

🎯 [Tiny Programming Principles: Immutability](https://www.tiny.cloud/blog/mutable-vs-immutable-javascript/)

```js
// Non-Primitive Data Examples

let x = {job: 'web developer'};
let y = x;
let x.job = 'front end developer';
console.log(x, y)
// {job: 'front end developer'} {job: 'front end developer'}
let y.job = 'full stack developer';
console.log(x, y)
// {job: 'full stack developer'} {job: 'full stack developer'}
```

```js
// Primitive Data is Non-Changeable
let n = 10;
function increase(n) {
  n++;
}
increase(n);
console.log(n); // 10

// Non-Primitive Data is Changeable
let nn = { value: 10 };
function increase0(nn) {
  nn.value++;
}
increase0(nn);
console.log(nn); // 11
```

# Typeof

In JavaScript there are 5 different data types that can contain values:

- string
- number
- boolean
- object
- function

There are 6 types of objects:

- Object
- Date
- Array
- String
- Number
- Boolean

And 2 data types that cannot contain values:

- null
- undefined

```js
// Numbers
typeof 37 === "number";
typeof 3.14 === "number";
typeof 42 === "number";
typeof -0 === "number";
typeof Math.LN2 === "number";
typeof Infinity === "number";
typeof -Infinity === "number";
typeof NaN === "number"; // "Not-A-Number"
typeof Number("1") === "number"; // Number tries to parse things into numbers
typeof Number("shoe") === "number"; // including values that cannot be type coerced to a number

// Bigint
typeof 42n === "bigint";

// Strings
typeof "" === "string";
typeof "bla" === "string";
typeof `template literal` === "string";
typeof "1" === "string"; // NOTE: that a number within a string is still typeof string
typeof typeof 1 === "string"; // typeof always returns a string
typeof String(1) === "string"; // String converts anything into a string, safer than toString

// Booleans
typeof true === "boolean";
typeof false === "boolean";
typeof Boolean(1) === "boolean"; // Boolean() will convert values based on if they're truthy or falsy
typeof !!1 === "boolean"; // two calls of the ! (logical NOT) operator are equivalent to Boolean()
typeof isNaN(null); // false | null is a object.
typeof isNaN(undefined); // true(empty) | undefined is not a number[while reading]
isNaN(); // true(empty)

// Symbols
typeof Symbol() === "symbol";
typeof Symbol("foo") === "symbol";
typeof Symbol.iterator === "symbol";

// Objects
typeof { a: 1 } === "object";
typeof [1, 2, 3, 4]; // "object" (NOT "array")
typeof Math === "object";

// to differentiate regular objects from arrays
// use Array.isArray or Object.prototype.toString.call

typeof new Date() === "object";
typeof /regex/ === "object"; // See Regular expressions section for historical results

// The following are confusing, dangerous, and wasteful. Avoid them.
typeof new Boolean(true) === "object";
typeof new Number(1) === "object";
typeof new String("abc") === "object";

// Functions
typeof function () {} === "function";
typeof class C {} === "function";
typeof Math.sin === "function"; // built-in function/method
typeof Math === "object"; // object

// Null
typeof null === "object"; // This stands since the beginning of JavaScript

// Undefined
typeof undefined === "undefined";
typeof declaredButUndefinedVariable === "undefined";
typeof undeclaredVariable === "undefined";
```

### The Constructor Property

The `constructor` property returns the constructor function for all JavaScript variables.

```js
"John".constructor                // Returns function String()  {[native code]}
(3.14).constructor                // Returns function Number()  {[native code]}
false.constructor                 // Returns function Boolean() {[native code]}
[1,2,3,4].constructor             // Returns function Array()   {[native code]}
{name:'John',age:34}.constructor  // Returns function Object()  {[native code]}
new Date().constructor            // Returns function Date()    {[native code]}
function () {}.constructor        // Returns function Function(){[native code]}
```

### Built-in JavaScript Constructors

JavaScript has built-in constructors for native objects:

```js
new String(); // A new String object
new Number(); // A new Number object
new Boolean(); // A new Boolean object
new Object(); // A new Object object
new Array(); // A new Array object
new RegExp(); // A new RegExp object
new Function(); // A new Function object
new Date(); // A new Date object
```

🎯**NOTE:** The `Math()` object is not in the list. `Math` is a global object. The `new` keyword cannot be used on `Math`.

### Manually Check Individual Object

```js
// Create a function which able to check input is Array or NOT.
function isArray(myArray) {
  return console.log(myArray.constructor.toString().includes("Array"));
}
isArray([1, 2, 3, 4, 5]); // true
isArray({ name: "Nur Rafi" }); // false
```

### Difference Between Undefined and Null

`undefined` and `null` are equal in value but different in type:

```js
typeof undefined; // returns 'undefined'
typeof null; // returns 'object'
```

In JavaScript, `undefined` means a variable has been declared but has not yet been assigned a value, such as:

```js
var testVar;
alert(testVar); // undefined
alert(typeof testVar); // undefined
```

`null` is an assignment value. It can be assigned to a variable as a representation of no value:

```js
var testVar = null;
alert(testVar); // shows null
alert(typeof testVar); // shows object
```

From the preceding examples, it is clear that undefined and null are two distinct types: undefined is a type itself (undefined) while null is an object.

```js
null === undefined; // false ( null => 0 , undefined => NaN)
null === object; // true
null == undefined; // true
null === null; // true
```

`undefined` value is undefined but it has a memory reference.
`undefined` used for unintentionally missing values.
`null` value is undefined but it doesn't exist.
`null` used for unintentionally missing values.

```js
null = 'value' // ReferenceError
undefined = 'value' // 'value'
```

### Different ways you will get undefined

1. Variable value not assign

```js
let first;
console.log(first); // undefined
```

2. Forget to use return keyword

```js
function second(x, y) {
  const sum = x + y;
  // forget to return
}
```

3. Return keyword used but didn't return anything

```js
function add(a, b) {
  const sum = a + b;
  return;
}
const result = second(3, 91);
console.log(result);
```

4. Function parameter that isn't passed

```js
function double(a, b) {
  const result = a * 2;
  console.log(b); // undefined
  return result;
}

double(81);
```

5. Accessing a property that doesn't exist

```js
fifth = { name: "Alex", age: 30, location: "USA" };

console.log(fifth.phone); // undefined
```

6. Accessing array element out of range

```js
const sixth = [40, 30, 20, 10];
console.log(sixth[10]); // undefined
```

7. Accessing deleted array element

```js
const seventh = [10, 20, 30, 40];
delete seventh[2]; // bad practice
console.log(seventh[2]); // undefined
```

8. Explicitly set value to undefined

```js
const eight = undefined;
console.log(eight);

const myObj = { name: "Nur Rafi", profession: null };
console.log(myObj.profession);
```

# Type Conversion

There are two types of type conversion in JavaScript.

- Implicit Conversion - automatic type conversion [by JavaScript]
- Explicit Conversion - manual type conversion [by Programmer]

🎯 [JS Is Weird](https://jsisweird.com/) - MCQ

🎯 [What the f\*ck JavaScript?](https://github.com/denysdovhan/wtfjs)

🎯 [JavaScript Type Conversions](https://www.programiz.com/javascript/type-conversion) - programiz

🎯 [JavaScript | Type Conversion](https://www.geeksforgeeks.org/javascript-type-conversion/?ref=rp) - geeksforgeeks

🎯 [JavaScript Type Conversion](https://www.w3schools.com/js/js_type_conversion.asp) - w3schools

🎯 [What is Type Coercion in JavaScript ?](https://www.geeksforgeeks.org/what-is-type-coercion-in-javascript/) - geeksforgeeks

🎯 [How To Use JavaScript Unary Operators](https://www.digitalocean.com/community/tutorials/javascript-unary-operators-simple-and-useful) - digitalocean

# Operators

🎯 [JavaScript Operators](https://www.programiz.com/javascript/operators) - Programiz

🎯 [Expressions and operators](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators) - MDN Web Docs

## What is an Operator?

In JavaScript, an operator is a special symbol used to perform operations on operands (values and variables). For example,

```js
2 + 3; // 5
```

Here `+` is an operator that performs addition, and `2` and `3` are operands.

There are following types of operators in JavaScript.

1. Assignment Operators
2. Arithmetic Operators
3. Comparison Operators
4. Logical Operators
5. Bitwise Operators
6. String Operators
7. Other Operators

🎯 [You MUST store this Javascript Operator Index](https://dev.to/codeoz/you-must-store-this-javascript-operator-index-2bec?fbclid=IwAR2Ou_aelu5Ih5bpip7IcjaeDst3Vd4-PlEJ11Q5if8Jw0aSQdUfXmsjujE)

🎯 [Expressions and operators](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators) - MDN Web Docs

🎯 [Operator Precedence Table](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_Precedence#table)

🎯**NOTE:**

- `spread syntax` is intentionally not included in the table — because, to quote an an answer at Stack Overflow, “Spread syntax is not an operator and therefore does not have a precedence. It is part of the array literal and function call (and object literal) syntax.”
- Grouping ( ... ) has a highest precidence
- Within Arithmetic Operators Postfix Operators has highest precidence `count++` `count--`

### Arithmetic Operators

```js
+   // Addition
-   // Subtraction
*   // Multiplication
**  // Exponentiation (ES2016)
/   // Division
%   // Modulus (Division Remainder)(Modulo Operation)
++  // Increment
--  // Decrement
```

#### Increment & Decrement Operators

🎯 [Javascript Increment And Decrement Operators](https://www.youtube.com/watch?v=CyZgsYNOxqI)

```js
// Post Increment Operator
let a = 10;
a++; // <= short form | full form => num = num + 1 OR num += 1; [increase 1 with previous value and store in the variable]
// **NOTE:** a++[postfix operator] returns old value
console.log(a); // 11 [Increment after call]

// Pre Increment Operator
let b = 10;
++b; // 11 **NOTE:** ++b[prefix operator] returns new/current value
console.log(b); // 11 [same return after call]
```

#### 3 ways to increment or decrement value

```js
number = number + 1;
number += 1;
number++;

///

number = number - 1;
number -= 1;
number--;
```

### Assignment Operators

```js
=     // Example: x = y     // Same As: x = y
+=    // Example: x += y    // Same As: x = x + y
-=    // Example: x -= y    // Same As: x = x - y
*=    // Example: x *= y    // Same As: x = x * y
/=    // Example: x /= y    // Same As: x = x / y
%=    // Example: x %= y    // Same As: x = x % y
<<=   // Example: x <<= y   // Same As:x = x << y
>>=   // Example: x >>= y   // Same As:x = x >> y
>>>=  // Example: x >>>= y  // Same As:x = x >>> y
&=    // Example: x &= y    // Same As:x = x & y
^=    // Example: x ^= y    // Same As:x = x ^ y
|=    // Example: x |= y    // Same As:x = x | y
**=   // Example: x **= y   // Same As:x = x ** y
```

### Comparison Operators

```js
==    (equal to)
===   (equal value and equal type)
!=    (not equal)
!==   (not equal value or not equal type)
>     (greater than)
<     (less than)
>=    (greater than or equal to)
<=    (less than or equal to)
?     (ternary operator)
```

### Logical Operators

```js
&&(AND)
(true && true) // true;
(true && false) // false;

||(OR)
(true || true) // true;
(true || false) // true;
(false || true || true) // true;

!(NOT)
!true // false;
!false // true
```

🎯 [JavaScript Comparison and Logical Operators](https://www.programiz.com/javascript/comparison-logical)

### Type Operators

```js
typeof		// Returns the type of a variable
instanceof	// Returns true if an object is an instance of an object type
```

## Conditional Operator

🎯 [JavaScript If-Else and If-Then – JS Conditional Statements](https://www.freecodecamp.org/news/javascript-if-else-and-if-then-js-conditional-statements/)

### IF / Conditional Value [Ternary Operator]

```js
const age = 20;
// age >= 18 ? console.log('I like to drink wine 😎') :
// console.log('I like to drink water 😎');

const drink = age >= 18 ? "wine" : "water";
console.log(drink);
console.log(`I like to drink ${age >= 18 ? "wine" : "water"}`);
console.log(`I like to drink ${drink}`);

// syntax:
// <expression> ? <value-if-true> : <value-if-false>
```

### IF / Conditional Statement

```js
if (condition) { ... }

if (hour < 18) {
    greeting = "Good day";
} else {
    greeting = "Good evening";
}

if (time < 10) {
    greeting = "Good morning";
} else if (time < 20) {
    greeting = "Good day";
} else {
    greeting = "Good evening";
}
```

### Tricks of Operators

#### Convert String to Number using (+)

Adding increment(+) operator before `String` typed number can convert to `Number`

```js
const str = "50";
const strToNumber = +str;
console.log(strToNumber); // 50
```

### Check Even/Odd Number using Function and Modulus Operator(%)

```js
function isEven(number) {
  if (number % 2 == 0) {
    return true;
  }
  return false;
}
isEven(199);
```

### Truthy and Falsy Values

`falsy` values:

- false
- 0 (zero)
- -0 (negative zero)
- 0n (BigInt zero)
- "", '', `` (empty string)
- null
- undefined
- NaN (Not a Number)
- `function() { // return something but forget to store function variable or forget to declare return keyword }` (undefined)

`truthy` values:

- any number (positive or negative)
- " ", ' '(whitespace)
- '0', "0"
- "false"
- [] empty array
- {} empty object
- anything else that is not falsy will be truthy

# Functions

🎯 [A Closer Look at Functions](https://devrafe.blogspot.com/2021/09/a-closer-look-at-functions.html)

🎯 ['this' is Shit](https://devrafe.blogspot.com/2021/08/this-is-shit.html)

Reuseable code blocks are called "Function".

### Function Declaration

JavaScript functions are defined with the `function` keyword.

```js
// Create Function
function sum(x, y) {
  return x + y;
}
// Call Function
sum(x, y);
```

Semicolons(;) are used to separate **`executable statements`**.

Since a function declaration is not an **`executable statement`**, it is not common to end it with a semicolon(;).

But using an semicolon(;) will not throw error.

#### Function With Default Value

```js
function myFunction(x, y = 10) {
  // y is 10 if not passed or undefined
  return x + y;
}
myFunction(5); // will return 15
```

### Function Expressions

A JavaScript function can also be defined using an expression.

A function expression can be stored in a variable:

```js
const x = function (a, b) {
  return a * b;
};
```

After a function expression has been stored in a variable, the variable can be used as a function:

```js
const x = function (a, b) {
  return a * b;
};
console.log(x(4, 3));
```

### Function Return

Without return output will be undefined

```js
function test(a, b) {
  a * b;
}

let test = test();
console.log(test); // undefined
```

if we write return keyword without statement or line-break after return, JavaScript will close this line using semicolon(;) and returns undefined.

```js
function test(a, b) {
  return; // JavaScript add semiclone(;) here, close this statement and Stop executing this function.
  a * b;
}

let test = test();
console.log(test); // undefined
```

### Function Hoisting

Hoisting is a JavaScript mechanism where variables and function declarations are moved to the top of their scope before code execution.

**🎯NOTE:**

- Variable assignment takes precedence over function declaration
```js
var double = 22;

function double(num) {
  return (num*2);
}

console.log(typeof double); // Output: number
```
- Function declarations take precedence over variable declarations
```js
var double;

function double(num) {
  return (num*2);
}

console.log(typeof double); // Output: function
```

🎯 [Understanding Hoisting in JavaScript](https://www.digitalocean.com/community/tutorials/understanding-hoisting-in-javascript) - Digital Ocean

🎯 [JavaScript Scoping and Hoisting](http://www.adequatelygood.com/JavaScript-Scoping-and-Hoisting.html)

JavaScript functions can be loosely classified as the following:

1. Function declarations
2. Function expressions

#### Function declarations(Hoisting)

```js
hoisted(); // Output: "This function has been hoisted."

function hoisted() {
  console.log("This function has been hoisted.");
}
```

#### Function Expressions(Hoisting)

```js
expression(); //Output: "TypeError: expression is not a function

var expression = function () {
  console.log("Will this work?");
};
```

Let’s try the combination of a function declaration and expression.

```js
expression(); // Output: TypeError: expression is not a function

var expression = function hoisting() {
  console.log("Will this work?");
};
```

### Immediately Invoked Function Expression

Syntax

```js
(function () {
  // statements;
})();
```

```js
let result = (function (a, b) {
  return a - b;
})(100, 42);

console.log(result); // 58
```

**Example**

```js
let count = 0;
(function immediate() {
  if (count === 0) {
    let count = 1; // let and const have [Block Scope]
    console.log(count); // returns 1 [Block Scope]
  }
  console.log(count); // returns 0 [Global Scope]
})();
```

### Functions are Objects

The `typeof` operator in JavaScript returns **"function"** for functions.

But, JavaScript functions can best be described as objects.

JavaScript functions have both **properties** and **methods**.

```js
console.dir(myFunction); // returns function Object
```

The `arguments.length` **property** returns the number of arguments received when the function was invoked:

```js
function myFunction(a, b) {
  return arguments.length;
}
```

The `toString()` **method** returns the function as a string:

```js
function myFunction(a, b) {
  return a * b;
}

let textStr = myFunction.toString(); // returns function body as a str

let text = myFunction(5, 6).toString(); // function result convert to str
console.log(text);
```

### Arrow Function

🎯 [Arrow Function](https://www.programiz.com/javascript/arrow-function) - Programiz

Arrow functions allows a short syntax for writing function expressions.

You don't need the `function` keyword, the `return` keyword, and the **curly brackets**.

```js
// ES5
const x = function (a, b) {
  return a * b;
};

// ES6
const x = (a, b) => a * b;
```

Arrow functions do not have their own `this`. They are not well suited for defining **object methods**.

Arrow functions are not hoisted. They must be defined before they are used.

Using const is safer than using var, because a function expression is always constant value.

### Function Constructor (Class like)

```js
function Person(first, last, age, eye) {
  this.firstName = first;
  this.lastName = last;
  this.age = age;
  this.eyeColor = eye;
}

let myFather = new Person("John", "Doe", 50, "blue");
let myMother = new Person("Sally", "Rally", 48, "green");
```

### Function with Callback

A callback function is a function passed into another function
as an argument, which is then invoked inside the outer function
to complete some kind of routine or action.

🎯 [JavaScript CallBack Function](https://www.programiz.com/javascript/callback)

```js
// function
function greet(name, callback) {
  console.log(`Hi, ${name}`);
  callback();
}

// callback function
function callMe() {
  console.log("I am from callback function");
}

// passing function as an argument
greet("Rafe", callMe);
```

### Function Recursion

Recursion is a process of calling itself. A function that calls itself is called a recursive function. A recursive function must have a condition to stop calling itself. Otherwise, the function is called indefinitely.

🎯 [JavaScript Recursion](https://www.programiz.com/javascript/recursion) - Programiz

🎯 [Difference between Recursion and Iteration](https://www.geeksforgeeks.org/difference-between-recursion-and-iteration/) - GeeksforGeeks

Syntax

```js
function recurse() {
  // function code
  recurse();
  // function code
}

recurse();
```

#### Understand for loop in a forward and reverse way

```js
function recursion(i) {
  if (i > 5) {
    return;
  }
  console.log(i);
  recursion(i + 1);
}

recursion(1);
```

#### Understand recursion using sum of numbers

```js
function sum(i) {
  if (i == 1) {
    return 1;
  }
  return i + sum(--i);
}

console.log(sum(5));
```

#### Explore Factorial Recursion using a for loop concept

```js
function getFactorial(i) {
  if (i == 1) {
    return 1;
  }
  return i * getFactorial(--i);
  // return getFactorial(--i) * i;
}
console.log(getFactorial(4));
```

### Function Closure, Encapsulation, Private variable

🎯 [JavaScript Closures](https://www.w3schools.com/js/js_function_closures.asp) - W3Schools

🎯 [JavaScript Closures](https://www.programiz.com/javascript/closure) - Programiz

🎯 [JavaScript Closure Tutorial – With JS Closure Example Code](https://www.freecodecamp.org/news/javascript-closure-tutorial-with-js-closure-example-code/) - freecodecamp

**🎯NOTE:**

- Access to an outer function's scope from an inner function
- A closure is the combination of a function bundled together (enclosed) with references to its surrounding state (the lexical environment)

- যদি কোনো একটা function এর ভিতর আবার আরেকটা function কে use করা হয় অথবা function কে return করা হয়, সেই function টা যদি parent function এর ভিতর কোনো variable কে access করে তাহলে তার নিজস্ব একটা Closure, Private variable create করে।
  - Close করে রাখা variable কেউ কিছু করতে পারবে না 😎
    - closed environment
    - cannot access
    - cannot change

```js
function stopWatch() {
  let counter = 0; // increase this reference value each time when call f
  return function () {
    counter++;
    return counter;
  };
}
// here counter = 0; is closure;

let clock1 = stopWatch();
console.log(clock1); // anonymous function
console.log(clock1()); // 1
console.log(clock1()); // 2
console.log(clock1()); // 3
console.log(clock1()); // 4
console.log(clock1()); // 5

let clock2 = stopWatch();
console.log(clock2()); // 1
console.log(clock2()); // 2
```

**🎯 BEST Example:** Create Bank Accounts by Owner Name

```js
// single return
const bank = (owner) => {
  // প্রথমে function create করতে হবে
  let balance = 0; // function এর ভিতর initial value set করতে হবে, যা inner function use করবে
  return (amount) => {
    // anonymous function, call করার প্রয়োজন নাই, যদি function expression use করা হয় তাহলে call করতে হবে এবং parameter থাকলে pass করতে হবে
    balance += balance + amount;
    return balance; // অবশ্যই return করতে হবে
  };
};

// create accounts by owner name
const sultansBank = bank("Sultan"); // ১ম function call করে variable এর মধ্যে set করতে হবে, parameter থাকলে pass করতে হবে

// individual transactions
console.log(sultansBank(100)); // তারপর সেই variable টাকে আবার function এর মত use করে return এর ভিতরের যদি parameter থাকে তাহলে pass করতে হবে
console.log(sultansBank(500));
console.log(sultansBank(300));

console.log(sultansBank.balance); // undefined [বাহির থেকে কেউ Balance জানতে পারবে না]

// multiple return {object}
const bank = (owner) => {
  let balance = 0;
  return {
    deposit: (amount) => {
      balance += balance + amount;
      return balance;
    },

    withdraw: (amount) => {
      balance += balance - amount;
      return balance;
    },
  };
};

// create accounts by owner name
const sultansBank = bank("Sultan");
const farooqisBank = bank("Farooqi");

// individual transactions
console.log(sultansBank.deposit(100));
console.log(sultansBank.deposit(500));
console.log(sultansBank.balance); // undefined
console.log(sultansBank.withdraw(300));
console.log(sultansBank.deposit(100));

console.log(faroowisBank.deposit(100));
console.log(faroowisBank.deposit(200));
console.log(faroowisBank.withdraw(300));
console.log(faroowisBank.balance); // undefined
```

### Function Parameters

🎯 [Function Parameters](https://www.w3schools.com/js/js_function_parameters.asp) - W3Schools

🎯 [Parameter](https://developer.mozilla.org/en-US/docs/Glossary/Parameter) - MDN Web Docs

Function `parameters` are the names listed in the function definition.

Function `arguments` are the real values passed to (and received by) the function.

#### What are formal and actual parameters?

When a function is called, the values (expressions) that are passed in the function call are called the `arguments` or `actual parameters`. The parameter used in function definition statement which contain data type on its time of declaration is called `formal parameter`.

#### Parameter Rules

- JavaScript function definitions do not specify data types for parameters.
- JavaScript functions do not perform type checking on the passed arguments.
- JavaScript functions do not check the number of arguments received.

**Note:** This is why TypeScript introduced

### Arguments Object

JavaScript functions have a built-in object called the arguments object.

The argument object contains an array of the arguments used when the function was called (invoked).

This way you can simply use a function to find (for instance) the highest value in a list of numbers:

```js
// Calculate Unlimited number of arguments using Arguments Object
const numbers = [10, 20, 30, 40, 50];

function add() {
  let result = 0;
  for (let i = 0; i < arguments.length; i++) {
    result += arguments[i]; // Same As: x = x + y
  }
  return result;
}
console.log(add(...numbers)); // SPREAD operator // returns: 150
```

### Arguments Keyword

- Arguments keyword exists but its only exists in the Regular function but not in the arrow function.

- Arguments keyword is not important in Modern JavaScript anymore because now we have a Modern Way that dealing with multiple parameters.

```js
const addExpr = function (a, b) {
  console.log(arguments); // returns: arguments array
  return a + b;
};
addExpr(2, 5);
addExpr(2, 5, 8, 12); // we can add more arguments

const addArrow = (a, b) => {
  console.log(arguments); // returns: ReferenceError: arguments is not defined
  return a + b;
};
addArrow(2, 5, 8);
```

### How Passing Arguments Works: Value vs. Reference

🎯 [Pass By Value in JavaScript](https://dev.to/ale3oula/pass-by-value-in-javascript-5gch) - dev.to

#### Arguments are Passed by Value

The parameters, in a function call, are the function's arguments.

JavaScript arguments are passed by `value`: The function only gets to know the values, not the argument's locations.

If a function changes an argument's value, it does not change the parameter's original value.

Changes to arguments are not visible (reflected) outside the function.

```js
function a(x, y) {
  x = x * 5;
  return x * y;
}

let m = 5;
let n = 6;

console.log(a(m, n));
console.log(m); // 5 Unchanged
```

#### Objects are Passed by Reference

In JavaScript, object references are values.

Because of this, objects will behave like they are passed by `reference`:

If a function changes an object property, it changes the original value.

Changes to object properties are visible (reflected) outside the function.

```js
function a(x) {
  x.one = 7;
  return x.one * x.two;
}

let m = {
  one: 4,
  two: 5,
};

console.log(a(m));
console.log(m); // 7 Changed
```

# **this** Keyword

🎯 ['this' is Shit](https://devrafe.blogspot.com/2021/08/this-is-shit.html)

- `this` হচ্ছে `execution context`;
- Depends on where `this` is executing;
- Regular method হলে বাম পাশে যে আছে সেটাকে context হবে;
- Arrow function হলে উপরের level অনুসারে context ধরবে;
- কোনো DOM এর element এ click করলে, সেই event টাই `this` বুঝাবে;
- DOM এর element এর event টা কোনো event handler হলে (যেটা পরে execute হবে), তাহলে function টা calling এর উপর `this` নির্ভর করবে।

- `this` keyword refers to the object it belongs to.
- It has different values depending on where it is used:
  - Alone, `this` refers to the global object. [implicit binding]
  - In a function, `this` refers to the global object. [implicit binding]
  - In a function, in strict mode, `this` is `undefined`. [implicit binding]
  - In a Object method, `this` refers to the owner object. [implicit binding]
  - Methods like `call()`, and `apply()` can refer `this` to any object. [explicit binding]
  - In an event, `this` refers to the element that received the event.

🎯 ['this' is Shit](https://devrafe.blogspot.com/2021/08/this-is-shit.html) - [Dev Rafé](https://twitter.com/MohamodRafi)

🎯 [Javascript This keyword](https://www.youtube.com/watch?v=S2pBGSeUFCk) - Dipesh Malvia

🎯 [JavaScript | Function binding](https://www.geeksforgeeks.org/javascript-function-binding/) - GeeksforGeeks

🎯 [Difference between call,apply and bind](https://dev.to/hebashakeel/difference-between-call-apply-and-bind-4p98) - dev.to

🎯 [The difference between JavaScript’s call, apply, and bind methods](https://www.freecodecamp.org/news/the-difference-between-javascripts-call-apply-and-bind-methods-4e69917f77bd/) - freeCodeCamp.org

## Rules for findout what 'this' is pointing =>

1. implicit binding
2. explicit binding
3. new binding
4. window binding

## 1. implicit binding (this Set By JavaScript) =>

- Implicit Binding is applied when call a function in an Object using the dot notation
- check where is the function is called with dot notation
- left side of the dot is this object
  - `obj.function(console.log(this))` [this object]
  - `console.log(this)` [this window]
  - `myFunction(console.log(this))` [this window]
  - `<button onclick="console.log(this)">Check This</button>` [this element]
  - `<button onclick="add()">Check This</button>` [this window]
    - add(console.log(this));
- exception: arrow function will point to global object
  - arrow function cannot hold this value
  - arrow function always point 1 level up object
  - `const arrowFunc = () => console.log(this)` [this window]
  - `const obj = {normalFunc(){ const arrowFunc = () => console.log(this) }}` [this object]

```js
// object > function
const person = {
  firstName: "Nur",
  lastName: "Rafe",
  fullName: function () {
    return this.firstName + " " + this.lastName;
  },
};

let fullName = person.fullName();
console.log(fullName);

// function > para(obj) > function
function printPlayerFunction(obj) {
  obj.printPlayerName = function () {
    console.log(this.name);
  };
}

var sakib = {
  name: "Sakib",
  age: 35,
};

var tamim = {
  name: "Tamim",
  age: 35,
};
printPlayerFunction(sakib);
printPlayerFunction(tamim);

sakib.printPlayerName();
tamim.printPlayerName();

// function > para > return.object > function
var person = function (name, age) {
  return {
    name: name,
    age: age,
    printName: function () {
      console.log(this.name);
    },
  };
};

let rafe = person("rafe", 30);
rafe.printName();

// function > para > return.object > new object > function
var person = function (name, age) {
  return {
    name: name,
    age: age,
    printName: function () {
      console.log(this.name);
    },
    father: {
      name: "Mr. X",
      printName: function () {
        console.log(this.name);
      },
    },
  };
};

let rafe = person("rafe", 30);
rafe.printName();
rafe.father.printName();
```

### **this** in a Object Method

- In an object method, `this` refers to the "owner" of the method.
- The person object is the owner of the fullName method.

```js
const person = {
  firstName: "Nur",
  lastName: "Rafi",
  fullName: function () {
    return this.firstName + " " + this.lastName;
  },
  balance: 5000
};
console.log(person.fullName()); // Nur Rafi

// inside method
	> access any property [this.name]
	> change property value [this.balance - 500]
	> return something [fullName = firstName + " " + lastName]
```

```js
const person = {
  checkThis: function
  (){
    console.log(this);

    function checkThisAgain(){
      console.log(this);
    }
    checkThisAgain(🎯); // There is no calling Context. So this point to the window object.
  }
}
person.checkThis(); // {checkThis: f}
console.log(person); // {checkThis: f}

const func = person.checkThis;
func(🎯) // There is no calling Context. So this is point to the window object.
```

```js
// If there is no calling Context, then 'this' will point to the window object.
// Nested function
```

## 2. explicit binding (this Set By Developer) =>

- Borrow method from another object
- By default inside a method this always point to its own object. But we can set different object while using `explicit binding` method. In this case main function will invoke but this will point to targeted object. ✔✔✔

- `function.call(obj, variable, variable. variable...);`
  - obj => where want to use this function;
  - variables separated by comma(,);
- `function.apply(obj, [variable, variable, variable...]);`
  - obj => where want to use this function;
  - variables inside an array[] and separated by comma(,);
- `function.bind(obj, variable, variable. variable...);`
  - `bind()` similar as call but bind returns function body, that's why store in a variable then call this variable like a function. ✔✔✔

🎯**NOTE:**

কোনো একটা object এর ভিতর যদি common method থাকে, সেই method এর default হিসেবে this use করবে সেই object টাকে, কিন্তু চাইলে অন্য একটা object কে bind করে this হিসেবে pass করা যায়। সেই ক্ষেত্রে 1st method ঠিকই call হবে কিন্তু this এর জায়গায় bind করা object pass হবে।

```js
let printName = function (v1, v2, ...v3) {
  console.log(`${this.name} is ${v1}, ${v2} & ${v3}`);
};
var sakib = {
  name: "Sakib",
  age: 27,
};

let v1 = "Handsome";
let v2 = "All-rounder";
let v3 = "Best Player";

var v = [v1, v2, v3];

printName.call(sakib, v1, v2, v3);
printName.apply(sakib, v);
let newFuncBind = printName.bind(sakib, v1, v2, v3);
newFuncBind();
// OR
let newFuncBind = printName.bind(sakib);
newFuncBind(v1, v2, v3);
```

## 3. new binding =>

- new Constructor function create new object
- like

```js
let this = Object.create(null);
return this;
```

- that object name is 'this'
- using dot notation we can assign new values

```js
function Person(name, age) {
  // let this = Object.create(null);
  this.name = name;
  this.age = age;
  console.log(`${this.name} is ${this.age} years old`);
  // return this;
}

let rafe = new Person("Rafe", 30);
```

## 4. window binding =>

If none of bindings are able to point object then it will point to window object and returns [this = window object |OR| this.name = 'undefined']

### **this** Alone

When used alone, the owner is the Global object, so this refers to the Global object.

In a browser window the Global object |OR| Window object is `[object Window]`.

### Window object⤵

A global variable, window , representing the window in which the script is running.

```js
console.log(this); // window object
```

```js
Window {0: global, window: Window, self: Window, document: document, name: 'Rafe', location: Location, …}
```

```js
this.name = "Rafe";

console.log(this.name); // Rafe => Window object
console.log(window.name); // Rafe => Window object
console.log(name); // Rafe => Window object
```

### **this** in a Function (Default)

In a JavaScript function, the owner of the function is the default binding for this.

So, in a function, this refers to the Global object |OR| Window object is `[object Window]`.

```js
function checkThis() {
  console.log(this); // Window object
}
console.log(checkThis()); // undefined
```

### **this** in a Function (Strict Mode)

JavaScript strict mode does not allow default binding.

So, when used in a function, in strict mode, `this` is `undefined`.

```js
"use strict";
function checkThis() {
  console.log(this); // undefined
}
console.log(checkThis()); // undefined
```

🎯**NOTE:** [Why is "this" in an anonymous function undefined when using strict mode?](https://stackoverflow.com/a/9822631/15497939) - stackoverflow

🎯**NOTE:** What is calling Context?

# Strings

### Find / Search in a String

#### String.indexOf()

The `indexOf()` method returns the index of (the position of) the first occurrence of a specified text in a string ...

```js
let str = "Please 'locate' where locate occurs!";
let pos = str.indexOf("locate"); // returns 8
```

#### String.lastIndexOf()

The `lastIndexOf()` method returns the index of the last occurrence of a specified text in a string ...

```js
let str = "Please locate where 'locate' occurs!";
let pos = str.lastIndexOf("locate"); // returns 14
```

🎯 Both `indexOf()`, and `lastIndexOf()` return -1 if the text is not found, also Case Sensitive

```js
// Both methods accept a second parameter as the starting position for the search ...
let str = "Please locate where 'locate' occurs!";
let pos = str.indexOf("locate", 15); // returns 21
```

```js
str.indexOf("") == -1; // missing in the str
str.indexOf("") != -1; // available in the str
```

#### String.search()

The `search()` method searches a string for a specified value and returns the position of the match

```js
let str = "Please 'locate' where locate occurs!";
let pos = str.search("locate"); // returns 8
```

🎯**NOTE:**
The two methods are NOT equal. These are the differences:

- The `search()` method cannot take a second start position argument.
- The `indexOf()` method cannot take powerful search values (regular expressions).

### String.match(regexp)

The `match()` method searches a string for a match against a regular expression, and returns the matches, as an Array object.

```js
let text = "The rain in SPAIN stays mainly in the plain";
text.match(/ain/g);
// returns an array [ain, ain, ain]

let text = "The rain in SPAIN stays mainly in the plain";
text.match(/ain/gi);
// returns an array [ain, AIN, ain, ain]
```

```js
// Real Use Case 🎯
const airline = "TAP Air Portugal";
const plane = "A320";

console.log(plane[0]); //  A
console.log(plane[1]); //  3
console.log(plane[2]); //  2
console.log("B737"[0]); //  B

console.log(airline.length); //  16
console.log("B737".length); //  4

console.log(airline.indexOf("r")); //  position at 6
console.log(airline.lastIndexOf("r")); // position at 10
console.log(airline.indexOf("portugal")); //  -1 [Case Sensitive]
console.log(airline.indexOf("Portugal")); //  8
```

### Extracting String Parts 🍕🍕🍕

There are 3 methods for extracting a part of a string:

- `slice(start, end)`
- `substring(start, end)`
- `substr(start, length)`

#### The slice(start, end) Method 🍕

```js
let str = "Apple, Banana, Kiwi"; // Start counting from [1] is easier than [-1]
let res = str.slice(7, 13); // [7, 8, 9, 10, 11, 12, 13]
// returns Banana

let str = "Apple, Banana, Kiwi";
var res = str.slice(-12, -6);
// returns Banana

let str = "Apple, Banana, Kiwi";
let res = str.slice(7);
// returns Banana, Kiwi

let part = str.slice(-12);
// returns Banana, Kiwi
```

```js
// Real Use Case 🎯
const airline = "TAP Air Portugal";
const plane = "A320";

console.log(airline.slice(4)); // Only Start //  Air Portugal
console.log(airline.slice(4, 7)); // Air | (End-Start) or Base [1]

console.log(airline.slice(0, airline.indexOf(" "))); // TAP
console.log(airline.slice(airline.lastIndexOf(" ") + 1)); // Portugal

console.log(airline.slice(0, -1) + 1); //  TAP Air Portugal // When we want full length of String but don't know length value
console.log(airline.slice(-1)); // last Character

const checkMiddleSeat = function (seat) {
  // B and E are middle seats
  const s = seat.slice(-1); // returns last string
  if (s === "B" || s === "E") console.log("You got the middle seat 😖");
  else console.log("You got lucky 😃");
};
checkMiddleSeat("11B"); // You got the middle seat 😖
checkMiddleSeat("23C"); // You got lucky 😃
checkMiddleSeat("3E"); // You got the middle seat 😖
```

#### The substring(start end) Method

`substring()` is similar to `slice()`.
The difference is that `substring()` cannot accept negative indexes.

```js
let str = "Apple, Banana, Kiwi";
let part = substring(7, 13);
// returns Banana, Kiwi
```

#### The substr(start, length) Method

`substr()` is similar to `slice()`.
The difference is that the second parameter specifies the length of the extracted part.

```js
let str = "Apple, Banana, Kiwi";
let part = str.substr(7, 6);
// returns Banana

let str = "Apple, Banana, Kiwi";
let part = str.substr(7);
// returns Banana, Kiwi

let str = "Apple, Banana, Kiwi";
let part = str.substr(-4);
// returns Kiwi
```

### Replace in Strings

```js
const priceGB = "288,97£"; // Replace comma(,) and pound sign(£)
const priceUS = priceGB.replace(",", ".").replace("£", "$");
console.log(priceUS); // 288.97$

const announcement =
  "All passengers come to boarding door 23. Boarding door 23!";
console.log(announcement.replace("door", "gate")); // only replace single word

// Replace All()
console.log(announcement.replaceAll("door", "gate")); // Replace multiple words

// Regular Expression
console.log(announcement.replace(/door/g, "gate")); // Replace multiple words

const oneWord = function (str) {
  return console.log(str.toLowerCase().replace(/ /g, "")); // javascriptisthebest!
};
oneWord("JavaScript is the best!");

let str = "       Hello World!        ";
str.trim();
// Removes whitespace from both sides of a string.

let str = "       Hello World!        ";
str.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, "");
// Remove with regular expressions.
```

### String to Upper and Lower Case

```js
let text1 = "Hello World!"; // String
let text2 = text1.toUpperCase(); // text2 is text1 converted to upper

let text1 = "Hello World!"; // String
let text2 = text1.toLowerCase(); // text2 is text1 converted to lower
```

#### Fix Capitalization in Name🎯

```js
const passenger = "jOnAs"; // Should look like this
const passengerLower = passenger.toLowerCase(); // convert all to lower case
const passengerCorrect =
  passengerLower[0].toUpperCase() + passengerLower.slice(1); // convert 1st one Upper and rest of lower case
console.log(passengerCorrect);
```

#### Fix Capitalization using function🎯

```js
const fixName = function (name) {
  const lowercase = name.toLowerCase();
  const correct = lowercase[0].toUpperCase() + lowercase.slice(1);
  return correct;
};
console.log(fixName("nUrMohAmmoD"));
```

#### Comparing Emails🎯

```js
const email = "hello@rafe.io";
const loginEmail = " Hello@Rafe.Io \n";

const lowerEmail = loginEmail.toLowerCase();
const trimmedEmail = lowerEmail.trim();
console.log(trimmedEmail); //hello@rafe.io

// Single line code
const normalizeEmail = loginEmail.toLowerCase().trim();
console.log(normalizeEmail); // hello@rafe.io
console.log(email === normalizeEmail);
```

### Character at index position

```js
let str = "HELLO WORLD";
str.charAt(0);
// Returns H

str[0];
// Returns H
```

### Booleans

The `includes()` method returns `true` if a string contains a specified value otherwise returns `false`

```js
const airbus = 'Airbus A320neo';
console.log(airbus.includes('A320')); // true
console.log(airbus.includes('Boeing')); // false
console.log(airbus.startsWith('Air')); // true
console.log(airbus.endsWith('neo')); // true

// Real Use Case 🎯
if (airbus.startsWith('Airbus') && airbus.endsWith('neo')) {
console.log('Part of the NEW Airbus family');

const checkBaggage = function (items) {
const baggage = items.toLowerCase();
if (baggage.includes('knife') || baggage.includes('gun')) {
    console.log('You are NOT allowed on board')
} else {
    console.log('You are Welcome!');
}
};
checkBaggage('I have a laptop, some Food and a pocket Knife');
checkBaggage('Socks and camera');
checkBaggage('Got some snacks and gun for protection');
```

### Split & Join

```js
console.log("A+very+nice+movie".split("+")); // ["A", "very", "nice", "movie"]
console.log("Nur Mohamod Rafi".split(" ")); // ["Nur", "Mohamod", "Rafi"]

// Split output Array so Loop is available

const [firstName, ...lastName] = "Nur Mohamod Rafi".split(" ");

console.log(firstName); // Nur
console.log(...lastName); // Mohamod Rafi

// Join('') Method is OPOSITE of Split('') Method

// Join Name 1
const joinName1 = ["Mr.", firstName, lastName.toUpperCase()];
console.log(joinName1); // ['Mr.', 'Nur', 'MOHAMOD']
console.log(...joinName1); // Mr. Nur Mohamod

// Join Name 2
const joinName2 = ["Mr.", firstName, lastName.toUpperCase()].join(" ");
console.log(joinName2); // Mr. Nur MOHAMOD
```

#### Capitalization Multiple Names or Words🎯

**Solution 1**

```js
const capitalizeName = function (name) {
  const names = name.split(" "); // Array output
  console.log(names); // ['nur', 'mohamod', 'rafi']
  console.log(names[1]);
  const namesUpper = [];

  for (const n of names) {
    // Method 1 toUpperCase + Slice
    namesUpper.push(n[0].toUpperCase() + n.slice(1));
    // Method 2 Replace
    // namesUpper.push(n[0].replace(n[0], n[0].toUpperCase()));
  }
  console.log(namesUpper.join(" "));
};
capitalizeName("nur mohamod rafi");

// Split('') Output = Array // or USE [...]
// Join Output('') = String
```

**Solution 2**

```js
const capitalizeName = (name) => {
  const arr = name.split(" ");
  const newArray = [];
  arr.forEach((item) => {
    const normalize = item.toLowerCase();
    newArray.push(normalize[0].toUpperCase() + normalize.slice(1));
  });
  const capitalize = newArray.join(" ");
  return capitalize;
};

capitalizeName("nur mohamod rafi");
console.log(capitalizeName("nur mohamod rafi"));
// output: Nur Mohamod Rafi
```

### Padding

```js
const message = "Go to gate 07";
const padStart = message.padStart(25, "+");
console.log(padStart.padEnd(35, "+"));
console.log(padStart.length);
```

#### Credit Card Masking🎯

**Solution 1**

```js
const maskCreditCard = function (number) {
  const str = String(number);
  // OR
  // const str = number + ''// => Number + ''(Empthy String) = String
  const first = str.slice(0, 4); // first 4
  const last = str.slice(-4); // last 4
  return last.padStart(str.length, "*"); // Except last 4 digit full length of string will covered by * or any characters
};
console.log(maskCreditCard(56869479831659)); // Output: **********1659
```

**Solution 2**

```js
const maskCreditCard = (number) => {
  console.log(number.toString().length);
  let last4digit = number.toString().slice(-4);
  console.log(number.toString().slice(4).split("").fill("*").length);
  const mask = Array(10).fill("*").join("") + last4digit;
  console.log(mask);
  return mask;
};

console.log(maskCreditCard(56869479831659)); // Output: **********1659
```

#### Phone Number Masking🎯

```js
const maskPhoneNumber = function (number) {
  const str = String(number);
  // NUMBER to STRING Convert Leading 0 Missing
  const addZero = str.padStart(11, 0); // Leading 0 problem solved
  console.log(addZero);
  const first = addZero.slice(0, 3);
  const last = addZero.slice(-3);
  return first.padEnd(8, "*") + last;
};
console.log(maskPhoneNumber(01913093140)); // Output: 019*****140
```

### Repeat

```js
const message2 = "Bed weather... All Departures Delayed...";

console.log(message2.repeat(5)); // Repeat 5 times

const planesInline = function (n) {
  console.log(`There are ${n} planes in line ${"✈".repeat(n)}`);
};
planesInline(5); // There are 5 planes in line ✈✈✈✈✈
```

### Convert String to Array

```js
let txt = "HELLO WORLD"; // String
txt.split(); // returns ["HELLO WORLD"]
txt.split(","); // Split on commas
txt.split(" "); // Split on spaces returns ["HELLO", "WORLD"]
txt.split("|"); // Split on pipe
txt.split(""); // Split all Characters into a Array returns ["H", "E", "L", "L", "O", " ", "W", "O", "R", "L", "D"]
```

### Convert to String

🎯 The JavaScript method `toString()` converts an array to a string of (comma separated) array values.  
🎯 All JavaScript objects have a `toString()` method.

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.toString(); // returns Banana,Orange,Apple,Mango

let num = 12;
num.toString(); // returns "12" as string.
```

# Numbers

🎯 Tricks

Extra large or extra small numbers can be written with scientific (exponent) notation

```js
const num1 = 100000000;
const num2 = 100_000_000; // You can separate the number by using underscore! It's more easy to read
console.log(num2) // 100000000
```

Floating point arithmetic is not always 100% accurate.

```js
let x = 0.2 + 0.1; // 0.30000000000000004

// Best Practice
parseFloat(x.toFixed(1)); // [is perfect for working with money.] 💲💲💲
// returns 0.3
```

```js
let x = 123e5; // 12300000 [after (e*) add * 0]
let y = 123e-5; // 0.00123 [total number count will be(e-*)]
```

Check Even/Odd Number using Function and Modulus Operator(%)

```js
function isEven(number) {
  if (number % 2 == 0) {
    return true;
  }
  return false;
}
isEven(199);
```

### Integer Precision

Integers (numbers without a period or exponent notation) are accurate up to 15 digits.

```js
let x = 999999999999999; // x will be 999999999999999
let y = 9999999999999999; // y will be 10000000000000000
```

### Floating Precision🎯🎯🎯

Floating point arithmetic is not always 100% accurate.

```js
let x = 0.2 + 0.1; // 0.30000000000000004

🎯 // Best Practice
parseFloat(x.toFixed(1)); // [is perfect for working with money.] 💲💲💲
// returns 0.3

// Or
let x = (0.2 * 10 + 0.1 * 10) / 10;
// returns 0.3
```

### Checks

```js
Number.isInteger(0); // true
Number.isInteger(1); // true
Number.isInteger(-1); // true
Number.isInteger(1.5); // false
Number.isInteger("1"); // false

Number.isSafeInteger(10); // true
Number.isSafeInteger(12345678901234567890); // false

isNaN("Hello"); // true
isNaN(123); // false
typeof NaN; // Number
```

### Decimals

`toFixed()` returns a `string`, with the number written with a specified number of decimals:

```js
let x = 9.656;
x.toFixed(0); // '10' [0.5 > Next Integer][0.4 < Current Integer]
x.toFixed(1); // '9.6'
x.toFixed(2); // '9.66' [is perfect for working with money.] 💲💲💲
x.toFixed(4); // '9.6560'
x.toFixed(6); // '9.656000'
```

### Specified Length

`toPrecision()` returns a `string`, with a number written with a specified length:

```js
let x = 9.656;
x.toPrecision(); // '9.656'
x.toPrecision(2); // '9.7'
x.toPrecision(4); // '9.656'
x.toPrecision(6); // '9.65600'
```

### String `typeof` Number Parse into Int or Float

- Parsing => Analyze and Convert to a Formate

```js
parseInt("10"); // 10
parseInt("10.33"); // 10
parseInt("10 20 30"); // 10
parseInt("10 years"); // 10
parseInt("years 10"); // NaN

parseFloat("10"); // 10
parseFloat("10.33"); // 10.33
parseFloat("10 20 30"); // 10
parseFloat("10 years"); // 10
parseFloat("years 10"); // NaN
```

### Number Check / Convert

```js
Number(true); // 1
Number(false); // 0
Number("10"); // 10
Number("  10"); // 10
Number("10  "); // 10
Number(" 10  "); // 10
Number("10.33"); // 10.33
Number("10,33"); // NaN
Number("10 33"); // NaN
Number("John"); // NaN
Number(new Date("1970-01-01")); // 0
Number(new Date("1970-01-02")); // 86400000
// The number of milliseconds between 1970-01-02 and 1970-01-01 is 86400000
```

# Arrays

![alt text](https://lh3.googleusercontent.com/-EEpeq-uIcls/YUSSSk5aR9I/AAAAAAAACfo/EZ06nl4QtOMsJe5zMc0PtilBXMfkS_2ugCLcBGAsYHQ/s16000/1_XCPNNcF9l8nliSJdVxNIGw.jpeg)

### When to Use Arrays

We use arrays whenever we want to create and store a list of multiple items in a single variable. Arrays are especially useful when creating ordered collections where items in the collection can be accessed by their numerical position in the list. Just as object properties can store values of any primitive data type (as well as an array or another object), so too can arrays consist of strings, numbers, booleans, objects, or even other arrays.

## The Difference Between Arrays and Objects

🎯 In JavaScript, `arrays` use numbered indexes.
🎯 In JavaScript, `objects` use named indexes.

### Creating an Array

Syntax:

```js
// Example 1
const cars = ["Saab", "Volvo", "BMW"];

// Example 2
const cars = [
  "Saab",
  "Volvo",
  "BMW"
];

// Example 3
const cars = [];
cars[0]= "Saab";
cars[1]= "Volvo";
cars[2]= "BMW";

// Example 4
const cars = new Array("Saab", "Volvo", "BMW");

// Example 5

const cars = Array("Saab", "Volvo", "BMW"); // Without new keyword

// ❗Problems
const fruits = ["Banana", "Orange", "Apple"];
fruits[6] = "Lemon";
typeof fruits[5] // 'undefined'
// returns ['Banana', 'Orange', 'Apple', empty × 3, 'Lemon']

const exThree = [,,,]; // [empty × 3]
const exThree = ["","","",]; // [empty × 3]
const exThree = [,,""]; // [empty × 2, ""]
const points = [40]; // returns [40] ✔
const points = new Array(40); // returns [empty × 40] [length: 40❗]
const points = new Array(40, 50); // returns [40, 50]
const points = Array (40, 50); // Without new keyword output is same
const notRecommended = new Array('notRecommended') 🎯// [Performace Issue]
Array[] == new Array[] // Comparing two JavaScript objects always return false.
Array[] === new Array[] // Comparing two JavaScript objects always return false.
```

### Basic Array Operations (Method)

```js
const friends = ["Nur", "Mohamod", "Rafe"];

console.log(friends[0]); // first value;
console.log(friends[1]); // second value;
console.log(friends.length); // total value count;
console.log(friends.length - 1); // total value count - 1;
console.log(friends[friends.length - 1]); // last value name;
console.log(friends.indexof("name")); // if not match than output (-1)
console.log(friends.includes("name")); // true or false

variable.push(""); // Adds new item(s) to the end of array
variable.pop(); // Removes the last item from array
variable.unshift(""); // Adds item(s) to the beginning of array
variable.shift(); // Removes the first item from array
```

### Add (Push) new element to end of array

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.push("Kiwi"); // returns 5 (Length)
console.log(fruits); // ['Banana', 'Orange', 'Apple', 'Mango', 'Kiwi']
```

### Remove (Pop) last element of array

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.pop(); // returns 'Mango'
console.log(fruits); // ['Banana', 'Orange', 'Apple']
```

### Add (unshift) new element to beginning of array

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.unshift("Lemon"); // returns 5 (Length)
console.log(fruits); // ['Lemon', 'Banana', 'Orange', 'Apple', 'Mango']
```

### Remove (Shift) first array element

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.shift(); // // returns 'Banana'
console.log(fruits); // ['Orange', 'Apple', 'Mango']
```

### Remove (Delete) array element

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
delete fruits[0]; // returns true (Succesfully detete item)
console.log(fruits) // returns [empty, 'Orange', 'Apple', 'Mango']
🎯// Using delete may leave undefined holes in the array. Use pop() or shift() instead.
fruits[0] // undefined
console.log(fruits) // [empty, 'Orange', 'Apple', 'Mango']

```

### Slicing an Array 👽

🎯 The `slice()` method creates a `new array`. It does not remove any elements from the source array.

```js
let fruits = ["Banana", "Orange", "Lemon", "Apple", "Mango"];
let citrus = fruits.slice(1); // returns ['Orange', 'Lemon', 'Apple', 'Mango']
let citrus = fruits.slice(1, 3); // returns ['Orange', 'Lemon']
```

### Add (Splice) element to position in array 👽

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.splice(2, 0, "Lemon", "Kiwi");
console.log(fruits); // ['Banana', 'Orange', 'Lemon', 'Kiwi', 'Apple', 'Mango']

// The first parameter (2) defines the position where new elements should be added (spliced in).
// The second parameter (0) defines how many elements should be removed.
// The rest of the parameters ("Lemon" , "Kiwi") define the new elements to be added.
```

### Remove (Splice) element from position in array 👽

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.splice(0, 1, "Lemon", "Kiwi"); // returns ['Banana'] [Removed items]
console.log(fruits); // ['Lemon', 'Kiwi', 'Orange', 'Apple', 'Mango']

// The first parameter (0) defines the position where new elements should be added (spliced in).
// The second parameter (1) defines how many elements should be removed.
// The rest of the parameters are omitted. No new elements will be added.
```

**Example**

```js
let task = ["java", "javascript", "php", "c++"];
delete task[1]; // ['java', empty, 'php', 'c++']
task.splice(1, 0, "python"); // ['java', 'python', empty, 'php', 'c++']
console.log(task.length); // 5
console.log(task[2]); // undefined
console.log(task); // returns ['java', 'python', empty, 'php', 'c++']
```

### Merging (Concatenating) Arrays

The `concat()` method creates a new array by merging (concatenating) existing arrays.

```js
let arr1 = ["Cecilie", "Lone"];
let arr2 = ["Emil", "Tobias", "Linus"];
let arr3 = ["Robin", "Morgan"];
let myChildren = arr1.concat(arr2, arr3); // Concatenates arr1 with arr2 and arr3
// returns ['Cecilie', 'Lone', 'Emil', 'Tobias', 'Linus', 'Robin', 'Morgan']
```

🎯**NOTE:** Duplicate values remain same

### Converting Array to String

🎯 The JavaScript method `toString()` converts an array to a string of (comma separated) array values.  
🎯 All JavaScript objects have a `toString()` method.

```js
const fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.toString(); // returns Banana,Orange,Apple,Mango [typeof 'string']
```

The `join()` method also joins all array elements into a single `string`.🎯
It behaves just like `toString()`, but in addition you can specify the separator.

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.join(" "); // returns 'Banana Orange Apple Mango' [typeof 'string'] [single 'string']
fruits.join(""); // returns BananaOrangeAppleMango
fruits.join(); // returns Banana,Orange,Apple,Mango [default = separate by comma(,)]
```

### How to Recognize an Array

#### Solution 1:

```js
const fruits = ["Banana", "Orange", "Apple"];
Array.isArray(fruits); // returns true
```

#### Solution 2:

```js
const fruits = ["Banana", "Orange", "Apple"];
fruits instanceof Array; // returns true
fruits instanceof Object; // returns false
```

### Array find the indexOf element

```js
let fruits = ["Apple", "Orange", "Apple", "Mango"];
let a = fruits.indexOf("Apple"); // returns 0

let fruits = ["Apple", "Orange", "Apple", "Mango"];
let a = fruits.lastIndexOf("Apple"); // returns 2
```

```js
arr.indexOf("") == -1; // missing in the arr
arr.indexOf("") != -1; // available in the arr
```

## Sort

🎯 [JavaScript Array sort: Sorting Array Elements](https://www.javascripttutorial.net/javascript-array-sort/) - javascripttutorial.net

### Sorting Arrays

The `sort()` method sorts an array `alphabetically`

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.sort();
// returns ['Apple', 'Banana', 'Mango', 'Orange']
```

### Reversing an Array

The `reverse()` method reverses the elements in an array.
You can use it to sort an array in `descending order`

```js
let fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.sort(); // First sort the elements of fruits
fruits.reverse(); // Then reverse the order of the elements
// returns ['Orange', 'Mango', 'Banana', 'Apple']
```

### Numeric Sort🎯

- By default, the `sort()` function sorts values as strings.
- This works well for strings ("Apple" comes before "Banana").
- However, if numbers are sorted as strings, "25" is bigger than "100", because "2" is bigger than "1".
- Because of this, the `sort()` method will produce incorrect result when sorting numbers.
- You can fix this by providing a `compare function`.

```js
// Ascending
let points = [40, 100, 1, 5, 25, 10];
let sort = points.sort((a, b) => a - b);
// returns [1, 5, 10, 25, 40, 100]
Use the same trick to sort an array descending
// Descending
let points = [40, 100, 1, 5, 25, 10];
let sort = points.sort((a, b) => b - a);
// returns [100, 40, 25, 10, 5, 1]
```

### The Compare Function

When the `sort()` function compares two values, it sends the values to the compare function, and sorts the values according to the returned `(negative, zero, positive)` value.

- Sorting default is [0-9] or [a-z]
- If the result is negative `a` is sorted before `b`. `[(a < b) = -1]`
- If the result is positive `b` is sorted before `a`. `[(a > b) = 1]`
- If the result is `0` no changes are done with the sort order of the two values. `[(a == b) = 0]`
- This method's morality is "The rich get richer and the poor get poorer" 🎯 [for memorize 🤦‍♂️]

Syntax

```js
function(a, b){return a - b}
```

**Example:**

- The compare function compares all the values in the array, two values at a time `(a, b)`.
- When comparing 40 and 100, the `sort()` method calls the compare function(40, 100).
- The function calculates 40 - 100 `(a - b)`, and since the result is negative (-60), the sort function will sort 40 as a value lower than 100.

### Highest or Lowest length of String

```js
// lowest to highest
let arr = ["java", "javascript", "php", "c"];
let sort = arr.sort((a, b) => a.length - b.length)[0];
console.log(sort); // javascript
```

```js
// highest to lowest
let arr = ["java", "javascript", "php", "c"];
let sort = arr.sort((a, b) => b.length - a.length)[0];
console.log(sort); // c
```

### Sorting an Array in Random Order

```js
let points = [40, 100, 1, 5, 25, 10];
points.sort(function () {
  return 0.5 - Math.random();
});
points.sort(() => 0.5 - Math.random());
// returns [Random Number Each Time]
```

### Sorting Object Arrays

JavaScript arrays often contain objects:

```js
const cars = [
  {type:"Volvo", year:2016},
  {type:"Saab", year:2001},
  {type:"BMW", year:2010}
];

cars.sort((a, b) => a.year - b.year)
// returns Ascending years
0: {type: 'Saab', year: 2001}
1: {type: 'BMW', year: 2010}
2: {type: 'Volvo', year: 2016}
```

Comparing string properties is a little more complex:

```js
cars.sort(function(a, b){
  let x = a.type.toLowerCase(); // ignore upper and lowercase
  let y = b.type.toLowerCase(); // ignore upper and lowercase
  if (x < y) {return -1;}
  if (x > y) {return 1;}
  return 0;
});
// returns Ascending types alphabetically
0: {type: 'BMW', year: 2010}
1: {type: 'Saab', year: 2001}
2: {type: 'Volvo', year: 2016}
// Here we made our own compare function
```

### Convert Object > Array > Sort

```js
let salaries = {
  John: 100,
  Pete: 300,
  Mary: 250,
};

let sortable = [];

for (let salary in salaries) {
  sortable.push([salary, salaries[salary]]);
}

sortable.sort((a, b) => b[1] - a[1]);

let [topSalary, ...others] = sortable;

console.log(topSalary); // ['Pete', 300]
```

```js
let salaries = {
  John: 100,
  Pete: 300,
  Mary: 250,
};

let sortable = [];

for (let [name, salary] of Object.entries(salaries)) {
  sortable.push([name, salary]);
}

sortable.sort((a, b) => b[1] - a[1]);

let [topSalary, ...others] = sortable;

console.log(topSalary); // ['Pete', 300]
```

```js
let salaries = {
  John: 100,
  Pete: 300,
  Mary: 250,
};

const sortable = Object.fromEntries(
  // ES10 😒
  Object.entries(salaries).sort((a, b) => b[1] - a[1])
);

console.log(sortable); // {Pete: 300, Mary: 250, John: 100}
```

### Sorting non-ASCII characters

For sorting strings with non-ASCII characters, i.e. strings with accented characters (e, é, è, a, ä, etc.), strings from languages other than English, use `String.localeCompare`. This function can compare those characters so they appear in the right order.

```js
let items = ["réservé", "premier", "communiqué", "café", "adieu", "éclair"];
items.sort(function (a, b) {
  return a.localeCompare(b);
});
// items is ['adieu', 'café', 'communiqué', 'éclair', 'premier', 'réservé']
```

### Javascript String localeCompare()

🎯 [Javascript String localeCompare()](https://www.programiz.com/javascript/library/string/localeCompare) - Programiz
🎯 [String.prototype.localeCompare()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare) - MDN Web Docs

```js
const obj = {
  a: 1,
  b: 2,
  c: 3,
};

Object.entries(obj).sort((a, b) => b[0].localeCompare(a[0]))[
  // Output
  ("c", 3)
][("b", 2)][("a", 1)];
```

### Using Math.max() on an Array

You can use `Math.max.apply` to find the highest number in an array:

```js
function myArrayMax(arr) {
  return Math.max.apply(null, arr);
}
```

**OR**

```js
Math.max.apply(null, [1, 2, 3]) is equivalent to Math.max(1, 2, 3).
```

### Using Math.min() on an Array

You can use `Math.min.apply` to find the lowest number in an array:

```js
function myArrayMin(arr) {
  return Math.min.apply(null, arr);
}
```

**OR**

```js
Math.min.apply(null, [1, 2, 3]) is equivalent to Math.min(1, 2, 3).
```

### Methods

Array iteration methods operate on every array item.

### Array for loop and forEach loop Method

```js
let cars = ["Saab", "Volvo", "BMW"];
let length = cars.length; // Store length property increase performance
for (i = 0; i < length; i++) {
  console.log(cars[i]);
}
```

**OR**

```js
let cars = ["Saab", "Volvo", "BMW"];
function myFunction(value) {
  // cars value
  console.log(value);
}
cars.forEach(myFunction);
```

### The Array forEach(callbackfn) Method

The `forEach()` method calls a function (a callback function) once for each array element.

- Output is `loop`.
- If we try to `return` calculated value it will not work.

```js
const numbers = [45, 4, 9, 16, 25];
let txt = "";
numbers.forEach(myFunction);

function myFunction(value, index, array) {
  txt += value + "<br>";
}
```

```js
const numbers = [45, 4, 9, 16, 25];
numbers.forEach(myFunction);

function myFunction(value, index, array) {
  console.log(value * 2);
}
// returns calculated loop
```

### The Array map(callbackfn) Method

- The `map()` method creates a new array by performing a function on each array element.
- The `map()` method does not change the original array.
- The `map()` method creates new array.
- The `map()` method does not execute the function for array elements without values.

```js
const numbers1 = [45, 4, 9, 16, 25];
const numbers2 = numbers1.map(myFunction);

function myFunction(value, index, array) {
  return value * 2;
}
```

### The Array filter(callbackfn) Method

- The `filter()` method creates a new array with array elements that passes a test. See also `find()` method that returns only 1st matched item.
- The `filter()` method accepts `Number`, `String`, `Boolean` functions.

```js
let numbers = [45, 4, 9, 16, 25];
let over18 = numbers.filter(myFunction); // returns [45, 25]
function myFunction(value, index, array) {
  return value > 18;
}
```

#### Remove Falsy Value from an array

Here is a list of `falsy` values:

- false
- 0 (zero)
- -0 (negative zero)
- 0n (BigInt zero)
- "", '', `` (empty string)
- null
- undefined
- NaN (not a number)

```js
let arr = ["Next Topper", 10, 20, true, 100, false, "", NaN];
let filterValue = arr.filter(Number); // [10, 20, true, 100]
let filterValue = arr.filter(String); // ['Next Topper', 10, 20, true, 100, false, NaN]
let filterValue = arr.filter(Boolean); // ['Next Topper', 10, 20, true, 100]
```

### The Array find(callbackfn) Method

The `find()` method returns the value of the first array element that passes a test function. See also `filter()` method, that returns every matched items.

```js
const numbers = [4, 9, 16, 25, 29];
let first = numbers.find(myFunction); // 25 (only returns 1st matched item)

function myFunction(value, index, array) {
  return value > 18;
}
```

### The Array findIndex(callbackfn) Method

The `findIndex()` method returns the index of the first array element that passes a test function.

```js
const numbers = [4, 9, 16, 25, 29];
let first = numbers.findIndex(myFunction);

function myFunction(value, index, array) {
  return value > 18;
}
```

### The Array reduce(callbackfn) Method

❄ [Array reduce method in javascript](https://dev.to/rakshithbellare/array-reduce-method-in-javascript-330d)

- The `reduce()` method runs a function on each array element to produce (reduce it to) a single value.
- The `reduce()` method does not reduce the original array.
- The `reduce()` method creates new array.
- The `reduce()` method works from left-to-right in the array. See also `reduceRight()`.

```js
const numbers = [0, 1, 2, 3, 4];
let sum = numbers.reduce(myFunction); // returns 10

function myFunction(previousValue, currentValue, currentIndex, array) {
  return previousValue + currentValue;
}
```

#### How `reduce()` works behind the scene

| Previous Value | Current Value | Return Value |
| -------------- | ------------- | ------------ |
| 0              | 1             | 1            |
| 1              | 2             | 3            |
| 3              | 3             | 6            |
| 6              | 4             | 10           |

The `reduce()` method can accept an initial value:

```js
const numbers = [45, 4, 9, 16, 25];
let sum = numbers.reduce(myFunction, 100); // initial value = 100

function myFunction(total, value) {
  return total + value;
}
```

```js
const votes = ["y", "y", "n", "n", "y", "n", "y", "y", "n", "n"];

const tally = votes.reduce((tally, val) => {
  tally[val] = (tally[val] || 0) + 1;
  return tally;
}, {});
console.log(tally); // {y: 5, n: 5}
```

### The Array reduceRight(callbackfn) Method

- The `reduceRight()` method runs a function on each array element to produce (reduce it to) a single value.
- The `reduceRight()` method does not reduce the original array.
- The `reduceRight()` method creates new array.
- The `reduceRight()` works from right-to-left in the array. See also `reduce()`.

```js
const numbers = [45, 4, 9, 16, 25];
let sum = numbers1.reduceRight(myFunction);

function myFunction(total, value, index, array) {
  return total + value;
}
```

### The Array every(callbackfn) Method

- The `every()` method check if all array values pass a test.

```js
const numbers = [45, 4, 9, 16, 25];
let allOver18 = numbers.every(myFunction); // return false

function myFunction(value) {
  return value > 18;
}
```

### The Array some(callbackfn) Method

- The `some()` method check if some array values pass a test.

```js
const numbers = [45, 4, 9, 16, 25];
let someOver18 = numbers.some(myFunction); // returns true

function myFunction(value, index, array) {
  return value > 18;
}
```

### The Array indexOf() Method

- The `indexOf()` method searches an array for an element value and returns its position.

```js
const fruits = ["Apple", "Orange", "Apple", "Mango"];
let position = fruits.indexOf("Apple") + 1; // + 1 for visual output
```

Syntax

```js
array.indexOf(item, start);
```

`Array.indexOf()` returns -1 if the item is not found.

### The Array lastIndexOf() Method

`Array.lastIndexOf()` is the same as `Array.indexOf()`, but returns the position of the last occurrence of the specified element.

```js
const fruits = ["Apple", "Orange", "Apple", "Mango"];
let position = fruits.lastIndexOf("Apple") + 1;
```

Syntax

```js
array.indexOf(item, start);
```

`Array.lastIndexOf()` returns -1 if the item is not found.

### The Array includes() Method

`Array.includes()` allows to check for NaN values. Unlike `Array.indexOf()`.

```js
const fruits = ["Banana", "Orange", "Apple", "Mango"];
fruits.includes("Mango"); // is true
```

### The Array.from() Method

- The `Array.from()` method returns an Array object from any object with a length property or any iterable object.

```js
// Create an Array from a String:
Array.from("ABCDEFG"); // returns ['A', 'B', 'C', 'D', 'E', 'F', 'G']
Array.from(101010); // returns []
```

### The Array Keys() Method

- The `Array.keys()` method returns an Array Iterator object with the keys of an array.

```js
const fruits = ["Banana", "Orange", "Apple", "Mango"];
const keys = fruits.keys();

for (let x of keys) {
  text += x + "<br>";
}
/*
returns
1
2
3
4
*/
```

### Key iterator doesn't ignore holes

```js
let arr = ["a", , "c"];
let sparseKeys = Object.keys(arr);
let denseKeys = [...arr.keys()];
console.log(sparseKeys); // ['0', '2']
console.log(denseKeys); // [0, 1, 2]
```

### Find elements in array that are not in another array 🔥🔥🔥

https://stackoverflow.com/a/44918208/15497939

```js
const slots = [
  "08.00 AM - 08.30 AM",
  "08.30 AM - 09.00 AM",
  "09.00 AM - 9.30 AM",
  "09.30 AM - 10.00 AM",
  "10.00 AM - 10.30 AM",
  "10.30 AM - 11.00 AM",
  "11.00 AM - 11.30 AM",
  "11.30 AM - 12.00 AM",
];
const booked = [
  "08.00 AM - 08.30 AM",
  "10.00 AM - 10.30 AM",
  "11.30 AM - 12.00 AM",
];
const available = slots.filter((s) => !booked.includes(s));
console.log(available);
// ['08.30 AM - 09.00 AM', '09.00 AM - 9.30 AM', '09.30 AM - 10.00 AM', '10.30 AM - 11.00 AM', '11.00 AM - 11.30 AM']
```

## map vs forEach & filter vs find

```js
const products = [
	{name: 'laptop', price: 3200, brand: 'lenovo'},
	{name: 'phone', price: 700, brand: 'iphone'},
	{name: 'watch', price: 3000, brand: 'casio'}
]


// map 🚂[📦📦📦📦📦].🗺(⚒) = [🗃🗃🗃🗃🗃]
map array return করে তাই return তাকে store করার জন্য variable declare করতে হয়।
const brands = products.map(product => product.brand)

// forEach
forEach কিছু return করে না, তাই variable declare প্রয়োজন নাই।

products.forEach(product => console.log(product.name))

// filter [📦📦🔴📦📦🔺] = [📦📦📦📦]
filter এ শর্তে যে গুলা match করবে তার array return করবে, তাই variable declare করতে হবে।

const cheap = product.filter(product => product.price <= 5000)
console.log(cheap)

// find [📦📦🔴📦📦🔺] = 📦
find এ যেটা 1st match করবে সেই full object return করে, তাই variable declare করতে হবে।

const special = products.find(product => product.name.includes('n'))
console.log(special)
```

# Objects

🎯 [JavaScript Objects](https://www.w3schools.com/js/js_object_definition.asp) - W3Schools

🎯 [Objects: the basics](https://javascript.info/object) - javascript.info

🎯 [JavaScript Getter and Setter](https://www.programiz.com/javascript/getter-setter) - Programiz

🎯 [Property Accessors](https://javascript.info/property-accessors) - javascript.info

🎯 [JavaScript Proxies](https://www.programiz.com/javascript/proxies) - Programiz

### Object Initializer

JavaScript objects can be initialized in various ways which are as follows.

1. Using object literals

```js
const person = { name: "Nur Mohamod Rafi", job: "Web Developer" };
```

2. Using Object.create() method

```js
const Person = Object.create({});
Person.name = "Nur Mohamod Rafi";
Person.job = "Web Developer";
// OR
Person["name"] = "Nur Mohamod Rafi";
Person["job"] = "Web Developer";
```

3. Using new Object() method

```js
const Person = new Object();
person.name = "Nur Mohamod Rafi";
person.job = "Web Developer";
// OR
person["name"] = "Nur Mohamod Rafi";
person["job"] = "Web Developer";
```

4. Using constructor functions

```js
function Person(name, job) {
  this.name = name;
  this.job = job;
}

const mySelf = new Person("Nur Mohamod Rafi", "Web Developer");
```

#### 3 ways to get & set object property

```js
const student = {
  name: "Nur Rafi",
  roll: 01,
  major: "Finance",
};
const myName = "name";

student.name = "Nur Rafe"; // direct by property
student["name"] = "Nur Rafe"; // access by property string
student[myName] = "Nur Rafe"; // access by property name in a variable
```

🎯**NOTE:**

bracket দিয়ে access করার সময় string use করতেই হবে directly হক বা indirectly.

#### Es6 operation on Object

```js
const phones = [
  { name: "samsung s5", price: 45000, camera: 10, storage: 32 },
  { name: "walton g5", price: 15000, camera: 8, storage: 8 },
  { name: "xiaomi m1", price: 12000, camera: 8, storage: 16 },
  { name: "oppo a2", price: 17000, camera: 8, storage: 16 },
  { name: "nokia n95", price: 8000, camera: 8, storage: 32 },
  { name: "htc h81", price: 25000, camera: 8, storage: 16 },
];

// get all phone names
const phoneNames = phones.map((phone) => phone.name);
console.log(phoneNames); // ['samsung s5', 'walton g5', 'xiaomi m1', 'oppo a2', 'nokia n95', 'htc h81']

// calc total price of all phones
let totalPrice = 0;
phones.forEach((phone) => {
  totalPrice += phone.price;
  return totalPrice;
});
console.log(totalPrice); // 69000

// get phones below price 15000
const filterPhonesUnder15k = phones.filter((phone) => {
  if (phone.price <= 15000) {
    return phone.name;
  }
});
console.log(filterPhonesUnder15k);

// get phones name below price 15000
const phonesUnder15k = filterPhonesUnder15k.map((phone) => phone.name);
console.log(phonesUnder15k)[("walton g5", "xiaomi m1", "nokia n95")];

// get 1st cheapestPriced phone by serially
const cheapestPrice = phones.find((phone) => phone.price < 15000);
console.log(cheapestPrice);
// {name: 'xiaomi m1', price: 12000, camera: 8, storage: 16}
```

### Keys, values, entries, delete, seal, freeze

```js
const bottle = { color: "yellow", hold: "water", price: 100, isCleaned: true };

// Syntax
{
  key: value;
}

// Get all keys
const keys = Object.keys(bottle); // returns array of keys

// Get all values
const values = Object.values(bottle); // returns array of values

// Get key value pairs
const pairs = Object.entries(bottle); // returns array of key value pair arrays (2 dimentional array [[x, y], [y, x], [z, x]])

// Delete key value both
delete bottle.isCleaned;
console.log(bottle); // returns without deleted property
```

Seal Object [❌ Add | ❌ Remove | ✔ Edit]

```js
❌ Insertion of new Property
❌ Deletion of existing Property
✔ Modification existing Property

Object.seal(bottle);
delete bottle.isCleaned; // NOT RECOMMANDED causes memory issue
console.log(bottle); // returns object with modification
```

Freeze Object [❌ Add | ❌ Remove | ❌ Edit]

```js
❌ Insertion of new Property
❌ Deletion of existing Property
❌ Modification existing Property

Object.seal(bottle);
delete bottle.isCleaned;
console.log(bottle); // returns unchanged Object
```

### Looping Objects: using for in, for of, Object Entries

- `Object.keys(obj)` – returns an array of keys.
- `Object.values(obj)` – returns an array of values.
- `Object.entries(obj)` – returns an array of [key, value] pairs.

```js
for (let i = 0; i < 10; i++) {} // basic
for (const num of numbers) {
} // NOT RECOMMANDED for Object

for (const prop in obj) {
  // object
  console.log(prop); // keys
  console.log(obj[prop]); // values
  console.log(prop, obj[prop]); // keys + values
}

// key, value destructuring
for (const [key, value] of Object.entries(objName)) {
  console.log(key, value);
}

const entries = Object.entries(objName);
console.log(entries);
[
  ["key", "value"],
  ["key", "value"],
  ["key", "value"],
];

const [key, value] = ["key", "value"];
```

### Compare Objects, Referential integrity

```js
const first = { a: 1 };
const second = { a: 1 };
const third = first; // memory reference are same

(first === second)(
  // Not Equal
  first === third
); // Equal

// Compare objects are always checking memory reference
// Object will be equal if their reference is same
```

#### Convert to String for Compare Objects

```js
const first2 = {a: 1, b: 2};
const second2 = {a: 1, b: 2};
(JSON.stringify(first2) === JSON.stringify(second2)); // Equal

const first3 = {a: 1, b: 2};
const second3 = {b: 2, a: 1};
(JSON.stringify(first3) === JSON.stringify(second3); // Not Equal

// String(Primitive Value) are not checking reference
```

### Using function for Compare Objects

```js
function compareObjects(obj1, obj2) {
  if (Object.keys(obj1).length !== Object.keys(obj2).length) {
    return false;
  }
  for (const prop in obj1) {
    if (obj1[prop] !== obj2[prop]) {
      return false;
    }
  }
  return true;
}

const isEqual = compareObjects(first2, second2);
console.log(isEqual);
```

# Date

🎯 [JavaScript Date Reference](https://www.w3schools.com/jsref/jsref_obj_date.asp) - W3Schools

🎯 [Moment.js - A JavaScript date library for parsing, validating, manipulating, and formatting dates.](https://momentjs.com/)

- Date objects are static. The computer time is ticking, but date objects are not.🎯
- Output comes from when this code is coded.
- JavaScript Stores Dates as Milliseconds.
- 7 numbers specify year, month, day, hour, minute, second, and millisecond (in that order).
- You cannot use only one parameter it will be treated as milliseconds.
- JavaScript counts months from 0 to 11 [January = 0] [December = 11]
- Specifying a month higher than 11, will not result in an error but add the overflow to the next year.
- Zero time is January 01, 1970 00:00:00 UTC.
- One and two digit years will be interpreted as 19xx `new Date(99, 11, 24);`

Syntax

```js
new Date() // Constructor function [Most Used]
new Date(year, month, day, hours, minutes, seconds, milliseconds)
new Date(milliseconds)
new Date(date string)
```

```js
// Use
let date = Date.now();
let date = new Date(); // [Most Used]
let date = new Date(2018, 11, 24, 10, 33, 30); // Or Set Date
let date = new Date("2015-03-25T12:00:00Z"); // Or Set Date
```

### JavaScript Date Input

| Type       | Example                                   |
| ---------- | ----------------------------------------- |
| ISO Date   | "2015-03-25" (The International Standard) |
| Short Date | "03/25/2015"                              |
| Long Date  | "Mar 25 2015" or "25 Mar 2015"            |

🎯**NOTE:**

- The ISO format follows a strict standard in JavaScript.[all browser output will be same]
- The other formats are not so well defined and might be browser specific.

### The getMonth() Method Tricks🎯

In JavaScript, the first month (January) is month number 0, so December returns month number 11.

```js
const months = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];
const date = new Date();
let month = months[date.getMonth()];
// `getMonth()` method returns number between [0-11] So we are just matching output with `month.length`
```

# Maths

### The Math Object

- Unlike other objects, the Math object has no constructor.
- Math is a global object. The `new` keyword cannot be used on Math.
- The Math object is static.

### Math Properties (Constants)

- The syntax for any Math property is : `Math.property`
- JavaScript provides 8 mathematical constants that can be accessed as Math properties.

```js
Math.E; // Euler's number [e = 2.718281828459045]
Math.PI; // PI [π = 3.141592653589793]
Math.SQRT2; // the square root of 2
Math.SQRT1_2; // the square root of 1/2
Math.LN2; // the natural logarithm of 2
Math.LN10; // the natural logarithm of 10
Math.LOG2E; // base 2 logarithm of E
Math.LOG10E; // base 10 logarithm of E
```

### Math Methods

The syntax for Math any methods is : `Math.method(number)`

#### Number to Integer

```js
✔ // Math.round(x) returns the nearest integer
Math.round(4.7); // 5
Math.round(4.5); // 5
Math.round(4.4); // 4
Math.round(-4.5); // -4

✔ // Math.ceil(x) returns the value of x rounded up to its nearest integer
Math.ceil(4.4); // 5 (Round up)
Math.ceil(-4.5); // - 4

✔ // Math.floor(x) returns the value of x rounded down to its nearest integer
Math.floor(4.7); // 4 (Round down)
Math.floor(-4.5); // -5

Math.min(0, 150, 30, 20, -8, -200); // -200 (Min) ✔
Math.max(0, 150, 30, 20, -8, -200); // 150 (Max) ✔

Math.PI; // returns 3.141592653589793
Math.pow(8, 2); // returns 64 (Power of)
Math.sqrt(64); // returns 8 (Square Root)
Math.abs(-4.7); // returns 4.7 (Positive) ✔

Math.sin((90 * Math.PI) / 180); // returns 1 (the sine of 90 degrees)
Math.cos((0 * Math.PI) / 180); // returns 1 (the cos of 0 degrees)
```

🎯 [JavaScript Math Reference](https://www.w3schools.com/jsref/jsref_obj_math.asp)

### JavaScript Random Integers

🎯**NOTE:** `Math.random()` returns a random number 0 to 1 and multiply with expected number, finally use `Math.floor()` to get a round number.

```js
Math.random(); // returns a random number from 0 to 1
Math.floor(Math.random() * 10);
Math.floor(Math.random() * 11);
Math.floor(Math.random() * 100);
Math.floor(Math.random() * 100) + 1;
```

### A Proper Random Function

```js
function getRendom(start, end) {
  return Math.floor(Math.random() * (start - end)) + start;
}
getRendom(1, 10);
```

**OR**

```js
function getRendom(start, end) {
  return Math.trunc(Math.random() * (start - end)) + start;
}
getRendom(1, 10);
```

# Boolean

A JavaScript Boolean represents one of two values: true or false. `[without '']`
The Boolean value of an expression is the basis for all JavaScript comparisons and conditions.🎯

| Operator | Description  | Example              |
| -------- | ------------ | -------------------- |
| ==       | equal to     | if (day == "Monday") |
| >        | greater than | if (salary > 9000)   |
| <        | less than    | if (age < 18)        |

#### Remove Falsy Value from an array

Here is a list of falsy values:

- false
- 0 (zero)
- -0 (negative zero)
- 0n (BigInt zero)
- "", '', `` (empty string)
- null
- undefined
- NaN (not a number)

```js
let arr = ["Next Topper", 10, 20, true, 100, false, "", NaN];
let filterValue = arr.filter(Boolean); // ['Next Topper', 10, 20, true, 100]
```

```js
let x = false; // typeof x returns boolean
let y = new Boolean(false); // typeof y returns object
```

# Switch

Design for Equality not for Comparision.

Syntax

```js
switch (expression) {
  case x:
    // code block
    break;
  case y:
    // code block
    break;
  default:
  // code block
}
```

```js
const day = prompt("Enter Your Day");
switch (day) {
  case "mon": // day === 'monday' [true]
    alert("Plan course structure");
    alert("Go to coding meetup");
    break;
  case "tue":
    alert("Prepare theory videos");
    break;
  case "wed":
  case "thu":
    alert("Write code examples");
    break;
  case "fri":
    alert("Record videos");
    break;
  case "sat":
  case "sun":
    alert("Enjoy the weekend :D");
    break;
  default:
    alert("Not a valid day!");
}
```

### Image path matching by Switch Statement

```js
    dice.src = `dice-${number}.png`	*****BEST*****

    const number = Math.trunc(Math.random() * 6) + 1;
    switch (number) {
        case 1:
            dice.src = 'dice-1.png';
            break;
        case 2:
            dice.src = 'dice-2.png';
            break;
        case 3:
            dice.src = 'dice-3.png';
            break;
        case 4:
            dice.src = 'dice-4.png';
            break;
        case 5:
            dice.src = 'dice-5.png';
            break;
        case 6:
            dice.src = 'dice-6.png';
            break;
    };
```

### Using the Switch(true) pattern for applying conditions

```js
function printMe(n) {
  switch (true) {
    case n == 1:
      console.log("This is One");
      break;
    case n == 2:
      console.log("This is Two");
      break;
    case n > 2 && n < 5:
      console.log("Greater than two and less than 10");
      break;
    default:
      console.log("No match found");
  }
}
printMe(2); // "This is Two"
printMe(5); // "Greater than two and less than 10"
```

🎯 [JavaScript Switch Statement – With JS Switch Case Example Code](https://www.freecodecamp.org/news/javascript-switch-statement-with-js-switch-case-example-code/) - freecodecamp

🎯 [The "switch" statement](https://javascript.info/switch) - javascript.info

🎯 [Switch Case Syntax](https://www.guru99.com/c-switch-case-statement.html)

🎯 [Using the Switch(true) Pattern in JavaScript](https://seanbarry.dev/posts/switch-true-pattern)

# Loops

- for - loops through a block of code a number of times - `Number`
- for/in - loops through the properties of an object - `{Object}`
- for/of - loops through the values of an iterable object - `[Array]`
- while - loops through a block of code while a specified condition is true
- do/while - also loops through a block of code while a specified condition is true

🎯 [Difference between forEach and for loop in Javascript](https://www.geeksforgeeks.org/difference-between-foreach-and-for-loop-in-javascript/) - GeeksforGeeks

🎯 [Difference between forEach() and map() loop in JavaScript](https://www.geeksforgeeks.org/difference-between-foreach-and-map-loop-in-javascript/) - GeeksforGeeks

### Loop (for) by number

for - loops through a block of code a number of times - `Number`

Syntax

```js
for (initializer; condition; increment) {
  // code;
}
```

```js
for(let i = 0; i < 10; i++){
console.log(any[i])

let length = 5;
for (i = 0; i < length; i++) {
console.log(i)
}
```

### Loop (for/in) properties of object

for/in - loops through the properties of an object - `{Object}`

Syntax

```js
for (let key in object) {
  // code block to be executed
}
// OR
for (let index in array) {
  // code block to be executed
}
```

```js
let person = { fname: "John", lname: "Doe", age: 25 };
let text = "";
let x;
for (let x in person) {
  text += person[x];
}
console.log(text); // JohnDoe25
```

```js
const obj = {
    one: 1,
    two: 2,
    three: 3
}

for (let property in obj){
    console.log(`key is ${property} and value is ${obj[property]}`)
}

// Output
key is one and value is 1
key is two and value is 2
key is three and value is 3
```

🎯**NOTE:**

- Do not use for in over an Array if the index order is `important`.
- The index order is implementation-dependent, and array values may not be accessed in the order you expect.
- It is better to use a for loop, a for of loop, or `Array.forEach()` when the order is important.

### Loop (for/of) elements of array

for/of - loops through the values of an iterable object - `[Array]`

Syntax

```js
for (variable of iterable) {
  // code block to be executed
}
```

```js
const cars = ["BMW", "Volvo", "Mini"];

let text = "";
for (let x of cars) {
  text += x;
}
```

# Iterables

- Iterables are iterable objects (like Arrays).
- Iterables can be accessed with simple and efficient code.
- Iterables can be iterated over with `for..of` loops

### Difference between `for...in` and `for...of`

🎯 [What is the difference between (for... in) and (for... of) statements?](https://stackoverflow.com/a/41910537/15497939) - stackoverflow

for...in Loop => iterates over the index in the array.[index in array |OR| key in object]

for...of Loop => iterates over the value in the array.

```js
let list = [4, 5, 6];

for (let i in list) {
  console.log(i, el); // "0", "1", "2",
}

for (let i of list) {
  console.log(i); // "4", "5", "6"
}
```

### Iterating Over an Array

```js
const letters = ["a", "b", "c"];
let text = "";
for (const x of letters) {
  text += x + " ";
}
console.log(text); // a b c
```

### Iterating Over a Set

```js
const letters = new Set(["a", "b", "c"]);
let text = "";
for (const x of letters) {
  text += x + " ";
}
console.log(text); // a b c
```

### Iterating Over a Map

```js
const fruits = new Map([
  ["apples", 500],
  ["bananas", 300],
  ["oranges", 200],
]);

for (const x of fruits) {
  // code block to be executed
}
```

### Loop (while) condition

while - loops through a block of code while a specified condition is true

Syntax

```js
while (condition) {
  // code block to be executed
}
```

```js
while (i < 10) {
  text += "The number is " + i;
  i++;
}
```

### Loop (do/while) condition

do/while - also loops through a block of code while a specified condition is true

Syntax

```js
do {
  // code block to be executed
} while (condition);
```

```js
do {
  text += "The number is " + i;
  i++;
} while (i < 10);
```

### forEach Loop Function

```js
const fruits = ["mango", "papaya", "pineapple", "apple"];

// Iterate over fruits below

// Normal way
fruits.forEach(function (fruit) {
  console.log("I want to eat a " + fruit);
});

// returns
/*
I want to eat a mango
I want to eat a papaya
I want to eat a pineapple
I want to eat a apple
*/
```

### Backwards Loop

```js
const jonas = [
  "Jonas",
  "Schmedtmann",
  2037 - 1991,
  "teacher",
  ["Michael", "Peter", "Steven"],
];
for (let i = jonas.length - 1; i >= 0; i--) {
  console.log(jonas[i]);
}

// jonas.length - 1 = findout last value;
// i-- = decrement;
```

🎯**NOTE:** Reverse String Best Tricks ✔✔✔

```js
let word = "I love JavaScript";
let text = "";

for (const chr of word) {
  text = chr + text;
}
console.log(text); // tpircSavaJ evol I
```

🎯**NOTE:** Reverse String without using `sort()` & `reverse()` methods.

```js
let word = "I love JavaScript";
let text = "";
for (let i = word.length - 1; i >= 0; i--) {
  text += word[i];
}
console.log(text); // tpircSavaJ evol I
```

### Nested Loop

```js
for (let exercise = 1; exercise <= 3; exercise++) {
console.log(`--------- Starting Exercise ${exercise}`);
for (let rep = 1; rep <= 5; rep++) {
    console.log(`Lifting weight repitition${rep}`)
};
}

for (let rep = 1; rep <= 3; rep++) {
console.log(`Lifting weight repitition${rep}`);
}
console.log({}, {})
let rep = 1;
while (rep <= 5) {
console.log(`Lifting weight repetition${rep}`);
rep++;
}
// Returns
    --------- Starting Exercise 1
    Lifting weight repetition 1
    Lifting weight repetition 2
    Lifting weight repetition 3
    --------- Starting Exercise 2
    Lifting weight repetition 1
    Lifting weight repetition 2
    Lifting weight repetition 3
    --------- Starting Exercise 3
    Lifting weight repetition 1
    Lifting weight repetition 2
    Lifting weight repetition 3
```

### Calculate Factorial of a number using for loop

```js
// Factorial
3! = 3 x 2 x 1
4! = 4 x 3 x 2 x 1
5! = 5 x 4 x 3 x 2 x 1
6! = 6 x 5 x 4 x 3 x 2 x 1

// Conditions of Factorial
1. Starts with 1;
2. Ends at factorial number;


let factorial = 1; // factorial initial value
for (let i = 1; i <= 7; i++) { // let factorial = 1;
// dont declare here, because it change value each loop
factorial *= i;
console.log("after", factorial);
}
```

### Create a Fibonacci Series using a for loop

```js
// Fibonacci Sequence
0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144
1st two number came from sky [0, 1]
from third number each number is sum of before two number itself.

nth = (n-1)th + (n-2)th
ith = (i-1)th + (i-2)th [array index]

function fibonacci(num) {
  let arr = [0, 1];
  for (let i = 2; i <= num; i++) {
    arr.push(arr[arr.length - 1] + arr[arr.length - 2]);
  }
  return arr;
}
let fiboSeries = fibonacci(10);
console.log(fiboSeries); // [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55]
```

```js
function fibonacci(num) {
  if (typeof num != "number") {
    return console.log("Please give a number");
  } else if (num < 0) {
    return console.log("Please give a positive number");
  } else {
    let arr = [0, 1];
    for (let i = 2; i <= num; i++) {
      arr[i] = arr[i - 1] + arr[i - 2];
    }
    return arr;
  }
}
console.log(fibonacci()); // Please give a number
console.log(fibonacci(-13)); // Please give a positive number
console.log(fibonacci(13)); // [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233]
```

# Break & Continue

### Break

The `break` statement "jumps out" of a loop.

```js
for (let i = 0; i < rafe.length; i++) {
  if (typeof rafe[i] === "string") break;
  console.log(rafe[i]);
}
```

### Continue

The `continue` statement "jumps over" one iteration in the loop.

```js
for (let i = 0; i < rafe.length; i++) {
  if (typeof rafe[i] === "number") continue;
}
```

### Labels

Syntax

```js
break labelname;
continue labelname;
```

- The continue statement (with or without a label reference) can only be used to skip one loop iteration.
- The break statement, without a label reference, can only be used to jump out of a loop or a switch.
- With a label reference, the break statement can be used to jump out of any code block:

```js
const cars = ["BMW", "Volvo", "Saab", "Ford"];
let text = "";
list: {
  text += cars[0] + "<br>";
  text += cars[1] + "<br>";
  break list; // continue not working 🐋
  text += cars[2] + "<br>";
  text += cars[3] + "<br>";
}
```

### Loop with Await/Async within

ForEach loops with async's and await's have some strange behaviour resulting in not waiting a running tasks out of order, which can be fixed using es6 .map and promise all functions as follows:

```js
const myArray = ["One", "Two", "Three"];

const myPromises = myArray.map(async (item) => {
  await myFunc("doSomeThing");
});

await Promise.all(myPromises);
```

## Looping Arrays & Objects - (Destructuring)

🎯 [JavaScript Destructuring Assignment](https://www.programiz.com/javascript/destructuring-assignment) - Programiz

🎯 [Destructuring Assignment](https://javascript.info/destructuring-assignment) - javscript.info

🎯 [Object.keys, values, entries](https://javascript.info/keys-values-entries) - javascript.info

```js
const restaurant = {
  name: "Classico Italiano",
  location: "Via Angelo Tavanti 23, Firenze, Italy",
  categories: ["Italian", "Pizzeria", "Vegetarian", "Organic"],
  starterMenu: ["Focaccia", "Bruschetta", "Garlic Bread", "Caprese Salad"],
  mainMenu: ["Pizza", "Pasta", "Risotto"],

  openingHours: {
    thu: {
      open: 12,
      close: 22,
    },
    fri: {
      open: 11,
      close: 23,
    },
    sat: {
      open: 0, // Open 24 hours
      close: 24,
    },
  },
};

const menu = [...restaurant.starterMenu, ...restaurant.mainMenu];
```

### Looping Arrays: The for-of Loop

#### 1. Normal Method

```js
for (const item of menu) console.log(item);
// returns each element line by line ==>

Focaccia
Bruschetta
Garlic Bread
Caprese Salad
Pizza
Pasta
Risotto


// NEED to write single line OR use {} brackets for output
// We can use 'continue' and 'break' keywords
// Index/Length will not work here, So we have to use entries()
```

#### 2. .entries() => Array: [Index with Items]

```js
for (const item of menu.entries()) console.log(item);
// returns each element line by line with index number but look like Array ==>

[0, "Focaccia"][(1, "Bruschetta")][(2, "Garlic Bread")][(3, "Caprese Salad")][
  (4, "Pizza")
][(5, "Pasta")][(6, "Risotto")];

console.log(menu.entries()); // returns Array Iterator {}
console.log([...menu.entries()]);
// returns Array Within Arrays ==>

[Array(2), Array(2), Array(2), Array(2), Array(2), Array(2), Array(2)];
```

#### 3. Used by Normal Method

```js
for (const item of menu.entries()) console.log(`${item[0]+1}: ${item[1]}`)
// returns each item lile by line with index number ==>

1: Focaccia
2: Bruschetta
3: Garlic Bread
4: Caprese Salad
5: Pizza
6: Pasta
7: Risotto
```

#### 4. Used by Destructuring Method

```js
for (const [i, el] of menu.entries()) console.log(`${i+1}: ${el}`);
// returns each item lile by line with index number ==>

1: Focaccia
2: Bruschetta
3: Garlic Bread
4: Caprese Salad
5: Pizza
6: Pasta
7: Risotto
```

### Looping Objects: Object Keys, Values, and Entries

- `Object.keys(obj)` – returns an array of keys.
- `Object.values(obj)` – returns an array of values.
- `Object.entries(obj)` – returns an array of [key, value] pairs.

#### Object Keys

```js
const openingHours = restaurant.openingHours; // Object

// WITHOUT Loop <===> Array
console.log(Object.keys(openingHours));
// returns Array: ["thu", "fri", "sat"]

// WITH Loop <===> Line by Line
for (const day of Object.keys(openingHours)) console.log(day);

// returns List of available Key/Property name of object ==>
fri;
sat;
thu;

console.log(Object.keys(openingHours).length); // returns Number of properties

const properties = Object.keys(openingHours);
let openStr = `We are open on ${properties.length} days:`;
for (const day of properties) {
  openStr += ` ${day},`; // Sentence + Property with dynamic loop value
}
console.log(openStr);
```

#### Object Values

```js
// WITHOUT Loop <===> Array
console.log(Object.values(openingHours));

// WITH Loop <===> Line by Line
for(const value of Object.values(openingHours)) console.log(value);

// returns
{open: 12, close: 22}
{open: 11, close: 23}
{open: 0, close: 24}
```

#### Entries Object

```js
const entries = Object.entries(openingHours)
console.log(entries) // returns Index [key, value]

for(const [key, {open, close}] of entries){
    console.log(`On ${key} we open at ${open} and close at ${close}`);
};

// returns
On thu we open at 12 and close at 22
On fri we open at 11 and close at 23
On sat we open at 0 and close at 24
```

# Sets & Maps

Till now, we’ve learned about the following complex data structures:

- Objects are used for storing keyed collections.
- Arrays are used for storing ordered collections.

But that’s not enough for real life. That’s why Set and Map also exist.

## Sets

- A JavaScript Set is a collection of unique values.
- Each value can only occur once in a Set.
- There is no Index and no need to get data out of a set.
- The main use case is to remove duplicate values of a set.

Its main methods are:

- `new Set(iterable)` – creates the set, and if an iterable object is provided (usually an array), copies values from it into the set.
- `add(value)` – adds a value, returns the set itself.
- `delete(value)` – removes the value, returns true if value existed at the moment of the call, otherwise false.
- `has(value)` – returns true if the value exists in the set, otherwise false.
- `clear()` – removes everything from the set.
- `size` – is the elements count.
- `values()` – The `values()` method returns a new `iterator object` containing all the unique values in a Set.

The main feature is that repeated calls of <del>set</del>.add(value) with the same value don’t do anything. That’s the reason why each value appears in a Set only once.

```js
const ordersSet = new Set(["Pasta", "Pizza", "Pizza", "Pasta", "Sandwich"]);
console.log(ordersSet); // returns Set(3) {"Pasta", "Pizza", "Sandwich"}

console.log(new Set("Rafe")); // returns Set(4) {"R", "a", "f", "e"}

console.log(ordersSet.size); // returns 3
console.log(ordersSet.has("Pizza")); // returns true
console.log(ordersSet.has("Burger")); // returns false
ordersSet.add("Garlic Bread");
ordersSet.delete("Pizza");
console.log(ordersSet); // returns Set(4) {"Pasta", "Sandwich", "Garlic Bread"}
ordersSet.clear(); // returns clear set
ordersSet.values() // returns SetIterator {"Pasta", "Sandwich", "Garlic Bread"}

for (const order of ordersSet) console.log(order);
// OR
let text = "";
for (const order of orderSet{
  text =+ order + " ";
}
console.log(text) // returns single string

// Example
const staff = ["Waiter", "Chef", "Waiter", "Manager", "Chef", "Waiter"];
// Q: How many different positions are in a restaurent?
const staffUnique = new Set(staff);
console.log(staffUnique.size); // returns 3

// Convert Set to Array using Spread Operator [...]
const staffArray = [...new Set(staff)];
console.log(staffArray); // returns ["Waiter", "Chef", "Manager"]

// How many characters in my name
console.log(new Set("nurmohamodrafi").size); // returns 10
```

## Map

- A Map holds key-value pairs where the keys can be any datatype.
- A Map remembers the original insertion order of the keys.
- A Map has 3 default parameters (key, value, map)

Methods and properties are:

- `new Map()` – creates the map.
- `set(key, value)` – stores the value by the key.
- `get(key)` – returns the value by the key, undefined if key doesn’t exist in map.
- `has(key)` – returns true if the key exists, false otherwise.
- `delete(key)` – removes the value by the key.
- `clear()` – removes everything from the map.
- `size` – returns the current element count.

```js
const rest = new Map();
rest.set("name", "Hotel Redison");
rest.set("location", "Dhaka, Bangladesh");
rest
  .set("categories", ["Deshi", "Indian", "Chinese", "Italiano"])
  .set("open", 11)
  .set("close", 23)
  .set(true, "We are open :D")
  .set(false, "We are closed :(");

console.log(rest.get("name")); // returns Hotel Redison
console.log(rest.get("location")); // returns Dhaka, Bangladesh

console.log(rest.get(true)); // returns We are open :D
const time = 21;
console.log(rest.get(time > rest.get("open") && time < rest.get("close")));

// truthy/falsy value AND conditional true/false, BOTH are different

console.log(rest.has("categories")); // returns true
```

## Map Iteration

```js
// Scratch to Code this method is BEST

const question = new Map([
  ["question", "What is the best programming language in the world?"],
  [1, "C"],
  [2, "Java"],
  [3, "Javascript"],
  ["correct", 3],
  [true, "Correct"],
  [false, "Try again!"],
]);

// Convert Object to Map
const hoursMap = new Map(Object.entries(openingHours));
console.log(hoursMap);

// Quiz app
console.log(question.get("question")); // returns question
for (const [key, value] of question) {
  if (typeof key === "number") console.log(`Answer ${key}: ${value}`); // returns 1-3 options
}
const answer = Number(prompt("Your answer"));
console.log(answer); // returns Input Answer
console.log(question.get(question.get("correct") === answer)); // Correct === Answer

// (===) USE Only for single Input/Output NOT for multiple output.

// Convert Map to Array
console.log([...question]); // Arrays of Arrays
// console.log(question.entries());
console.log([...question.keys()]);
console.log([...question.values()]);
```

# Scope & Hoisting

**Hoisting** is a JavaScript mechanism where variables and function declarations are moved to the top of their scope before code execution.

**🎯NOTE:**

- Variable assignment takes precedence over function declaration
- Function declarations take precedence over variable declarations

```js
console.log(a); // returns function body
var a;
function a() {
  // function declaration are hoisted before variable declaration
}
```

**🎯NOTE:** Functions defined using an expression are not hoisted. Only declared with var variable name are hoisted.

```js
console.log(a); // ReferenceError
const a = function(){
}

// Again

console.log(b) // undefined
var a = function
```

- Var - [✔] Redeclare, [✔] Reassign [✔] global [✔] function [❌] block
- Let - [❌] Redeclare, [✔] Reassign [✔] global [✔] block [✔] function
- Const = [❌] Redeclare, [❌] Reassign [✔] global [✔] block [✔] function

![alt text](https://lh3.googleusercontent.com/-ebijRdNr8HQ/YR_n2aOutgI/AAAAAAAACX8/e1djSHlQY04MY7Z-whPuL_vrwFvhKQO6ACLcBGAsYHQ/s16000/image.png)

🎯 [An introduction to scope in JavaScript](https://www.freecodecamp.org/news/an-introduction-to-scope-in-javascript-cbd957022652/) - freecodecamp

🎯 [Understanding Hoisting in JavaScript](https://www.digitalocean.com/community/tutorials/understanding-hoisting-in-javascript) - Digital Ocean

🎯 [JavaScript Scoping and Hoisting](http://www.adequatelygood.com/JavaScript-Scoping-and-Hoisting.html)

🎯 [JavaScript Hoisting](https://www.youtube.com/watch?v=pT9xqCS8Vwk&t=64s) - Learn With Sumit

🎯 [Difference between Global, Local and Block Scope](https://dev.to/ale3oula/the-hor-r-o-r-scope-global-local-and-block-scope-in-js-37a1)

# Strict Mode

- `"use strict";` Defines that JavaScript code should be executed in "strict mode".
- Strict mode changes previously accepted "bad syntax" into real errors.
- Make code more `secure` and `clean`.
- The "use strict" directive was new in ECMAScript version 5 (2009).
- It is not a statement, but a literal expression, ignored by earlier versions of JavaScript.

🎯**NOTE:** 'use strict' mode cannot allow to use without declaring a variable

```js
"use strict";
x = 3.14; // Error
```

🎯 [https://flaviocopes.com/javascript-strict-mode/](https://flaviocopes.com/javascript-strict-mode/)

🎯 [https://www.w3schools.com/js/js_strict.asp](https://www.w3schools.com/js/js_strict.asp)

# Classes

🎯 [JavaScript Classes](https://www.programiz.com/javascript/classes) - Programiz / Basics

🎯 [JavaScript Classes – How They Work with Use Case Example](https://www.freecodecamp.org/news/javascript-classes-how-they-work-with-use-case/) - freecodecamp / Advanced Topic 🔥

⭐ [Class](https://www.youtube.com/watch?v=ckdDIhQyK_A&t=51s)

## **What are classes?**

Classes are a template/blueprint for creating object by using constructor function.

- The `class` keyword is used to create a class. The properties are assigned in a constructor function.
- The `constructor()` method inside a class gets called automatically each time an object is initialized from class.
- Class name should be in PascalCase.

Syntax

```js
// creating a class
class Person {
  constructor(name) {
    this.name = name;
  }
}

// creating an object
const person1 = new Person("John");
const person2 = new Person("Jack");

console.log(person1.name); // John
console.log(person2.name); // Jack
```

```js
class Car {
  constructor(name, year) {
    // constructor method
    // constructor method
    this.name = name; // set the value of name property
    this.year = year; // set the value of year property
  }
  racing(status) {
    // prototype method
    // methods
    console.log(this.name + " " + "is racing" + " " + status);
  }
  static message() {
    // static method
    console.log("hello");
  }
}

// When the object is initialized, the constructor method is called inside class, with any parameters passed.
const toyota = new Car("Toyota", 2020); // initialize and create actual object
const audi = new Car("Audi", 2020); // initialize and create actual object
const bmw = new Car("BMW", 2021); // initialize and create actual object

console.log(toyota); // Toyota is called an instance of Car class
console.log(audi); // Audi is called an instance of Car class
console.log(bmw); // BMW is called an instance of Car class

// Invoke prototype methods on an instance of the class:
toyota.racing("fast");
audi.racing("slow");
bmw.racing("badly");

// Invoke static method:
Car.message();
```

### Extend a Class and super keyword

**Super Keyword**: is used in sub classes to access super/base/parent class.

```js
class Person {
  sayHello() {
    alert("hello");
  }
  walk() {
    alert("I am walking!");
  }
}

class Student extends Person {
  super(); // using super keyword we can access parent class
  sayGoodBye() {
    alert("goodBye");
  }
  sayHello() {
    alert("hi, I am a student");
  }
  useSuper(
    alert(`${super.walk()}`);
  )
}

let student1 = new Student();
student1.sayHello();
student1.walk();
student1.sayGoodBye();

// check inheritance
alert(student1 instanceof Person); // true
alert(student1 instanceof Student); // true
```

### Types of Methods

#### Constructor Method

- `constructor` method automatically called when a object initialized from a class.
- used for define properties or assign values to these properties

```js
// Constructor
constructor(){
  console.log("Hello");
}
```

#### Prototype Method

- This method can use any name and need to call for use this method
- used for calculation properties which are inside construction method

```js
// Prototype
message(){
  console.log("Hello");
}
```

#### Static Method

- This method includes static keyword and we can use any name
- This method is not dynamic, which means this method only used inside a class without creating any object

```js
// Static
static name(){
  console.log("Hello");
}
```

# Asynchronous JavaScript

<a href="https://ibb.co/pXx8XZv"><img src="https://blogger.googleusercontent.com/img/a/AVvXsEgx_qDUtXOg_uOcpbPDmsneKDl_gX3YZ-VVsFUT7JEi5jPXmhW-D077L5koiBuAHXkco8puico3YRW3CF7bF5S6XE5fh-mjaJuoDqbqjRueZ4YX-15B9nifnIt3NioVvQrnzXb22iwIo2iyguiANpIMiy0PXYWYUD_ieX1V31-if0daLqp_RGHyuyw2bw"></a>

🎯 [Synchronous vs Asynchronous](https://www.freecodecamp.org/news/synchronous-vs-asynchronous-in-javascript/) - freecodecamp.org

🎯 [Promises, async/await](https://javascript.info/async) - javascript.info

🎯 [Understanding the Event Loop, Callbacks, Promises, and Async/Await in JavaScript](https://www.taniarascia.com/asynchronous-javascript-event-loop-callbacks-promises-async-await/) - [💾 Tania Rascia](www.taniarascia.com/)

- **`Synchronous`** => Execution occuring at the same time by following sequence.
- **`Asynchronous`** => Not occuring at the same time and obviously not following sequence.

🎯**NOTE:** USE CASE

[1] Fetch data from server
[2] execute something with a delay
[3] execute something after an event

🎯**NOTE:** Async operation can be triggered by only 2 things =>

[1] Browser APIs / Web APIs

Examples:

- `setTimeout()`
- `setInterval()`
- Event Handler

[2] Promises => A unique JavaScript object that allows us to perform asynchronous operations.

### setTimeout()

The `setTimeout()` method executes a block of code after the specified time. The method executes the code only once.

Syntax

```js
setTimeout(function, milliseconds);
```

🎯 [Javascript setTimeout()](https://www.programiz.com/javascript/setTimeout)

### Callback Function

A callback is a function passed as an argument to another function.

This technique allows a function to call another function.

A callback function can run after another function has finished.

🎯 [JavaScript CallBack Function](https://www.programiz.com/javascript/callback)

### Promise

In JavaScript, a promise is a good way to handle asynchronous operations. It is used to find out if the asynchronous operation is successfully completed or not.

A promise may have one of three states.

[1] Pending
[2] Fulfilled
[3] Rejected

🎯 [JavaScript Promise and Promise Chaining](https://www.programiz.com/javascript/promise) - Programiz

🎯 [Using Promises](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises) - MDN Web Docs

🎯 [Async/Await](https://www.programiz.com/javascript/async-await) - Programiz

🎯 [try...catch...finally Statement](https://www.programiz.com/javascript/try-catch-finally) - Programiz

🎯 [throw Statement](https://www.programiz.com/javascript/throw) - Programiz

#### Creating a Promise Function

To create a promise object, we use the `Promise()` constructor.

Syntax

```js
let promise = new Promise(function (resolve, reject) {
  //do something
});
```

The `Promise()` constructor takes a function as an argument, this function is called executor function. The function also accepts two parameter those are also functions `resolve()` and `reject()`.

If the promise returns successfully, the `resolve()` function is called. And, if an error occurs, the `reject()` function is called.

Promise works after asynchronous operation execution.

```js
const count = true;
let promise = new Promise(function (resolve, reject) {
  if (count) {
    resolve("This a resolve");
  } else {
    reject("This is reject");
  }
});
```

```js
///// Sample 1 - Using Timer /////
function getAsyncData() {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve("Here is the resolved data");
    }, 2000);
  });
}

///// Sample 2 - Using MySQL /////
function getAsyncData() {
  return new Promise((resolve, reject) => {
    db.query("SELECT * FROM post", (error, response) => {
      if (error) {
        reject(error);
      } else {
        resolve(response);
      }
    });
  });
}
```

#### Using Promise Function

```js
// Option 1
getAsyncData()
  .then((result) => {
    // Do stuff
  })
  .catch((error) => {
    // Handle error
  })
  .finally(() => {
    // Finally always executed
  });

// Option 2
try {
  getAsyncData().then((result) => console.log(result));
} catch (error) {
  console.error(error);
}
```

#### Using Promise Function with Async and Await

```js
// (ES7 >) Async Function Loads in Order or Awaits calling Promises...
async function asyncFunction() {
  console.log("Getting Database Results Please Wait...");
  let result = await getAsyncData(); // Wait for Function with a Promise in it.
  console.log(result); // Results from getAsyncData
  return result;
}

// Option 1 for Calling Async Function
asyncFunction();

// Option 2 for Calling Async Function
asyncFunction()
  .then((result) => {
    console.log(`The Results: ${result}`);
  })
  .catch((error) => {
    // Handle error
  })
  .finally(() => {
    // Finally always executed
  });

// Option 3 for Calling Async Function
try {
  asyncFunction().then((result) => console.log(result));
} catch (error) {
  console.error(error);
}
```

### Javscript async/await[ES8]

🎯 [Javscript async/await](https://www.programiz.com/javascript/async-await) - Programiz

#### JavaScript async Keyword

We use the `async` keyword with a function to **`represent`** that the function is an **`asynchronous function`**. The async function returns a `promise`.

#### JavaScript await Keyword

The `await` keyword is used inside the async function to wait for the asynchronous operation.

The use of `await` pauses the async function until the promise returns a result (resolve or reject) value.

```js
// a promise
let promise = new Promise(function (resolve, reject) {
  setTimeout(() => {
    resolve("Promise resolved");
  }, 4000);
});

// async function
async function asyncFunc() {
  // wait for promise to complete and get result
  let result = await promise;
  // without await keyword other code will execute before promise get returns
  console.log(result);

  setTimeout(() => console.log("hello"), 500);
  console.log("No Time");
  console.log("No Time");
}

// calling the async function
asyncFunc();
```

### try...catch...finally Statement

The `try`, `catch` and `finally` blocks are used to handle exceptions (a type of an error).

🎯 [JavaScript try...catch...finally Statement](https://www.programiz.com/javascript/try-catch-finally)

### Error Handling

```js
try {
  // Block of code to try
} catch (err) {
  // Block of code to handle errors
} finally {
  // Block of code to be executed regardless of the try / catch result
}

throw "Too big"; // throw a text
throw 500; // throw a number
// The throw statement allows you to create a custom error.

try {
  if (x == "") throw "empty";
  if (x > 10) throw "too high";
} catch (err) {
  console.log(err);
  console.log(err.message);
}
```

# ES6

## Modern Operators

## Spread Operator(...)

```js
const restaurant = {
name: 'Classico Italiano',
location: 'Via Angelo Tavanti 23, Firenze, Italy',
categories: ['Italian', 'Pizzeria', 'Vegetarian', 'Organic'],
starterMenu: ['Focaccia', 'Bruschetta', 'Garlic Bread', 'Caprese Salad'],
mainMenu: ['Pizza', 'Pasta', 'Risotto'],

openingHours: {
thu: {
  open: 12,
  close: 22,
},
fri: {
  open: 11,
  close: 23,
},
sat: {
  open: 0, // Open 24 hours
  close: 24,
},
},

orderPasta: (ing1, ing2, ing3) => {
console.log(`Here is your delicious pasta with ${ing1}, ${ing2} and ${ing3}`);
},

};


/// BEST use for - Pass arguments into a function or build a new Array
const arr = [7, 8, 9]; // Unpacking all element at one
const badNewArr = [1, 2, arr[0], arr[1], arr[2]];
console.log(badNewArr); // returns [1, 2, 7, 8, 9]


/// Using Spread Operator(...) ///===>

const newArr = [1,2, ...arr]; // Automatically add comma(,) if there is other element with comma(,)
console.log(newArr); // returns [1, 2, 7, 8, 9]

console.log(...newArr); // returns 1 2 7 8 9 // Individual elements in the array

const newMenu = [...restaurant.mainMenu, 'Gnocci'];
console.log(newMenu); // returns ["Pizza", "Pasta", "Risotto", "Gnocci"]
console.log(...newMenu); // returns Pizza Pasta Risotto Gnocci

// Spread Operator is bit similer to destructuring because it also helps us get an element out of array.
// Big difference is spread operator take all the element from the array and it also does not create variables.


/// Shallow Copy array ///===>

const mainMenuCopy = [...restaurant.mainMenu]


/// Join Multiple Arrays ///===>

const menu = [...restaurant.starterMenu, ...restaurant.mainMenu]
console.log(menu); // returns ["Focaccia", "Bruschetta", "Garlic Bread", "Caprese Salad", "Pizza", "Pasta", "Risotto"]

// Spread Operator work not only on Arrays basically on all irritable
// What is irritable?
// ==> Iterable: arrays, strings, maps, sets but NOT Objects and Numbers

const str = 'Nur';
const latters = [...str];
console.log(...str); // returns N u r
console.log(latters); // returns ['N', 'u', 'r']
console.log(`${...str} Rafi`); // This is not a place that expects multiple value seperated by comma,
const numbers = 35468431;
const numbersStr = [...numbers];
console.log(numbersStr); // returns TypeError: numbers is not iterable


const ingredients = [prompt("Let's make pasta! Ingredient 1?"), prompt("Ingredient 2?"), prompt("Ingredient 3?")];
console.log(ingredients);

console.log(restaurant.orderPasta(...ingredients));

// Since 2018 Spread Operator(...) also works on Objects even though Objects are not Iterable.


/// Objects ///===>

const newRestaurant = {foundedIn: 2021, ...restaurant, founder: 'This is me'}
console.log(newRestaurant);


/// Shallow Copy Object ///===>

const restaurantCopy = {...restaurant}
console.log(restaurantCopy);
restaurantCopy.name = 'Nur Rafi'
console.log(restaurantCopy.name);
console.log(restaurant.name);

// We can build new Array and Object by copy them using Spread Operator(...) also edit them.
```

## Arguments Object

```js
/// Arguments Object ///===>

function add(a, b) {
  return a + b;
}

console.log(2, 5);

/// Calculate Unlimited number of arguments using Arguments Object ///===>

const numbers = [10, 20, 30, 40, 50];

function add() {
  let result = 0;
  for (let i = 0; i < arguments.length; i++) {
    result += arguments[i]; // Same As: x = x + y
  }
  return result;
}
console.log(add(...numbers)); // SPREAD operator

// Arguments Object NOT available in Arrow function

function add() {
  let result = 0;
  for (let i = 0; i < arguments.length; i++) {
    result += arguments[i]; // Addition Assignment Operator (+=)
  }
  return result;
}
console.log(add(10, 20)); // returns ReferenceError: arguments is not defined
```

## Rest Pattern and Parameters

```js
/// REST Parameter or Unused Parameter ///===>

// SPREAD, because on RIGHT side of =
const arr = [10, 20, ...[30, 40, 50]];

// REST, becuase on LEFT side of =
const [a, b, ...rest] = [10, 20, 30, 40, 50];

console.log(a); // returns 10
console.log(b); // returns 20
console.log(rest); // returns Array [30,40,50]

/// Destructuring using REST parameter(...otherFood) and SPREAD operator(...)=> Add 2 array ///===>
const [pizza, , risotto, ...otherFood] = [
  ...restaurant.mainMenu,
  ...restaurant.starterMenu,
];
console.log(pizza, risotto, otherFood); // returns Pizza Risotto Arrays ["Focaccia", "Bruschetta", "Garlic Bread", "Caprese Salad"]

/// Objects ///===>
const { thu, fri, ...weekend } = restaurant.openingHours;
console.log(weekend); // returns sat: {open: 0, close: 24}

// REST parameter in function
function person(name, age, ...degree) {
  console.log(name); // returns John
  console.log(age); // returns 25
  console.log(degree); // returns Array ['SSC', 'HSC']
}
person("John", 25, "SSC", "HSC");

function add(...numbers) {
  console.log(numbers);
}
add(2, 3); // returns [2, 3]
add(2, 3, 4, 5); // returns [2, 3, 4, 5]
add(2, 3, 4, 5, 6, 7); // returns [2, 3, 4, 5, 6, 7]

// Calculate Unlimited number of arguments using Arguments Object
const numbers = [10, 20, 30, 40, 50];

function add() {
  let result = 0;
  for (let i = 0; i < arguments.length; i++) {
    result += arguments[i]; // Same As: x = x + y
  }
  return result;
}
console.log(add(...numbers)); // SPREAD operator // returns 150
```

SPREAD Operator and REST Pattern syntax look exactly the same, but they work in opposite ways depending on where it is used.

Rest Pattern separated by commas(,) with variables and Spread Operators separated by commas(,) with values.

In Destructuring, Spread Operator is used on the right side of (=) & Rest Pattern is used on the left side of (=).

Rest Pattern is also known as Unused Parameter. Rest element must be the last element, there must be only one Rest element.

#### 👉🏻 Spread Operator(...) => Spread Array | Unpack Values.

#### 👉🏻 REST Parameter(...) => Compress Array | Pack Values.

## Short Circuiting (&& and ||)

- 0, '', undefined, null, NaN(Not a Number)
- 👉🏻 OR(||) operator will return 1st Truthy value or simply last value if all of them are falsy value. Value does not need to be Boolean.
- 👉🏻 AND(&&) operator will return 1st Falsy Value or simply last value if all of them are true.

#### Practical Use

- 👉🏻 OR(||) operator for set Default Value.
- 👉🏻 AND(&&) operator to Execute 2nd Value if the 1st one is true.

### Short-Circuiting

Use ANY data type, return ANY data type, short-circuiting also known as short-circuit evaluation.

If the 1st value is the truthy value then immediately return the 1st value. Javascript stop looking for other values.

```js
/// Falsy Value ///===>
// 0, '', undefined, null, NaN(Not a Number)

console.log(3 || "Jonas"); // return: 3
console.log("" || "Jonas"); // return: Jonas
console.log(true || 0); // returns true
console.log(undefined || null); // returns null // the is no short-circuiting
console.log(undefined || 0 || "" || "Hello" || 313 || null); // returns Hello

/// Setting Default Value ///===>

// Ternary Operator
restaurant.numGuests = 23; // if 0 it will not work and value will be 10
const guest1 = restaurant.numGuests ? restaurant.numGuests : 10;
console.log(guest1);

// OR(||) Operator and Short-Circuiting
restaurant.numGuests = 23; // if 0 it will not work and value will be 10
const guest2 = restaurant.numGuests || 10;
console.log(guest2); //

// restaurant.numGuests = 0;
// Both method will not work if the value is 0, but there is other SOLUTION

console.log(0 && "Jonas"); // returns 0
console.log(7 && "Jonas"); // returns Jonas
console.log(("Hello" && 313) || (null && undefined)); // returns null
```

## The Nullish Coalescing Operator (??)

```js
// ES 2020
// Nullish: null and undefined (NOT 0 or '')
restaurant.numGuests = 0;
const guest = restaurant.numGuests ?? 10;
console.log(guest); // return: 0

// 0 and '' is truthy value for Nullish Coalescing Operator
```

## Optional Chaining Operator(.?)

The optional chaining operator (?.) allows you to access the value of a property located deep within a chain of objects, If a certain property does not exist then return undefined immediately.

#### Nullish Coalescing Operator(??) 🤝🏻 Optional Chaining Operator(.?)

```js
if (restaurant.openingHours && restaurant.openingHours.mon)
  console.log(restaurant.openingHours.mon.open); // returns Error

// WITH Optional Chaining
console.log(restaurant.openingHours.mon?.open);

// MULTIPLE Optional Chaining
console.log(restaurant.openingHours?.mon?.open);

// Example
const shop = {
  openingHours: {
    thu: {
      open: 12,
      close: 22,
    },
    fri: {
      open: 11,
      close: 23,
    },
    sat: {
      open: 0, // Open 24 hours
      close: 24,
    },
  },
};

const days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

for (const day of days) {
  const open = shop.openingHours[day]?.open; // Using a variable to refer to a property name, we need to use [day] Notation.
  console.log(`On ${day}, we open at ${open}`);

  // Set Default Value Instead of UNDEFINED using OR(||) Operator
  const open = shop.openingHours[day]?.open || "closed";
  console.log(`On ${day}, we open at ${open}`);

  // If value is 0 or '' use AND(??) Operator
  const open = shop.openingHours[day]?.open ?? "closed";
  console.log(`On ${day}, we open at ${open}`);
}
```

## Import

```js
import "helpers";
// aka: require('···')

import Express from "express";
// aka: const Express = require('···').default || require('···')

import { indent } from "helpers";
// aka: const indent = require('···').indent

import * as Helpers from "helpers";
// aka: const Helpers = require('···')

import { indentSpaces as indent } from "helpers";
// aka: const indent = require('···').indentSpaces
```

## Export

```js
export default function () { ··· }
// aka: module.exports.default = ···

export function mymethod () { ··· }
// aka: module.exports.mymethod = ···

export const pi = 3.14159
// aka: module.exports.pi = ···
```

# Destructuring

🎯 [JavaScript Destructuring Assignment](https://www.programiz.com/javascript/destructuring-assignment) - Programiz

🎯 [Destructuring Assignment](https://javascript.info/destructuring-assignment) - javscript.info

🎯 [Object.keys, values, entries](https://javascript.info/keys-values-entries) - javascript.info

## Destructuring - Arrays

```js
const restaurant = {
  name: "Classico Italiano",
  location: "Via Angelo Tavanti 23, Firenze, Italy",
  categories: ["Italian", "Pizzeria", "Vegetarian", "Organic"],
  starterMenu: ["Focaccia", "Bruschetta", "Garlic Bread", "Caprese Salad"],
  mainMenu: ["Pizza", "Pasta", "Risotto"],

  order: function (starterIndex, mainIndex) {
    return [this.starterMenu[starterIndex], this.mainMenu[mainIndex]];
  },
};

const arr = [2, 3, 4];
// normal method =>
const a = arr[0];
const b = arr[1];
const c = arr[2];

// destructuring method =>
const [x, y, z] = arr; // This is not array, just a Distructuring assignment
console.log(x, y);
console.log(x, y, z);

/// Restaurant Categories ///===>

// first and second
const [first, second] = restaurant.categories;
console.log(first, second);

// first and third
let [main, , secondary] = restaurant.mainMenu; // skipping elements using skip(,)
console.log(main, secondary); // returns Italian Vegetarian
```

#### Reverse or Swap or Switching Variables

```js
// normal method =>
const temp = main; // temporary variable 🥃♻🥛♻🥃
main = secondary;
secondary = temp;
console.log(main, secondary); // returns Vegetarian Italian

// distructuring method =>
[main, secondary] = [secondary, main];
console.log(main, secondary); // returns Vegetarian Italian
```

#### Distructuring Function

```js
// normal method =>
const order = restaurant.order(2, 0);
console.log(order); // returns 'Garlic Bread', 'Pizza'

// destructuring method =>
// Receive 2 return values from a function
const [starterIdx, mainIdx] = restaurant.order(2, 0); // Destruction Assignment = Calling a function with(parameters)
console.log(starterIdx, mainIdx); // returns 'Garlic Bread', 'Pizza'
```

#### Nested Destructuring

```js
const nested = [2, (4)[(5, 6)]]; // nested = array inside an array
const [i, , j] = nested;
console.log(i, j); // returns 2 [5, 6]

const [i, , [j, k]] = nested;
console.log(i, j, k); // returns 2, 5, 6
```

#### Setup Default Values

```js
// normal method = undefined
const [p, q, r] = [8, 9];
console.log(p, q, r); // returns 8, 9, undefined

// Default Value
const [p = 1, q = 1, r = 1] = [8, 9];
console.log(p, q, r); // returns 8, 9, 1
// This is usefull when we get data from API
```

## Destructuring - Objects

```js
const restaurant = {
  name: "Classico Italiano",
  location: "Via Angelo Tavanti 23, Firenze, Italy",
  categories: ["Italian", "Pizzeria", "Vegetarian", "Organic"],
  starterMenu: ["Focaccia", "Bruschetta", "Garlic Bread", "Caprese Salad"],
  mainMenu: ["Pizza", "Pasta", "Risotto"],

  openingHours: {
    thu: {
      open: 12,
      close: 22,
    },
    fri: {
      open: 11,
      close: 23,
    },
    sat: {
      open: 0, // Open 24 hours
      close: 24,
    },
  },

  orderDelivery: function ({ starterIndex, mainIndex, time, address }) {
    console.log(
      `Order received! ${this.starterMenu[starterIndex]} and ${this.mainMenu[mainIndex]} will be deliverd to ${address} at ${time}`
    );
  },
};
```

#### Object Calling Function 🙁

```js
restaurantName.orderDelivery({
  time: "22:30",
  address: "Via del Sole, 21",
  mainIndex: 2,
  starterIndex: 2,
}); // If there is lots of parameters, 1st write object property then write function parameters.
```

#### Fundamental of Destructuring Objects

```js
const { name, openingHours, categories } = restaurant;
console.log(name, openingHours, categories);
// API data comes with Objects, So Destructuring is life saving method of Javascript. Like Weather Data, Movie Data //
```

#### Setup New Variables

```js
const {
  name: restaurantName,
  openingHours: hours,
  categories: tags,
} = restaurant;
// What if we want a new variable name from the property name, So write old name as reference and assign new name.
console.log(restaurantName, hours, tags); // Helpful for dealing with 3rd party data
```

#### Setup default value which is [empty]

```js
const { menu = [], starterMenu: starters = [] } = restaurantName;
console.log(menu, starters); // menu does not exist on restaurent Object so value is [empty]
// If we do not setup default value result will be [undefined]
// In real life API data do not comes with hardcoded like restaurent Object
// We do not know how will be data looks like, So setup default value is useful.
```

#### Mutating Variables | (Reassign Values to Variables)

```js
let a = 111;
let b = 222;
const obj = {a: 23, b: 7, c: 14};
{a, b} = obj;
console.log(a, b); // returns Unexpected token error '='
// solution is using parenthesis()
({a, b} = obj);
console.log(a, b); // returns 23, 7
```

#### Nested Objects

```js
const { fri } = openingHours;
console.log(fri); // {open: 11, close: 23}
// but we need open and close separately
const {
  fri: { open, close },
} = openingHours; // we can go more deep like {{{}}}
console.log(open, close);
```

#### Destructuring Fetch Object

```js
// Normal Method - [Without destructuring]
const getCountryHTML = (country) => {
  return `
	<div>
	<h2>${country.name.common}<h2>
	<img src="${country.name.flags.png}">
	</div>
	`;
};

// Option 1 - [Destructuring outside parameter]
const getCountryHTML = (country) => {
  const { name, flags } = country;

  return `
	<div>
	<h2>${name.common}<h2>
	<img src="${name.flags.png}">
	</div>
	`;
};

// Option 2 - [Destructuring inside parameter]
const getCountryHTML = ({ name, flags }) => {
  return `
	<div>
	<h2>${name.common}<h2>
	<img src="${name.flags.png}">
	</div>
	`;
};
```

# Regex

# API - Application Programming Interface

🎯 [What is an API?](https://www.youtube.com/watch?v=s7wmiS2mSXY)

🎯 [Web API](https://www.javascripttutorial.net/web-apis/) - www.javascripttutorial.net

### Useful API List

1. https://jsonplaceholder.typicode.com/ - Practice
2. https://randomuser.me/ - Get Random User
3. https://restcountries.com/ - Get Countries Information
4. https://unsplash.com/developers - Get Random Photos
5. https://source.unsplash.com/random - Get Random Photos
6. https://www.themealdb.com/api.php - Free Meal

## JSON - JavaScript Object Notation

### What is notation?

- A system of written symbols used to represent numbers, amounts, or elements in something such as music, mathematics and programming language.
- Language writing system

🎯 [JSON Path Finder](https://jsonpathfinder.com/)

🎯 [JSON Data to Schema Converter](https://www.liquid-technologies.com/online-json-to-schema-converter)

🎯 [JSON Schema Validator](https://www.jsonschemavalidator.net/)

🎯 [JSON Viewer](https://codebeautify.org/jsonviewer)

### `JSON.stringify(object)` Convert object to string

- Converts a JavaScript value to a JavaScript Object Notation (JSON) string.
- Cannot access like object

```js
const shop = {
  name: "Nahar Store",
  address: "Gulshan 01",
  products: ["laptop", "mobile", "tv", "computer"],
  isExpensive: false,
};

const shopString = JSON.stringify(shop); // Convert object to string
```

### `JSON.parse(string)` Convert string to object

- Converts a JavaScript Object Notation (JSON) string into an object.
- Can access like object

```js
let shop =
  '{"name":"Nahar Store","address":"Gulshan 01","products":["laptop","mobile","tv","computer"],"isExpensive":false}';

const shopObject = JSON.stringify(shop); // Convert string to object
```

## Fetch

- meaning (go and get)
- fetch() method/function in JavaScript is used to request to the server and load the information in the webpages
- (response) and (data) are parameter, also variable
- response receive data from server
- response.json() convert string to object
- data is converted object
- err is used for provide error message to user

🎯 [JavaScript Fetch API](https://www.javascripttutorial.net/javascript-fetch-api/) - www.javascripttutorial.net

### Fetch (GET) JSON

#### Using arrow function for get data

```js
fetch("url")
  .then((res) => res.json())
  .then((data) => console.log(data))
  .catch((err) => console.log(err));
```

#### Using async/await

```js
async function loadData() {
  const res = await fetch(url);
  const data = await res.json();
  displayData(data);
}
```

#### Handle fetch error, use try catch

```js
// Method 01
function loadData(){
	fetch(url)
	.then(res => res.json())
	.then(data => displayData(data))
	.catch(error = > displayError(error))
}

// Method 02
try{
	async function loadData(){
	const res = await fetch(url);
	const data = await res.json();
	displayData(data);
}
}
catch(error){
	displayError(error)
}
```

#### Common API Data access related issues

```js
const loadData = () =>{
	fetch(url)
	.then(res => res.json())
	.then(data => { // condition checking
		if(){

		} else{
			displayData(data);
		}
	})
}

const displayData = (data) =>{
	// display data
}

```

#### Using arrow function for load and display api data

```js
function loadPosts() {
  fetch("url")
    .then((res) => res.json())
    .then((data) => displayPosts(data))
    .then((err) => showError(err));
}

function displayPosts(data) {
  const postContainer = document.getElementById("posts"); // select container
  for (const post of posts) {
    console.log(post);
    const div = document.createElement("div"); // create child
    div.innerHTML = `
  <h3>${post.title}</h3>
  <p>${post.body}</p>
  `;
    postContainer.appendChild(div); // add element inside container
  }
}

loadPosts(); // display on load
```

#### Call dynamic API, load dynamic data to display

```html
<button onclick="loadCountryByName('${name}')">Details</button>
```

```js
const loadCountryByName = name => {

	✔✔✔ Dynamic url
	const url = `https://restcountries.com/v3.1/name/${name}`;

	fetch(url)
	.then(res => res.json())
	.then(data => displayCountryDetails(data))
}

const displayCountryDetails = country =>{
	// Code for display data
}
```

### Fetch (POST) Extended header

```js
fetch("http://example.com/movies.json", {
  method: "POST", // *GET, POST, PUT, DELETE, etc.
  mode: "cors", // no-cors, cors, *same-origin
  cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
  credentials: "same-origin", // include, same-origin, *omit
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    // "Content-Type": "application/x-www-form-urlencoded",
  },
  redirect: "follow", // manual, *follow, error
  referrer: "no-referrer", // no-referrer, *client
  body: JSON.stringify(data), // body data type must match "Content-Type" header
}).then((response) => response.json()); // parses response to JSON
```

### Fetch (POST / PUT) JSON

```js
let url = "https://example.com/profile";
let data = { username: "example" };

fetch(url, {
  method: "POST", // or 'PUT'
  body: JSON.stringify(data), // data can be `string` or {object}!
  headers: {
    "Content-Type": "application/json",
  },
})
  .then((res) => res.json())
  .then((response) => console.log("Success:", JSON.stringify(response)))
  .catch((error) => console.error("Error:", error));
```

### Fetch (POST) Multiple Files

```js
let formData = new FormData();
let photos = document.querySelector("input[type='file'][multiple]");

formData.append("title", "My Vegas Vacation");
formData.append("photos", photos.files);

fetch("https://example.com/posts", {
  method: "POST",
  body: formData,
})
  .then((response) => response.json())
  .then((response) => console.log("Success:", JSON.stringify(response)))
  .catch((error) => console.error("Error:", error));
```

# Web API

🎯 [Web API](https://www.javascripttutorial.net/web-apis/) - www.javascripttutorial.net

## LocalStorage

```js
// Primitive Value
localStorage.setItem("key", "value");
localStorage.getItem(key, value);

// Non-Primitive Value (array, object)
localStorage.setItem("key", JSON.stringify(value));
JSON.parse(logalStorage.getItem("key"));
```

```js
let storage = window.localStorage; // Set Storage (5MB LIMIT !!!)

storage.setItem("Name", "Tom"); // Add Data to a field/keys
storage.getItem("Name"); // Returns Tom
storage.removeItem("Name"); // Remove Data & Field / Key
storage.clear(); // Clear all items in localStorage
```

# DOM Document Object Model

DOM is a Document Object Model & Programming Interface for HTML and XML documents that defines properties, objects, events & methods to get, change, add or delete elements.

- P [Properties]
- O [Objects]
- E [Events]
- M [Methods]

🎯 [JavaScript DOM (Basic)](https://www.w3schools.com/js/js_htmldom.asp) - W3School

🎯 [DOM Manipulation Cheat Sheet](https://htmldom.dev/) ⭐⭐⭐⭐⭐

🎯 [17 Most Important DOM Manipulation Methods in JavaScript](https://codevoweb.com/important-dom-manipulation-methods-in-javascript/)

🎯 [Event](https://developer.mozilla.org/en-US/docs/Web/API/Event) - MDN Web Docs

🎯 [Event Reference](https://developer.mozilla.org/en-US/docs/Web/Events) - MDN Web Docs


### Node Types

```js
1. Element_Node
2. Attribute_Node
3. Text_Node
4. CData_Selection_Node
5. Entity_Reference_Node
6. Entity_Node
7. Processing_Instruction_Node
8. Comment_Node
9. Document_Node
10. Document_Type_Node
11. Document_Fragment_Node
12. Notation_Node
[Depricated: 2, 5, 6, 12]
```

### Explore getElementsByClassName and querySelectorAll

```js
1) getElementsByTagName 	[HTMLCollection]
2) getElementById			    [HTMLCollection]
3) getElementsByClassName	[HTMLCollection]
4) querySelector(1st el)	[NodeList] [CSS Selector]
5) querySelectorAll			  [NodeList] [CSS Selector]
```

### DOM Find the Element

```js
document.getElementById(id);
document.getElementsByTagName(name);
document.getElementsByClassName(name);
document.querySelectorAll("p.intro"); // Returns all p with class intro.
document.body;
document.head;
document.images;
document.forms["id"];
document.links;
document.scripts;
document.title;
```

### DOM Change the Element

```js
let element = document.getElementById(id);

element.innerHTML = `<span>My name is <b>Rafe</b></span>`; // HTML tags and text // {Most Used}
element.innerText = "new html content"; // Text inside element/tags // My name is Rafe
element.textContent = "new html content"; // Text inside element/tags // My name is *Rafe* {FASTEST}
element.attribute = "new value"; // Change the attribute value of an HTML element
element.setAttribute("attribute", "value"); // Change the attribute value of an HTML element
element.removeAttribute("attribute"); // just attribute name
img.src = "new path"; // Change the attribute value of an HTML element
a.href = "new link"; // Change the attribute value of an HTML element
element.style.property = "new style"; // Change the style of an HTML element
element.style.color = "red"; // Add Colour to Style
```

### DOM Add and Delete Elements

```js
document.createElement("element"); // Create an HTML element/tags
document.removeChild(element); // Remove an HTML element
document.appendChild(element); // Add an HTML element
document.replaceChild(newChild, oldChild); // Replace an HTML element
document.write("Hello World!"); // Write into the HTML output stream
element.innerHTML = ""; // NOT RECOMMANDED [Causes Memory Leak]
element.textContent = ""; // Best for clear previous content
```

### DOM Add Style (add, remove & toggle)

```js
.classList.add('class-name') // Add css class
.classList.remove('class-name') // Remove css class
.classList.toggle('class-name') // Automatically add or remove class by
```

### 3 ways to add class

```js
const addBtn = document.getElementById("add-btn");
addBtn.className = "btn btn-warning"; // single class
addBtn.classList.add("btn", "btn btn-danger"); // multiple classes
addBtn.setAttribute("class", "btn btn-success"); // [attr, value]
```

### DOM Node Tree

```js
// You can use the following node properties to navigate between nodes with JavaScript:
.parentNode
.childNodes[nodenumber]
.firstChild
.lastChild
.nextSibling
.previousSibling

event.target.parentNode;
let myTitle = document.getElementById("demo").firstChild.nodeValue;
let myTitle = document.getElementById("demo").childNodes[0].nodeValue;
```

### DOM Event Handlers (6 ways)

```js
// 1 inline onClick with single line code
<button onclick="alert(7)">Click Me</button>
<button onclick="document.body.style.backgroundColor = 'pink'">Click Me: Pink</button>

// 2 inline onClick with external function
<button onclick="makeRed()">Click Me: Red</button>

function makeRed() {
  document.body.style.backgroundColor = "red";
}

// 3 external onClick with function declaration
<button id="grayColor">Click Me: Gray</button>
function makeGray() {
  document.body.style.backgroundColor = "gray";
}

const grayBtn = document.getElementById("grayColor");
// just set the name of the function without (call) it, otherwise it will run immediately
grayBtn.onclick = makeGray;

// 4 external onClick with anonymous function or function declaration
<button id="greenColor">Click Me: Green</button>

// 4.1 (function declaration)
const greenBtn = document.getElementById("greenColor");
// just set the name of the function without (call) it, otherwise it will run immediately
greenBtn.onclick = makeGreen;

function makeGreen() {
  document.body.style.backgroundColor = "green";
};
// 4.2 (Anonymous function)
greenBtn.onclick = function () {
  document.body.style.backgroundColor = "LawnGreen";
};

// 5 addEventListener with anonymous function or function declaration
<button id="blueColor">Click Me: Blue</button>

// 5.1 (function declaration)
const blueBtn = document.getElementById("blueColor");
blueBtn.addEventListener("click", makeBlue);
function makeBlue() {
  document.body.style.backgroundColor = "navy";
}

// 5.2 (Anonymous function)
blueBtn.addEventListener("click", function () {
  document.body.style.backgroundColor = "blue";
});

// 6 direct shortcut [get > addEventListener > anonymous function]
<button id="goldenColor">Click Me: Golden</button>

document.getElementById('goldenColor').addEventListener('click', function(){
  document.body.style.backgroundColor = 'goldenrod';
})
```

### Event Handler Object

The `e` parameter of the function is an optional parameter of the input event handler which equals to a **`JavaScript Event Object`** that contains information regarding what action or event just happened.

`event.target` returns the node that was targeted by the function.

`event.target.parentNode` returns the parent of targeted node

```js
element.addEventListener("click", function (e) {
  console.log(e);
  // What is "e"?
});
```

### Event Bubble

#### Use Event Bubble to create calculator and clear

```js
document.getElementById("key-pad").addEventListener("click", function (e) {
  const number = event.target.value;
  const calcInput = getElementById("typed-numbers");
  if (isNan(number)) {
    if (number == "C") {
      calcInput.value = "";
    } else {
      const previousNumber = calcInput.value;
      const newNumber = previousNumber + number;
      calcInput.value = newNumber;
    }
  }
});
```

### Event Delegation

### Dom Manipulation Tricks

```js
// 1 clear data dynamically

	clear input value
		> input.value = "";
	clear previous content
		> parentElement.textContent = "";
	clear previous search result count
		> result.style.display = "none"

// 2 handle spinner and display

const toggleSpinner = displayStyle =>{
	document.getElementById('spinner').style.display = displayStyle;
}

const toggleSearchResult = displayStyle =>{
	document.getElementById('search-result').style.visibility = displayStyle;
}

	// after click search btn
	toggleSpinner('block');
	toggleSearchResult('hidden');

	// before display data
	toggleSpinner('none');
	toggleSearchResult('visible');


// 3 No meaningful search and api result null instead of array

	// optional chaining
	players?.forEach(player =>{
		// display data
	})

	// conditional checking
	if(!players){
		// do something
	}

// 4 if any property is null

<img src="${object.img ? object.img : 'Image not found'}">
```

### DOM Events

<table>
	<tbody>
		<tr>
			<th>Event</th>
			<th>Description</th>
			<th>Belongs To</th>
		</tr>
		<tr>
			<td>abort</td>
			<td>The event occurs when the loading of a media is aborted</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>afterprint</td>
			<td>The event occurs when a page has started printing, or if the print dialogue box has been closed</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>animationend</td>
			<td>The event occurs when a CSS animation has completed</td>
			<td>AnimationEvent</td>
		</tr>
		<tr>
			<td>animationiteration</td>
			<td>The event occurs when a CSS animation is repeated</td>
			<td>AnimationEvent</td>
		</tr>
		<tr>
			<td>animationstart</td>
			<td>The event occurs when a CSS animation has started</td>
			<td>AnimationEvent</td>
		</tr>
		<tr>
			<td>beforeprint</td>
			<td>The event occurs when a page is about to be printed</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>beforeunload</td>
			<td>The event occurs before the document is about to be unloaded</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td><b>blur*</b></td>
			<td>The event occurs when an element loses focus</td>
			<td>FocusEvent</td>
		</tr>
		<tr>
			<td>canplay</td>
			<td>The event occurs when the browser can start playing the media (when it has buffered enough to begin)</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>canplaythrough</td>
			<td>The event occurs when the browser can play through the media without stopping for buffering</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>change</td>
			<td>The event occurs when the content of a form element, the selection, or the checked state have changed (for <code>input select and textarea</code>)</td>
			<td>Event</td>
		</tr>
    <tr>
			<td><b>click*</b></td>
			<td>The event occurs when the user clicks on an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>contextmenu</td>
			<td>The event occurs when the user right-clicks on an element to open a context menu</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>copy</td>
			<td>The event occurs when the user copies the content of an element</td>
			<td>ClipboardEvent</td>
		</tr>
		<tr>
			<td>cut</td>
			<td>The event occurs when the user cuts the content of an element</td>
			<td>ClipboardEvent</td>
		</tr>
		<tr>
			<td>dblclick</td>
			<td>The event occurs when the user double-clicks on an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>drag</td>
			<td>The event occurs when an element is being dragged</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>dragend</td>
			<td>The event occurs when the user has finished dragging an element</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>dragenter</td>
			<td>The event occurs when the dragged element enters the drop target</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>dragleave</td>
			<td>The event occurs when the dragged element leaves the drop target</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>dragover</td>
			<td>The event occurs when the dragged element is over the drop target</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>dragstart</td>
			<td>The event occurs when the user starts to drag an element</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>drop</td>
			<td>The event occurs when the dragged element is dropped on the drop target</td>
			<td>DragEvent</td>
		</tr>
		<tr>
			<td>durationchange</td>
			<td>The event occurs when the duration of the media is changed</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>ended</td>
			<td>The event occurs when the media has reach the end (useful for messages like "thanks for listening")</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>error</td>
			<td>The event occurs when an error occurs while loading an external file </td>
			<td>ProgressEvent, UiEvent, Event</td>
		</tr>
		<tr>
			<td><b>focus*</b></td>
			<td>The event occurs when an element gets focus</td>
			<td>FocusEvent</td>
		</tr>
		<tr>
			<td>focusin</td>
			<td>The event occurs when an element is about to get focus</td>
			<td>FocusEvent</td>
		</tr>
		<tr>
			<td>focusout</td>
			<td>The event occurs when an element is about to lose focus</td>
			<td>FocusEvent</td>
		</tr>
		<tr>
			<td>fullscreenchange</td>
			<td>The event occurs when an element is displayed in fullscreen mode</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>fullscreenerror</td>
			<td>The event occurs when an element can not be displayed in fullscreen mode</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>hashchange</td>
			<td>The event occurs when there has been changes to the anchor part of a URL</td>
			<td>HashChangeEvent</td>
		</tr>
		<tr>
			<td>input</td>
			<td>The event occurs when an element gets user input</td>
			<td>InputEvent, Event</td>
		</tr>
		<tr>
			<td>invalid</td>
			<td>The event occurs when an element is invalid</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>keydown</td>
			<td>The event occurs when the user is pressing a key</td>
			<td>KeyboardEvent</td>
		</tr>
		<tr>
			<td>keypress</td>
			<td>The event occurs when the user presses a key [Deprecated]</td>
			<td>KeyboardEvent</td>
		</tr>
		<tr>
			<td><b>keyup</b></td>
			<td>The event occurs when the user releases a key</td>
			<td>KeyboardEvent</td>
		</tr>
		<tr>
			<td>load</td>
			<td>The event occurs when an object has loaded</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>loadeddata</td>
			<td>The event occurs when media data is loaded</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>loadedmetadata</td>
			<td>The event occurs when meta data (like dimensions and duration) are loaded</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>loadstart</td>
			<td>The event occurs when the browser starts looking for the specified media</td>
			<td>ProgressEvent</td>
		</tr>
		<tr>
			<td>message</td>
			<td>The event occurs when a message is received through the event source</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>mousedown</td>
			<td>The event occurs when the user presses a mouse button over an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mouseenter</td>
			<td>The event occurs when the pointer is moved onto an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mouseleave</td>
			<td>The event occurs when the pointer is moved out of an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mousemove</td>
			<td>The event occurs when the pointer is moving while it is over an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mouseover</td>
			<td>The event occurs when the pointer is moved onto an element, or onto one of its children</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mouseout</td>
			<td>The event occurs when a user moves the mouse pointer out of an element, or out of one of its children</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mouseup</td>
			<td>The event occurs when a user releases a mouse button over an element</td>
			<td>MouseEvent</td>
		</tr>
		<tr>
			<td>mousewheel</td>
			<td>Deprecated. Use the wheel event instead</td>
			<td>WheelEvent</td>
		</tr>
		<tr>
			<td>offline</td>
			<td>The event occurs when the browser starts to work offline</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>online</td>
			<td>The event occurs when the browser starts to work online</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>open</td>
			<td>The event occurs when a connection with the event source is opened</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>pagehide</td>
			<td>The event occurs when the user navigates away from a webpage</td>
			<td>PageTransitionEvent</td>
		</tr>
		<tr>
			<td>pageshow</td>
			<td>The event occurs when the user navigates to a webpage</td>
			<td>PageTransitionEvent</td>
		</tr>
		<tr>
			<td>paste</td>
			<td>The event occurs when the user pastes some content in an element</td>
			<td>ClipboardEvent</td>
		</tr>
		<tr>
			<td>pause</td>
			<td>The event occurs when the media is paused either by the user or programmatically</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>play</td>
			<td>The event occurs when the media has been started or is no longer paused</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>playing</td>
			<td>The event occurs when the media is playing after having been paused or stopped for buffering</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>popstate</td>
			<td>The event occurs when the window's history changes</td>
			<td>PopStateEvent</td>
		</tr>
		<tr>
			<td>progress</td>
			<td>The event occurs when the browser is in the process of getting the mediadata (downloading the media)</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>ratechange</td>
			<td>The event occurs when the playing speed of the media is changed</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>resize</td>
			<td>The event occurs when the document view is resized</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>reset</td>
			<td>The event occurs when a form is reset</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>scroll</td>
			<td>The event occurs when an element's scrollbar is being scrolled</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>search</td>
			<td>The event occurs when the user writes something in a search field input="search"</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>seeked</td>
			<td>The event occurs when the user is finished moving/skipping to a new position in the media</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>seeking</td>
			<td>The event occurs when the user starts moving/skipping to a new position in the media</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>select</td>
			<td>The event occurs after the user selects sometext (for <code>input and textarea</code>)</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>show</td>
			<td>The event occurs when a menu element is shown as a context menu</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>stalled</td>
			<td>The event occurs when the browser is trying to get media data, but data is not available</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>storage</td>
			<td>The event occurs when a Web Storage area is updated</td>
			<td>StorageEvent</td>
		</tr>
		<tr>
			<td>submit</td>
			<td>The event occurs when a form is submitted</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>suspend</td>
			<td>The event occurs when the browser is intentionally not getting media data</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>timeupdate</td>
			<td>The event occurs when the playing position has changed (like when the user fast forwards to a different point in the media)</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>toggle</td>
			<td>The event occurs when the user opens or closes the details element</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>touchcancel</td>
			<td>The event occurs when the touch is interrupted</td>
			<td>TouchEvent</td>
		</tr>
		<tr>
			<td>touchend</td>
			<td>The event occurs when a finger is removed from a touch screen</td>
			<td>TouchEvent</td>
		</tr>
		<tr>
			<td>touchmove</td>
			<td>The event occurs when a finger is dragged across the screen</td>
			<td>TouchEvent</td>
		</tr>
		<tr>
			<td>touchstart</td>
			<td>The event occurs when a finger is placed on a touch screen</td>
			<td>TouchEvent</td>
		</tr>
		<tr>
			<td>transitionend</td>
			<td>The event occurs when a CSS transition has completed</td>
			<td>TransitionEvent</td>
		</tr>
		<tr>
			<td>unload</td>
			<td>The event occurs once a page has unloaded (for <code>body</code>)</td>
			<td>UiEvent, Event</td>
		</tr>
		<tr>
			<td>volumechange</td>
			<td>The event occurs when the volume of the media has changed (includes setting the volume to "mute")</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>waiting</td>
			<td>The event occurs when the media has paused but is expected to resume (like when the media pauses to buffer more data)</td>
			<td>Event</td>
		</tr>
		<tr>
			<td>wheel</td>
			<td>The event occurs when the mouse wheel rolls up or down over an element</td>
			<td>WheelEvent</td>
		</tr>
	</tbody>
</table>

### DOM Alert / Popup

```js
window.alert("Hello World");
alert("Hello World");

window.confirm("sometext");
confirm("sometext");

confirm("sometext");

if (confirm("Press a button!")) {
  txt = "You pressed OK!";
} else {
  txt = "You pressed Cancel!";
}

window.prompt("sometext", "defaultText");
prompt("sometext", "defaultText");

let person = prompt("Please enter your name", "Harry Potter");
if (person == null || person == "") {
  txt = "User cancelled the prompt.";
} else {
  txt = "Hello " + person + "! How are you today?";
}
```

### DOM (BOM) Window / Screen Methods

```js
window.innerHeight; // Browser Height in pixels
window.innerWidth; // Browser Width in pixels

window.open(); // open a new window
window.close(); // close the current window
window.moveTo(); // move the current window
window.resizeTo(); // resize the current window

screen.width;
screen.height;
screen.availWidth;
screen.availHeight;
screen.colorDepth;
screen.pixelDepth;
```

### DOM (BOM) Locations and History

```js
window.location.href; // property returns the URL of the current page
window.location.hostname; // property returns the name of the internet host
window.location.pathname; // property returns the pathname of the current page
window.location.protocol; // property returns the web protocol of the page
window.location.port; // property returns the number of the internet host port
window.location.assign("https://URL"); // method loads a new document

window.history.back(); // method loads the previous URL in the history list
window.history.forward(); // method loads the next URL in the history list
```

### DOM Window / Browser Navigator

```js
navigator.appName; // Returns the application name of the browser
navigator.appCodeName; // Returns the application code name of the browser
navigator.appVersion; // Returns version information about the browser
navigator.platform; // Returns the browser platform (operating system)
navigator.cookieEnabled; // Returns true if cookies are enabled, otherwise false
navigator.product; // Returns Browser Engine
navigator.userAgent; // Returns the user-agent header sent by the browser to the server
navigator.language; // Returns the browser's language

navigator.onLine; // onLine property returns true if the browser is online
navigator.offLine; // offLine property returns true if the browser is offline

navigator.javaEnabled(); // Returns true if Java is enabled
```

# Object Oriented Programming

🎯 [OOP](https://www.youtube.com/watch?v=ckdDIhQyK_A)

# Prototype

🎯 [Prototype - the foundation of JavaScript](https://www.youtube.com/watch?v=Z45VQuHO_VA&t=87s) - Learn with Sumit Bangladesh

🎯 [Object Prototypes](https://www.w3schools.com/js/js_object_prototypes.asp) - W3Schools

# Interview Preparation

⭐ [JavaScript Interview Questions 436+](https://github.com/sudheerj/javascript-interview-questions) - Github

⭐ [JavaScript Interview Questions 70+](https://www.javatpoint.com/javascript-interview-questions) - Javapoint

⭐ [Most Frequent JavaScript Interview Questions 64+](https://www.interviewbit.com/javascript-interview-questions/) - Interviewbit

⭐ [JavaScript Modern Interview Code Challenges](https://github.com/sadanandpai/javascript-code-challenges) - Github

⭐ [JavaScript Coding Challenges for Beginners (Codewares) 57+](https://github.com/rradfar/javascript-coding-challenges) - Github

⭐ [JavaScript Output Test](https://gist.github.com/nurmdrafi/1e686651fd34729eae8f5c7fb9c28869) - Github

⭐ [JavaScript MCQ Questions 155+](https://github.com/lydiahallie/javascript-questions) - Github

⭐ [JavaScript MCQ Questions 150+](https://www.javatpoint.com/javascript-interview-questions) - Javapoint

⭐ [React Interview Questions 80+](https://www.javatpoint.com/react-interview-questions) - Javapoint

⭐ [HR Interview Questions 50+](https://www.javatpoint.com/job-interview-questions) - Javapoint
