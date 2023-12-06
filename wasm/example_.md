
##
https://gist.github.com/kripken/59c67556dc03bb6d57052fedef1e61ab
##

Standalone WebAssembly Example
Build hello_world.c using

emcc hello_world.c -Os -s WASM=1 -s SIDE_MODULE=1 -o hello_world.wasm
(make sure to use latest Emscripten incoming). That creates a WebAssembly dynamic libraryhello_world.wasm. You can then run hello_world.html in your browser, which loads and uses it.

More details: https://github.com/kripken/emscripten/wiki/WebAssembly-Standalone

hello_world.c
int doubler(int x) {
  return 2 * x;
}
hello_world.html
<html>
<head>
  <script>
    // Check for wasm support.
    if (!('WebAssembly' in window)) {
      alert('you need a browser with wasm support enabled :(');
    }

    // Loads a WebAssembly dynamic library, returns a promise.
    // imports is an optional imports object
    function loadWebAssembly(filename, imports) {
      // Fetch the file and compile it
      return fetch(filename)
        .then(response => response.arrayBuffer())
        .then(buffer => WebAssembly.compile(buffer))
        .then(module => {
          // Create the imports for the module, including the
          // standard dynamic library imports
          imports = imports || {};
          imports.env = imports.env || {};
          imports.env.memoryBase = imports.env.memoryBase || 0;
          imports.env.tableBase = imports.env.tableBase || 0;
          if (!imports.env.memory) {
            imports.env.memory = new WebAssembly.Memory({ initial: 256 });
          }
          if (!imports.env.table) {
            imports.env.table = new WebAssembly.Table({ initial: 0, element: 'anyfunc' });
          }
          // Create the instance.
          return new WebAssembly.Instance(module, imports);
        });
    }

    // Main part of this example, loads the module and uses it.
    loadWebAssembly('hello_world.wasm')
      .then(instance => {
        var exports = instance.exports; // the exports of that instance
        var doubler = exports._doubler; // the "doubler" function (note "_" prefix)
        // now we are ready, set up the button so the user can run the code
        var button = document.getElementById('run');
        button.value = 'Call a method in the WebAssembly module';
        button.addEventListener('click', function() {
          var input = 21;
          alert(input + ' doubled is ' + doubler(input));
        }, false);
      }
    );
  </script>
</head>
<body>
  <input type="button" id="run" value="(waiting for WebAssembly)"/>
</body>
</html>
@EthanBogart
EthanBogart commented on Aug 13, 2017
This is great! Do you have an example that uses WebAssembly.instantiate? I see it compiles as well, but I can't seem to get it to work.

@agnivade
agnivade commented on May 15, 2018 • 
Hi, this is the error I get now - WebAssembly Instantiation: Import #5 module="global" error: module is not an object or function.

EDIT: Sorry, I see now that -Os flag is required.

@nikkolasg
nikkolasg commented on May 31, 2018 • 
I tried it and it failed on my machine (on arch so using latest prod Firefox).
I had to change the import object to:

var importObject = {
            env: {
            'memoryBase': 0,
            'tableBase': 0,
            'memory': new WebAssembly.Memory({initial: 256}),
            'table': new WebAssembly.Table({initial: 256, element: 'anyfunc'}),
            abort: alert,
            }
       }
Note that the abort function can be anything, but it's just conveninent to just alert for me.

@marcmoo
marcmoo commented on Sep 12, 2018
I tried it and it failed on my machine (on arch so using latest prod Firefox).
I had to change the import object to:

var importObject = {
            env: {
            'memoryBase': 0,
            'tableBase': 0,
            'memory': new WebAssembly.Memory({initial: 256}),
            'table': new WebAssembly.Table({initial: 256, element: 'anyfunc'}),
            abort: alert,
            }
       }
Note that the abort function can be anything, but it's just conveninent to just alert for me.

edit your abort as following
abort:function(){}

@dotaheor
dotaheor commented on Nov 22, 2018 • 
It doesn't work:

In chrome:

(index):29 Uncaught (in promise) LinkError: WebAssembly Instantiation: 
Import #0 module="env" function="__memory_base" error: global import must be a number or WebAssembly.Global object
In firefox:

LinkError: import object field '__memory_base' is not a Number
Same results with @nikkolasg 's modification.

@william8000
william8000 commented on Dec 7, 2018
@dotaheor
Try changing tableBase to __table_base and memoryBase to __memory_base in the env part of the import object.
emscripten-core/emscripten#7467

@yard
yard commented on Dec 8, 2018
Looks like the most recent version of emcc also requires -s EXPORTED_FUNCTIONS='["_doubler"]' argument to mark the function as exported (otherwise it would be killed by dce)

@JerrySievert
JerrySievert commented on Jan 31, 2019 • 
I'm trying to do the same thing, but with node, and am running into an issue:

const {readFileSync} = require('fs');

let buffer = readFileSync('hello_world.wasm');

async function createWebAssembly (importObject) {
  let compiled = await WebAssembly.compile(buffer);
  return new WebAssembly.Instance(compiled, importObject);
}

const memory = new WebAssembly.Memory({ initial: 256, maximum: 256 });

async function init ( ) {
  const env = {
    'abortStackOverflow': _ => { throw new Error('overflow'); },
    'table': new WebAssembly.Table({ initial: 0, maximum: 0, element: 'anyfunc' }),
    '__table_base': 0,
    'memory': memory,
    '__memory_base': 1024,
    'STACKTOP': 0,
    'STACK_MAX': memory.buffer.byteLength,
  };

  const importObject = {env};

  const wa = await createWebAssembly(importObject);

  console.log(JSON.stringify(wa));
}

init();
no errors, but the output is {"exports":{}}, which doesn't seem to include the export of _doubler. compilation seems fine, as it works in the web version:

$ emcc hello_world.c -Os -s WASM=1 -s SIDE_MODULE=1 -s EXPORTED_FUNCTIONS='["_doubler"]' -o hello_world.wasm
any help would be greatly appreciated. this is a step toward easy use in plv8.

thanks!

@st-patrick
st-patrick commented on Feb 10, 2019
I had the same problem as @dotaheor and the solution suggested by @william8000 worked for me! (Chrome as well as Firefox)

@gutenye
gutenye commented on Mar 18, 2019
Confirmed, needs extra flag by @yard

@sudheer5
sudheer5 commented on Apr 25, 2019 • 
Hi,
I tried to get the debugging of c file in the browser using the following code.

'C' code:
int doubler(int x) {
return 2 * x;
}

compilation code:
emcc hello_world.c -g4 -s WASM=1 -s SIDE_MODULE=1 -s "EXPORTED_FUNCTIONS=['_doubler']" -o hello_world.wasm -g --source-map-base http://localhost:6931/

error:
Unknown option '--all-features'
shared:ERROR: 'D:/GitHub/emsdk/clang/e1.38.30_64bit/binaryen\bin\wasm-as hello_world.wast -o hello_world.wasm --all-features --disable-bulk-memory -g --source-map=hello_world.wasm.map --source-map-url=http://localhost:6931/hello_world.wasm.map' failed (1)

any help would be appreciated.
thanks

@wuxulome
wuxulome commented on Aug 15, 2019
My output is {"exports":{}} too, but if add code: console.log(wa.exports._doubler(xx));, I can also get the right results in console.

@jalamari2018
jalamari2018 commented on Sep 19, 2019 • 
I tried all proposed solutions but none of them works for me.
I don't have any issue when I write .wat files and use wat2wasm tool to generate .wasm files.
the problem happens only when I use emscripten to generate WebAssembly code.

@kripken
Author
kripken commented on Sep 19, 2019
Emscripten is adding proper support for emitting standalone wasm now, see emscripten-core/emscripten#9461

@kripken
Author
kripken commented on Nov 22, 2019
More details on emscripten's standalone wasm support: https://v8.dev/blog/emscripten-standalone-wasm

@iiic
iiic commented on Feb 27, 2020
Why it's there a _ preffix ? It's breaking function for me, it works well after I remove it. Was it something in the past versions ? ( used emcc 1.39.8 ; clang version 11.0.0 )

@kripken
Author
kripken commented on Feb 27, 2020
@iiic The old fastcomp backend added _ prefixes on the wasm exports. The new upstream backend (like in the version you use) doesn't, which can be noticeable if you access the exports directly.

@cloudwheels
cloudwheels commented on Aug 31, 2020
I confirm I got this working by removing the "_" prefix to the function name in the html file line 38, and EXPORTED_FUNCTIONS flag for the compiler, i.e.
var doubler = exports.doubler;
emcc hello_world.c -Os -s WASM=1 -s SIDE_MODULE=1 -s EXPORTED_FUNCTIONS='["doubler"]' -o hello_world.wasm

@mahaidong
mahaidong commented on Jan 5, 2021
I confirm I got this working by removing the "_" prefix to the function name in the html file line 38, and EXPORTED_FUNCTIONS flag for the compiler, i.e.
var doubler = exports.doubler;
emcc hello_world.c -Os -s WASM=1 -s SIDE_MODULE=1 -s EXPORTED_FUNCTIONS='["doubler"]' -o hello_world.wasm

cool

@frank-pian
frank-pian commented on Apr 20 • 
I am using emcc 3.1.35. It's changed again. Do not remove the "_" in front of EXPORTED_FUNCTIONS
var doubler = exports.doubler;
emcc hello_world.c -Os -s WASM=1 -s SIDE_MODULE=1 -s EXPORTED_FUNCTIONS='["_doubler"]' -o hello_world.wasm
