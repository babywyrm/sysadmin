//
//
package main

/*
$ cat helloworld.ts 
export function add(a: i32, b: i32): i32 {
    return a + b;
}
$ npm install -g assemblyscript
$ asc helloworld.ts -o hello-world.wasm
$ go run main.go
*/

import (
	"fmt"
	"io/ioutil"

	wasmer "github.com/wasmerio/wasmer-go/wasmer"
)

func main() {
  // use TEE attestation token here to download `hello-world.wasm`
	wasmBytes, err := ioutil.ReadFile("hello-world.wasm")
	if err != nil {
		panic(err)
	}
	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)

	// Compiles the module
	module, err := wasmer.NewModule(store, wasmBytes)
	if err != nil {
		panic(err)
	}
	// Instantiates the module
	importObject := wasmer.NewImportObject()
	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		panic(err)
	}
	// Gets the `add` exported function from the WebAssembly instance.
	add, err := instance.Exports.GetFunction("add")
	if err != nil {
		panic(err)
	}
	// Calls that exported function with Go standard values. The WebAssembly
	// types are inferred and values are casted automatically.
	result, err := add(1, 5)
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}

//
//

// Define a function that is imported into the module.
// By default, the "env" namespace is used.
extern "C" {
    fn print_str(ptr: *const u8, len: usize);
}

// Define a string that is accessible within the wasm
// linear memory.
static HELLO: &'static str = "Hello, World!";

// Export a function named "hello_wasm". This can be called
// from the embedder!
#[no_mangle]
pub extern fn hello_wasm() {
    // Call the function we just imported and pass in
    // the offset of our string and its length as parameters.
    unsafe {
      print_str(HELLO.as_ptr(), HELLO.len());
    }
}

//
//

// This is an example on how a cache system could work.
// It enforces a very useful pattern for caching:
// - serializing (cache.save)
// - deserializing (cache.load)

// This abstracts the responsibility on how to load or how to save
// outside, so it can be a FileSystem, a HashMap in memory, ...

// We get the hash from the binary
let hash: WasmHash = get_wasm_hash(&wasm_binary);

// We create a new cache instance.
// It could be possible to use any other kinds of caching, as long as they
// implement the Cache trait (with save and load functions)
let cache = FileSystemCache::new(WASMER_CACHE_DIR);

// cache.load will return the Module if it's able to deserialize it properly, and an error if:
// * The file is not found
// * The file exists, but it's corrupted or can't be converted to a module
let module = cache.load(hash).unwrap_or_else(|err| {
    let module = webassembly::compile(&wasm_binary[..])
        .map_err(|e| format!("Can't compile module: {:?}", e))?;

    // We save the module into a cache file
    cache.save(hash, module).unwrap();
    module
});

//
//

package main

import (
	"fmt"
	wasm "github.com/wasmerio/go-ext-wasm/wasmer"
)

func main() {
	// Reads the WebAssembly module as bytes.
	bytes, _ := wasm.ReadBytes("simple.wasm")
	
	// Instantiates the WebAssembly module.
	instance, _ := wasm.NewInstance(bytes)
	defer instance.Close()

	// Gets the `sum` exported function from the WebAssembly instance.
	sum := instance.Exports["sum"]

	// Calls that exported function with Go standard values. The WebAssembly
	// types are inferred and values are casted automatically.
	result, _ := sum(5, 37)

	fmt.Println(result) // 42!
}

//
//

```
# wapm 发布的 WASI 的模块

----

## 术语

- wapm 一个 WebAssembly 的包管理
- wasmer / wasmtime, 解释运行 WebAssembly 的命令
- [WASI](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-tutorial.md), WebAssembly System Interface
- Rust, WebAssembly...

----

## Rust 编译到 WASI

```bash
rustup target add wasm32-wasi
cargo build --target=wasm32-wasi --release
```

```
cp target/wasm32-unknown-wasi/release/wasi-example.wasm .
wasmer run wasi-example.wasm -- -e "HQ9+"
```

https://github.com/wapm-packages/rust-wasi-example

----

## 发布到 wapm

https://docs.wasmer.io/ecosystem/wapm/publishing-your-package

https://wapm.io/calcit

...以及一些模块的管理功能

----

### 项目结构

https://github.com/calcit-lang/wasi-calcit

----

Thx.
