//
//
// https://gist.github.com/syrusakbary/96676f608b514d3ae41d08b83d256c07
//
//

extern crate wasmer_clif_backend;
extern crate wasmer_runtime;

use std::{
    fs::File,
    io::prelude::*,
    str,
};

use wasmer_clif_backend::CraneliftCompiler;
use wasmer_runtime::{
    self as runtime,
    export::{Context, Export, FuncPointer},
    import::{Imports, NamespaceMap},
    structures::TypedIndex,
    types::{FuncSig, MemoryIndex, Type},
    vm,
};

fn main() {
    // Read the wasm file produced by our sample application...
    let mut wasm_file =
        File::open("../wasm-sample-app/target/wasm32-unknown-unknown/release/wasm_sample_app.wasm")
            .unwrap();
    // ... and put it into a vector.
    let mut wasm_bytes = Vec::new();
    wasm_file.read_to_end(&mut wasm_bytes).unwrap();
    
    // Instantiate the compiler we're going to use. The wasmer-runtime
    // is designed to support multiple compiler backends. Right now,
    // only the Cranelift compiler is supported, but we're working on
    // an LLVM backend as well!
    let compiler = CraneliftCompiler::new();
    
    // Compile our webassembly into a wasmer-runtime `Module`.
    let module = runtime::compile(&wasm_bytes, &compiler).unwrap();
    
    // Let's define that "env" namespace that was implicitly used
    // by our sample application.
    //
    // First, we have to create a `NamespaceMap` and insert our "print_str"
    // function into it. We define that function lower down on the page.
    let mut env_namespace = NamespaceMap::new();
    env_namespace.insert(
        // This is the name of the function we want to expose.
        "print_str",
        // The `Export` enum lets us add functions, memories, tables,
        // and globals to a namespace. We're working on a procedural-macro
        // that will automatically create this structure automagically, so you
        // don't have to write all this gobbledygook.
        Export::Function {
            // We force the user to make a `FuncPointer` here because
            // the runtime has no way of knowing if the function pointer
            // you pass in is valid (print_str in this case) or
            // if you specify the correct function signature.
            func: unsafe { FuncPointer::new(print_str as _) },
            // `Context::Internal` tells the runtime that we want to use
            // the context that is internally used by the webassembly module
            // we're about to run.
            ctx: Context::Internal,
            // This tells the runtime what the signature (the parameter
            // and return types) of the function we're defining here is.
            // Make sure to check this carefully!
            signature: FuncSig {
                // `Type::I32` just means that this function receives
                // the webassembly "i32" type.
                params: vec![Type::I32, Type::I32],
                // Our function doesn't return anything, so this is empty.
                // Eventually, webassembly will support multiple return values,
                // but currently, this only allows zero or one return types.
                returns: vec![],
            },
        },
    );
    
    // This lets us register our namespace and import it into this module
    // as we instantiate it.
    let mut imports = Imports::new();
    
    // Register our namespace with the name: "env".
    //
    // imports.register(...) is designed to take any type
    // that implements the `Namespace` trait. This even lets us
    // register an already existing wasmer `Instance`
    // as an imported namespace.
    imports.register("env", env_namespace);

    // Here we go!
    //
    // Instantiate the module with the imports we just created
    // to create, you guessed it, an `Instance`.
    //
    // You can create any number of instances with a single module.
    let mut instance = module.instantiate(imports).unwrap();

    // At last, we can call the function exported by our webassembly
    // sample application.
    //
    // Since our exported function doesn't receive any parameters,
    // we just pass it an empty slice as the parameter list.
    instance.call("hello_wasm", &[]).unwrap();
}

// Let's define our "print_str" function.
//
// The declaration must start with "extern" or "extern "C"".
extern fn print_str(ptr: u32, len: u32, vmctx: *mut vm::Ctx) {
    // Webassembly only supports a single memory for now,
    // but in the near future, it'll support multiple.
    //
    // Therefore, we don't assume you always just want to access first
    // memory and force you to specify.
    let memory_index = MemoryIndex::new(0);
    
    // Get a slice that maps to the memory currently used by the webassembly
    // instance.
    let memory = unsafe { (*vmctx).memory(memory_index) };
    
    // Get a subslice that corresponds to the memory used by the string.
    let str_slice = &memory[ptr as usize .. (ptr + len) as usize];
    
    // Convert the subslice to a `&str`.
    let str = str::from_utf8(str_slice).unwrap();

    // Print it!
    println!("{}", str);
}
