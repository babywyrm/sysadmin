
++++++++++++++++++++++++++++++++++++++++++++

https://0xdf.gitlab.io/2021/07/03/htb-ophiuchi.html

++++++++++++++++++++++++++++++++++++++++++++

wasm-functions
The index.go program reads in main.wasm and uses it to create a new wasm instance:

admin@ophiuchi:/opt/wasm-functions$ cat index.go 

++++++++++++++++++++++++++++++++++++++++++++

package main

import (
        "fmt"
        wasm "github.com/wasmerio/wasmer-go/wasmer"
        "os/exec"
        "log"
)


func main() {
        bytes, _ := wasm.ReadBytes("main.wasm")

        instance, _ := wasm.NewInstance(bytes)
        defer instance.Close()
        init := instance.Exports["info"]
        result,_ := init()
        f := result.String()
        if (f != "1") {
                fmt.Println("Not ready to deploy")
        } else {
                fmt.Println("Ready to deploy")
                out, err := exec.Command("/bin/sh", "deploy.sh").Output()
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println(string(out))
        }
}

++++++++++++++++++++++++++++++++++++++++++++

Then it runs a function, info from that instance and checks the result. If the return is not 1, then it prints “Not ready to deploy”. Otherwise, it prints “Ready to deploy” and runs deploy.sh, which is empty at this point:

#!/bin/bash

# ToDo
# Create script to automatic deploy our new web at tomcat port 8080
If I try to run this from /home/admin, it returns a bunch of errors:

admin@ophiuchi:~$ sudo /usr/bin/go run /opt/wasm-functions/index.go
panic: runtime error: index out of range [0] with length 0

goroutine 1 [running]:
github.com/wasmerio/wasmer-go/wasmer.NewInstanceWithImports.func1(0x0, 0x0, 0xc000040c90, 0x5d1200, 0x200000003)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:94 +0x201
github.com/wasmerio/wasmer-go/wasmer.newInstanceWithImports(0xc000086020, 0xc000040d48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc000040d70)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:137 +0x1d3
github.com/wasmerio/wasmer-go/wasmer.NewInstanceWithImports(0x0, 0x0, 0x0, 0xc000086020, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4e6180, ...)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:87 +0xa6
github.com/wasmerio/wasmer-go/wasmer.NewInstance(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4e6180, 0x1)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:82 +0xc9
main.main()
        /opt/wasm-functions/index.go:14 +0x6d
exit status 2
These error messages are not great, but it’s because it’s trying to read main.wasm from the current directory, and failing because it’s not there. If I go into the directory where the files are, it runs fine:

admin@ophiuchi:/opt/wasm-functions$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Not ready to deploy
Reverse main.wasm
Based on the output above, main.wasm is clearly returning a non-1 value, so it’s time to look at that.

WASM, or Web Assembly, is a binary instruction format for a stack-based virtual machine designed to run cross-platform. The main purpose for WASM is to have fast and high performance applications on webpages, but it can run in other environments as well.

I’ll copy main.wasm back to my VM using scp:

oxdf@parrot$ sshpass -p whythereisalimit scp admin@10.10.10.227:/opt/wasm-functions/main.wasm .
oxdf@parrot$ file main.wasm 
main.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
Googling for WASM disassembler, the first result is The WebAssembly Binary Toolkit, or WABT. I’ll build the tools by cloning the repo to my machine, and then running the make script:

oxdf@parrot$ git clone --recursive https://github.com/WebAssembly/wabt
Cloning into 'wabt'...
...[snip]...
oxdf@parrot$ cd wabt/
oxdf@parrot$ make
mkdir -p out/clang/Debug/
...[snip]...
This will require cmake (apt install cmake) to run. Now I have different binaries to read the WebAssembly. wasm2wat will convert main.wasm into WebAssembly text format (from the binary format):

oxdf@parrot$ /opt/wabt/bin/wasm2wat main.wasm
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))  
That wasn’t totally clear to me. wasm-decompile was much cleaner:

oxdf@parrot$ /opt/wabt/bin/wasm-decompile main.wasm                                                                                        
export memory memory(initial: 16, max: 0);

global g_a:int = 1048576;
export global data_end:int = 1048576;
export global heap_base:int = 1048576;

table T_a:funcref(min: 1, max: 1);

export function info():int {
  return 0
}
The function info returns 0.

Exploit
Strategy
Because the Go program isn’t using absolute paths, I can control both main.wasm and deploy.sh. I’ll write a main.wasm that returns 1, and a deploy.sh that gives a shell.

wasm
I recently looked at WASM for RopeTwo, where my V8 payload used WASM to create a binary space in memory that was executable. 
That payload was just a silly function that returned 42, and then I overwrite that memory with my shellcode and call it. 
That didn’t require much WASM knowledge or even understanding, but I did learn about WasmFidle. 
It allows me to put in some simple C code and generate Wasm.

image-20210207134325508Click for full size image

In fact, the default code (which just returns 42) will solve my issue here. I’ll hit the “Build” button to generate the Wasm (shown on the bottom left). Now I can run it and it will print 42 (bottom right).

I’ll change the name of the function from main to info, change 42 to 1, and then Build again. If I want to run it, I need to change the call in the JS on the top right, but I don’t need to run it. There are two download buttons. “Wat” is the text version, and “Wasm” is the binary. I’ll take the binary.



++++++++++++++++++++++++++++++++++++++++++++
++
