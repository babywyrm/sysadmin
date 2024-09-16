##
#
https://raw.githubusercontent.com/collabnix/wasmlabs/main/docker/pushing-wasm-to-dockerhub.md
#
##



## How to Build Wasm Docker Image and Push it to Docker Hub

Getting Started:

1. Install Rust and 

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```
This will download and install the official compiler for the Rust
programming language, and its package manager, Cargo.

Rustup metadata and toolchains will be installed into the Rustup
home directory, located at:

  /Users/ajeetsraina/.rustup

This can be modified with the RUSTUP_HOME environment variable.

The Cargo home directory is located at:

  /Users/ajeetsraina/.cargo

This can be modified with the CARGO_HOME environment variable.

The cargo, rustc, rustup and other commands will be added to
Cargo's bin directory, located at:

  /Users/ajeetsraina/.cargo/bin

This path will then be added to your PATH environment variable by
modifying the profile files located at:

  /Users/ajeetsraina/.profile
  /Users/ajeetsraina/.zshenv

You can uninstall at any time with rustup self uninstall and
these changes will be reverted.

Current installation options:


   default host triple: aarch64-apple-darwin
     default toolchain: stable (default)
               profile: default
  modify PATH variable: yes

1) Proceed with installation (default)
2) Customize installation
3) Cancel installation
>
```

```
stable-aarch64-apple-darwin installed - rustc 1.69.0 (84c898d65 2023-04-16)


Rust is installed now. Great!

To get started you may need to restart your current shell.
This would reload your PATH environment variable to include
Cargo's bin directory ($HOME/.cargo/bin).

To configure your current shell, run:
source "$HOME/.cargo/env"
```


```
rustup target add wasm32-wasi
info: downloading component 'rust-std' for 'wasm32-wasi'
info: installing component 'rust-std' for 'wasm32-wasi'
 18.9 MiB /  18.9 MiB (100 %)  18.9 MiB/s in  1s ETA:  0s
```

This command will download and install the necessary components for the wasm32-wasi target.Wait for the installation to complete. rustup will fetch the required files and configure your Rust toolchain to support compiling to the wasm32-wasi target.

Once the installation is finished, you can use the wasm32-wasi target when building your Rust code for the WebAssembly System Interface (WASI) environment. This target is specifically designed for running WebAssembly modules outside of a web browser, providing a set of standard APIs for interacting with the host system.

For example, you can compile your Rust code to WebAssembly using the wasm32-wasi target with the following command:

```
cargo build --target wasm32-wasi
```

This command will compile your Rust code to a WebAssembly module (your_wasm_app.wasm) that can be executed in a WASI-compliant runtime environment.

Make sure you have Rust and rustup installed on your system before attempting to add the wasm32-wasi target. You can install Rust and rustup by following the official Rust installation instructions available at: https://www.rust-lang.org/tools/install

If you encounter any issues during the installation or have further questions, feel free to ask for assistance.


Building a simple Rust WebAssembly application using the wasm-bindgen crate and interact with it from JavaScript:


```
 cargo new wasm-example
     Created binary (application) `wasm-example` package
```

Open the Cargo.toml file in a text editor and add the following dependencies:

```
[dependencies]
wasm-bindgen = "0.2"
```


```
cargo install wasm-bindgen-cli
```

Create a new Rust source file, src/lib.rs, and replace its contents with the following code:

```
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
```

This code defines a function greet that takes a string argument and returns a formatted greeting message.

## Build the Rust code into a Wasm binary:

```
cargo build --target wasm32-unknown-unknown
```

This command compiles the Rust code to WebAssembly using the wasm32-unknown-unknown target.

## Generate the JavaScript bindings for the Wasm module:

```
wasm-bindgen target/wasm32-unknown-unknown/debug/wasm-example.wasm --out-dir .
```

The wasm-bindgen command generates JavaScript code that allows you to interact with the Wasm module from JavaScript.

## Create an HTML file, index.html, in the project directory, and add the following code:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Rust Wasm Example</title>
    <script src="wasm_example.js"></script>
</head>
<body>
    <script>
        const { greet } = wasm_bindgen;
        async function run() {
            await wasm_bindgen('./wasm_example_bg.wasm');
            const greeting = greet('WebAssembly');
            console.log(greeting);
        }
        run();
    </script>
</body>
</html>
```

This HTML file loads the generated JavaScript bindings and calls the greet function, passing the name "WebAssembly". The greeting is logged to the console.

Start a local web server in the project directory. For example, you can use the http-server package:

```
npx http-server .
```

This command starts a local web server serving the files in the current directory.

Open a web browser and navigate to http://localhost:8080 (or the appropriate URL provided by the web server).

Open the browser's developer console, and you should see the greeting message "Hello, WebAssembly!" logged.

This example demonstrates the basic steps to build a Rust WebAssembly application and interact with it from JavaScript. You can customize the code and explore more advanced features provided by wasm-bindgen to interact with JavaScript and the web browser's APIs from Rust.



Steps to Produce a WASM File for Docker Container
Create Your WebAssembly Module

Write the WASM Code: Start with writing your code in a language that compiles to WebAssembly. Common languages include Rust, C/C++, and AssemblyScript.

Compile to WASM: Use the appropriate toolchain to compile your code into a WASM file. For example, if you're using Rust, you would use wasm-pack or cargo build --target wasm32-unknown-unknown.

Here’s an example for Rust:

```
cargo build --release --target wasm32-unknown-unknown
```

This command will generate a .wasm file in the target/wasm32-unknown-unknown/release/ directory.

Prepare Your WASM File

Ensure Compatibility: Make sure your WASM file doesn’t have unexpected imports or dependencies that would prevent it from running in a standalone environment or within your Docker container.

Optional - Use wasm-bindgen: If you need to interface with JavaScript or provide more functionality, you might need to use wasm-bindgen to facilitate this. Install wasm-bindgen-cli and use it to generate the WASM bindings.

```
wasm-bindgen target/wasm32-unknown-unknown/release/your_module.wasm --out-dir ./pkg
```

This will create additional files that might be needed depending on your use case.

Create Dockerfile

Use a Dockerfile to set up an environment where the WASM module can be executed. Here’s a sample Dockerfile:

```
# Use a base image with Wasmer installed or install Wasmer yourself
FROM debian:bullseye-slim

# Install Wasmer dependencies
RUN apt-get update && apt-get install -y curl

# Download and install Wasmer
RUN curl https://get.wasmer.io -sSfL | sh

# Set Wasmer binary path
ENV PATH="/root/.wasmer/bin:$PATH"

# Create the application directory
WORKDIR /app

# Copy the WASM module into the container
COPY my_module.wasm /app/my_module.wasm

# Copy any other necessary files (e.g., a run script)
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# Define the entrypoint to run the WASM module
ENTRYPOINT ["/app/run.sh"]
```

Create a Run Script

Here’s an example run.sh script that you can use to execute your WASM module:

```
#!/bin/bash

# Run the WebAssembly module with Wasmer
wasmer run /app/my_module.wasm --verbose > /app/output.log 2>&1
```


Build and Push the Docker Image

Build the Docker Image:

```
docker build -t my-wasm-app .
```


Tag the Image:

```
docker tag my-wasm-app yourusername/my-wasm-app:latest
```


Push the Image to Docker Hub:

```
docker push yourusername/my-wasm-app:latest
```

Summary
Write and Compile Code: Write your code in a language like Rust, and compile it to WASM using appropriate tools.
Prepare WASM File: Ensure the WASM file is standalone and compatible.
Dockerfile: Create a Dockerfile to set up the environment, copy the WASM module, and define the entry point.
Run Script: Write a script to execute the WASM module using Wasmer.
Build and Push: Build the Docker image and push it to Docker Hub.


