Rust WASM Application


First, set up the Rust application to use quickjs for JavaScript execution.

Install Rust and wasm-pack:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo install wasm-pack
Create a new Rust project:

cargo new wasm_app
cd wasm_app
```

Add WASM target:

```
rustup target add wasm32-unknown-unknown
Update Cargo.toml to include dependencies:

[dependencies]
wasm-bindgen = "0.2"
quick_js = "0.3.3"

[lib]
crate-type = ["cdylib"]
Update src/lib.rs:


use wasm_bindgen::prelude::*;
use quick_js::Context;

#[wasm_bindgen]
pub fn run_js_code(js_code: &str) -> String {
    let context = Context::new().unwrap();
    match context.eval(js_code) {
        Ok(result) => result.as_str().unwrap_or("undefined").to_string(),
        Err(err) => format!("Error: {}", err),
    }
}
```
Build the WASM module:

```
wasm-pack build --target web

```
###
###
```
echo 'console.log("Hello, WASM!");' > custom.js
docker run --rm -v $(pwd)/custom.js:/secure_js/custom.js:ro wasm-app




docker run --rm -v $(pwd)/custom.js:/secure_js/custom.js:ro wasm-app


use wasm_bindgen::prelude::*;
use quick_js::Context;

#[wasm_bindgen]
pub fn run_array_operations(js_code: &str) -> String {
    let context = Context::new().unwrap();
    match context.eval(js_code) {
        Ok(result) => result.as_str().unwrap_or("undefined").to_string(),
        Err(err) => format!("Error: {}", err),
    }
}
JavaScript Example:

js
Copy code
(function() {
    let numbers = [1, 2, 3, 4, 5];
    let squared = numbers.map(n => n * n);
    let sum = squared.reduce((a, b) => a + b, 0);
    return sum.toString();
})();

```
###
###


```
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache wasmtime

# Create a non-root user for running the application
RUN addgroup -S wasmgroup && adduser -S wasmuser -G wasmgroup

# Set working directory
WORKDIR /app

# Copy the WASM module into the container
COPY ./pkg /app/pkg

# Set permissions
RUN chown -R wasmuser:wasmgroup /app

# Switch to the non-root user
USER wasmuser

# Secure volume mount point
VOLUME /secure_js

# Run the application with seccomp profile for additional security
COPY ./seccomp.json /app/seccomp.json

# Entrypoint to run the WASM module
ENTRYPOINT ["sh", "-c", "wasmtime --seccomp /app/seccomp.json /app/pkg/wasm_app_bg.wasm --invoke run_js_code \"$(cat /secure_js/custom.js)\""]

```
