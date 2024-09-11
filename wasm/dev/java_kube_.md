##
#
https://gist.github.com/arun-gupta/60183c80262fb4e98c0be494ce3a70b7
#
##

## Java and Web Assembly Web Application

- This sample will use [TeaVM transpiler](https://teavm.org/) to convert Java code into WebAssembly. Create a new TeaVM project using Maven:
  ```
  mvn -DarchetypeCatalog=local \
  -DarchetypeGroupId=org.teavm \
  -DarchetypeArtifactId=teavm-maven-webapp \
  -DarchetypeVersion=0.8.1 archetype:generate
  ```
- Package the `.war` file:
  ```
  cd teavm-maven-webapp
  mvn clean package
  ```
- Install Apache Tomcat:
  ```
  brew install tomcat
  ```
- Start Tomcat:
  ```
  brew services start tomcat
  ```
- Deploy the web app:
  ```
  cp target/teavm-maven-webapp-1.0-SNAPSHOT.war /opt/homebrew/opt/tomcat/libexec/webapps
  ```
- Access the application at http://localhost:8080/teavm-maven-webapp-1.0-SNAPSHOT/

## Rust and Web Assembly Container

- Install Docker Desktop from https://docs.docker.com/desktop/install/mac-install/
- Enable containerd feature as explained at https://docs.docker.com/desktop/containerd/
- Install `rustup` and the latest version of Rust
- Create Rust microservice
  ```
  mkdir hello_world 
  cd hello_world 
  vi main.rs
  ```
  Add the following code:
  ```
  fn main() {
    println!("Hello, world!");
  }
  ```
- Compile and run the code
  ```
  rustc main.rs 
  ./main
  ```
- Install `wasm-pack`
  ```
  cargo install wasm-pack
  ```
- Build the wasm package
  ```
  wasm-pack build --target web
  ```
- Update Rust code in `hello-wasm/src/lib.rs` to this
  ```
  use wasm_bindgen::prelude::*;

  #[wasm_bindgen]
  extern {
      pub fn alert(s: &str);
  }

  #[wasm_bindgen]
  pub fn greet(name: &str) {
      alert(&format!("Hello, {}!", name));
  }
  ```
- Update hello-wasm/Cargo.toml to this:
  ```
  [package]
  name = "hello-wasm"
  version = "0.1.0"
  authors = ["Your Name <you@example.com>"]
  description = "A sample project with wasm-pack"
  license = "MIT/Apache-2.0"
  repository = "https://github.com/yourgithubusername/hello-wasm"
  edition = "2018"

  [lib]
  crate-type = ["cdylib"]

  [dependencies]
  wasm-bindgen = "0.2"
  ```
- 


## Kubernetes backend

## Serverless app using Spin

- [Spin](https://www.fermyon.com/spin)

  
