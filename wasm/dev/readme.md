WebAssembly: Docker without containers!
Asen Alexandrov

##
#
https://wasmlabs.dev/articles/docker-without-containers/
#
https://github.com/WordPress/wordpress-playground
#
https://github.com/WordPress/wporg-wasm
#
##
  
This is a companion article to a talk about Docker+WebAssembly that we gave at "Docker Community All Hands 7, Winter Edition" on Dec 15th, 2022.

Introduction
Recently Docker announced support for WebAssembly in cooperation with WasmEdge.

This article will explain what is WebAssembly, why it is relevant to the Docker ecosystem and provide some hands-on examples to try on. We assume you are familiar with the Docker tooling. We will be using our work on the WebAssembly port of PHP to demonstrate how to build a PHP interpreter, package it as part of an OCI image and run it using Docker.

Note that this article focuses on getting some hands-on experience rather than discussing technical details. You can either reproduce the examples below or just read through them till the end as we will also provide the output.

WebAssembly - What? and Why?
This is a very basic introduction. If you are already familiar with the technology you can skip to the next section.

What is WebAssembly?
WebAssembly (or Wasm) is an open standard that defines a binary instruction format, which allows the creation of portable binary executables from different source languages.

Wasm is in all browsers
These binaries can run in a variety of environments. It has its origins in the web and is supported by all major browsers.

How does Wasm work in browsers?
Browser engines integrate a Wasm virtual machine, usually called a Wasm runtime, which can run the Wasm binary instructions. There are compiler toolchains (like Emscripten) that can compile source code to the Wasm target. This allows for legacy applications to be ported to a browser and directly communicate with the JS code that runs in client-side Web applications.

Wasm in a browser
These technologies have allowed traditional desktop apps to run in a browser. And now they can run on any device on which you have a browser. Some notable examples are Google Earth and the Open CV library for computer vision.

How does Wasm work on servers?
There are Wasm runtimes that can run outside of the browser, including traditional operating systems such as Linux, Windows and macOS. Because they cannot rely on a JavaScript engine being available they communicate with the outside world using different interfaces, such as WASI, the WebAssembly System Interface. These runtimes allow Wasm applications to interact with their host system in a similar (but not quite the same) way as POSIX. Projects like WASI SDK and wasi-libc help people compile existing POSIX-compliant applications to WebAssembly.

Wasm on the server
You only need to compile an application into a Wasm module once, and then you can run the exact same binary everywhere.

What's great about Wasm?
Some of the features that make Wasm great in browsers also make it attractive for server-side development:

🌐 Open - it is a standard widely adopted in the industry. In contrast to the browser wars of the past, major companies are collaborating for the standardization of WASI and WebAssembly applications.

🚀 Fast - it can offer native-like speed via the JIT/AOT capabilities of most runtimes. No cold starts, unlike booting a VM or starting a container.

🔒 Secure - the Wasm runtime is sandboxed by default and allows for safe access to memory. The capabilities-based model ensures that a Wasm application can access only what it is explicitly allowed to. There is better supply chain security.

💼 Portable - across the several major runtimes there is support for most CPUs (x86, ARM, RISC-V) and most OS-es including Linux, Windows, macOS, Android, ESXi, and even non-Posix ones.

🔋 Efficient - Wasm applications can be made to run with minimal memory footprint and CPU requirements.

🗣️ Polyglot - 40+ languages can be compiled to Wasm, with modern, constantly improving toolchains.

The next step in server platform evolution?
You may have seen this quote from Solomon Hykes (one of the co-founders of Docker):

If WASM+WASI existed in 2008, we wouldn't have needed to create Docker. That's how important it is. WebAssembly on the server is the future of computing.

Indeed, WASM+WASI does seem to be the next step in the evolution of server-side software infrastructure.

Back in the day, we had physical hardware to work on. We would meticulously install OS-es and applications on each box and maintain them all one by one.
Then with the adoption of VMs, pioneered by VMware, things became easier. People could copy, clone and move VMs across hardware boxes. But that still kept the need to install OS-es and applications in VMs.
Then came containers, popularized by Docker, which made it easier to run application configurations in a minimalistic wrapping context, without affecting any other applications on the host OS. However, that still kept the need to distribute applications bundled with their runtimes and necessary libraries. The security boundary was provided by the Linux kernel
We now have WebAssembly. Its technical features and portability make it possible to distribute the application, without requiring shipping OS-level dependencies and can run with strict security constraints.
Given all this, it is common for developers to take a look at WebAssembly as the 'successor' to containers and the next logical step in infrastructure deployment.

Wasm is the next step in the server platform evolution
However, another way of looking at WebAssembly is as an alternative 'backend' for Docker tooling. You can use the same command line tools and workflows, but instead of using Linux containers, it is implemented using WebAssembly-based container equivalents. The rest of the article explores this concept and this is what we referred to with the "Docker without containers" title.

How does Wasm work with Docker?
Docker Desktop now includes support for WebAssembly. It is implemented with a containerd shim that can run Wasm applications using a Wasm runtime called WasmEdge. This means that instead of the typical Windows or Linux containers which would run a separate process from a binary in the container image, you can now run a Wasm application in the WasmEdge runtime, mimicking a container.

As a result, the container image does not need to contain OS or runtime context for the running application - a single Wasm binary suffices.

This is explained in detail in Docker's Wasm technical preview article.

What is WasmEdge?
WasmEdge is a High-Performance WebAssembly Runtime that:

Is Open Source, part of the CNCF.
Supports all major CPU architectures (x86, ARM, RISC-V).
Supports all major Operating Systems (Linux, Windows, macOS) as well as others such as seL4 RTOS, Android.
Is Optimized for cloud-native and Edge applications.
Is Extensible and supports standards and emerging technologies
AI Inference with Tensorflow, OpenVINO, PyTorch
Async networking with Tokio. Supports microservices, database clients, message queues, etc.
Integrates seamlessly with containers ecosystem, Docker and Kubernetes (as shown in this article!)
What about interpreted languages?
So far we have only mentioned compiled languages such as C and Rust can target WebAssembly. For interpreted languages such as Python, Ruby and PHP, the approach is different: their interpreters are written in C and can be compiled to WebAssembly. Then this interpreted compiled to Wasm can be used to execute the source code files, typically ending in .py, .rb, .php and so on. Once compiled to Wasm, any platform with a Wasm runtime will be able to run those interpreted languages even if the actual interpreter was never compiled for that platform natively.

Wasm on the server for interpreted languages
The hands-on examples
Let's get started! In the hands-on examples, we will use the PHP interpreter compiled to Wasm. We will:

Build a Wasm container.
Compare Wasm and native binaries.
Compare traditional and Wasm containers.
Showcase Wasm's portability
Prerequisites
If you want to reproduce the examples locally you will need to prepare your environment with some or all of the following:

WASI SDK - to build WebAssembly applications from legacy C code
PHP - to run a native PHP binary for the sake of comparison
WasmEdge runtime - to run WebAssembly applications
Docker Desktop + Wasm (at the time of this writing, available as stable beta in version 4.15) to be able to run Wasm containers
We are also leveraging the "Wasm Language Runtimes" repository, which provides ways to build the PHP interpreter as a WebAssembly application.

You can start by checking out the demo branch like this:
```
git clone --depth=1 -b php-wasmedge-demo \
   https://github.com/vmware-labs/webassembly-language-runtimes.git wlr-demo
cd wlr-demo
Building a Wasm container
As a first example, we will showcase how to build a C-based application like the PHP interpreter.

The build uses WASI-SDK set of tools. It includes a clang compiler that can build to the wasm32-wasi target as well as wasi-libc which implements the basic POSIX system call interfaces on top of WASI. With WASI SDK we can build a Wasm module out of PHP's codebase, written in C. After that, it takes a very simple Dockerfile based on scratch for us to make an OCI image that can be run with Docker+Wasm.

From C code to Wasm container
Building a WASM binary
Assuming you are in the wlr-demo folder which you checked out as part of the prerequisites section you could run the following to build a Wasm binary.

export WASI_SDK_ROOT=/opt/wasi-sdk/
export WASMLABS_RUNTIME=wasmedge

./wl-make.sh php/php-7.4.32/ && tree build-output/php/php-7.4.32/bin/

... ( a few minutes and hundreds of build log lines)

build-output/php/php-7.4.32/bin/
├── php-cgi-wasmedge
└── php-wasmedge
PHP is built with autoconf and make. So if you take a look at the scripts/wl-build.sh script you will notice that we set up all relevant variables like CC, LD, CXX, etc. to use the compiler from WASI_SDK.
```
```
export WASI_SYSROOT="${WASI_SDK_ROOT}/share/wasi-sysroot"
export CC=${WASI_SDK_ROOT}/bin/clang
export LD=${WASI_SDK_ROOT}/bin/wasm-ld
export CXX=${WASI_SDK_ROOT}/bin/clang++
export NM=${WASI_SDK_ROOT}/bin/llvm-nm
export AR=${WASI_SDK_ROOT}/bin/llvm-ar
export RANLIB=${WASI_SDK_ROOT}/bin/llvm-ranlib
Then, digging further into php/php-7.4.32/wl-build.sh you can see that we use the autoconf build process as usual.

./configure --host=wasm32-wasi host_alias=wasm32-musl-wasi \
   --target=wasm32-wasi target_alias=wasm32-musl-wasi \
   ${PHP_CONFIGURE} || exit 1
...
make -j ${MAKE_TARGETS} || exit 1
```

WASI is a work in progress and many of the POSIX calls still can not be implemented on top of it. 
So to build PHP we had to apply several patches on top of the original codebase.

We saw above that the output binaries go to build-output/php/php-7.4.32. In the following examples we will use the php-wasmedge binary that is specifically built for WasmEdge as it offers server-side socket support, which is not yet part of WASI.

Optimizing the binary
Wasm is a virtual instruction set so the default behavior of any runtime would be to interpret those instructions on the fly. Of course, this could make things slow in some cases. So to get the best of both worlds with WasmEdge you can create an AOT (ahead-of-time) optimized binary that runs natively on the current machine but can still be interpreted on other ones.

To create that optimized binary run the following:
```
wasmedgec --enable-all --optimize 3 \
   build-output/php/php-7.4.32/bin/php-wasmedge \
   build-output/php/php-7.4.32/bin/php-wasmedge-aot
```

We will use this build-output/php/php-7.4.32/bin/php-wasmedge-aot binary in the following examples. To get to know more about the WasmEdge AOT optimized binaries take a look here.

Building the OCI image
Now that we have a binary, we can wrap it up in an OCI image.

Let's take a look at images/php/Dockerfile.cli. All we need to do is just copy the Wasm binary and set it as ENTRYPOINT.
```
FROM scratch
ARG PHP_TAG=php-7.4.32
ARG PHP_BINARY=php
COPY build-output/php/${PHP_TAG}/bin/${PHP_BINARY} /php.wasm

ENTRYPOINT [ "/php.wasm" ]
We could also add more content to the image, which will be accessible to the Wasm binary when it is run by Docker. For example in images/php/Dockerfile.server we also add some docroot content to be served by php.wasm when the container starts.

FROM scratch
ARG PHP_TAG=php-7.4.32
ARG PHP_BINARY=php
COPY build-output/php/${PHP_TAG}/bin/${PHP_BINARY} /php.wasm
COPY images/php/docroot /docroot

ENTRYPOINT [ "/php.wasm" , "-S", "0.0.0.0:8080", "-t", "/docroot"]
Based on the above files we can easily build our php-wasm images locally.

docker build --build-arg PHP_BINARY=php-wasmedge-aot -t ghcr.io/vmware-labs/php-wasm:7.4.32-cli-aot -f images/php/Dockerfile.cli .
docker build --build-arg PHP_BINARY=php-wasmedge-aot -t ghcr.io/vmware-labs/php-wasm:7.4.32-server-aot -f images/php/Dockerfile.server .
```


Native vs Wasm
Now let's compare a native PHP binary with a Wasm binary. Both locally and in a Docker container. We will use the same index.php file and compare the results we get when running it with:

php,
php-wasmedge-aot,
php in a traditional container,
php-wasmedge-aot in a Wasm container.
Running index.php
We will use the same images/php/docroot/index.php file in all of the below examples so let's take a look. In a nutshell, this script will:

use phpversion and php_uname to show the interpreter version and the platform on which it is running
print the names of all environment variables that the script can access
print a hello message with the current time and date
list the contents of the root folder /
```
<html>
<body>
<h1>Hello from PHP <?php echo phpversion() ?> running on "<?php echo php_uname()?>"</h1>

<h2>List env variable names</h2>
<?php
$php_env_vars_count = count(getenv());
echo "Running with $php_env_vars_count environment variables:\n";
foreach (getenv() as $key => $value) {
    echo  $key . " ";
}
echo "\n";
?>

<h2>Hello</h2>
<?php
$date = getdate();

$message = "Today, " . $date['weekday'] . ", " . $date['year'] . "-" . $date['mon'] . "-" . $date['mday'];
$message .= ", at " . $date['hours'] . ":" . $date['minutes'] . ":" . $date['seconds'];
$message .= " we greet you with this message!\n";
echo $message;
?>

<h2>Contents of '/'</h2>
<?php
foreach (array_diff(scandir('/'), array('.', '..')) as $key => $value) {
    echo  $value . " ";
}
echo "\n";
?>

</body>
</html>
```
Native PHP running index.php
When we use the native php binary we see

a Linux-based platform
a list of 58 environment variables that the script can access if it needs to
a list of all the files and folders in `/``, which again the script can access if it needs to
$ php -f images/php/docroot/index.php

<html>
<body>
<h1>Hello from PHP 7.4.3 running on "Linux alexandrov-z01 5.15.79.1-microsoft-standard-WSL2 #1 SMP Wed Nov 23 01:01:46 UTC 2022 x86_64"</h1>

<h2>List env variable names</h2>
Running with 58 environment variables:
SHELL NVM_INC WSL2_GUI_APPS_ENABLED rvm_prefix WSL_DISTRO_NAME TMUX rvm_stored_umask TMUX_PLUGIN_MANAGER_PATH MY_RUBY_HOME NAME RUBY_VERSION PWD NIX_PROFILES LOGNAME rvm_version rvm_user_install_flag MOTD_SHOWN HOME LANG WSL_INTEROP LS_COLORS WASMTIME_HOME WAYLAND_DISPLAY NIX_SSL_CERT_FILE PROMPT_COMMAND NVM_DIR rvm_bin_path GEM_PATH GEM_HOME LESSCLOSE TERM CPLUS_INCLUDE_PATH LESSOPEN USER TMUX_PANE LIBRARY_PATH rvm_loaded_flag DISPLAY SHLVL NVM_CD_FLAGS LD_LIBRARY_PATH XDG_RUNTIME_DIR PS1 WSLENV XDG_DATA_DIRS PATH DBUS_SESSION_BUS_ADDRESS C_INCLUDE_PATH NVM_BIN HOSTTYPE WASMER_CACHE_DIR IRBRC PULSE_SERVER rvm_path WASMER_DIR OLDPWD BASH_FUNC_cr-open%% _

<h2>Hello</h2>
Today, Wednesday, 2022-12-14, at 12:0:36 we greet you with this message!

<h2>Contents of '/'</h2>
apps bin boot dev docroot etc home init lib lib32 lib64 libx32 lost+found media mnt nix opt path proc root run sbin snap srv sys tmp usr var wsl.localhost

</body>
</html>
php-aot-wasm running index.php
When we use php-aot-wasm with Wasmedge we see

a wasi/wasm32 platform
no environment variables, because non have been explicitly exposed to the Wasm application
the Wasm application was not given explicit access to / so attempts to list its contents failed with an error
Naturally, for php-wasmedge-aot to have access to read the index.php file we had to explicitly state to WasmEdge that we want to pre-open images/php/docroot for access as /docroot in the context of the Wasm application.

This easily shows one of the greatest benefits of Wasm apart from portability. We get better security because nothing is accessible unless explicitly stated.

$ wasmedge --dir /docroot:$(pwd)/images/php/docroot \
   build-output/php/php-7.4.32/bin/php-wasmedge-aot -f /docroot/index.php


<html>
<body>
<h1>Hello from PHP 7.4.32 running on "wasi (none) 0.0.0 0.0.0 wasm32"</h1>

<h2>List env variable names</h2>
Running with 0 environment variables:


<h2>Hello</h2>
Today, Wednesday, 2022-12-14, at 10:8:46 we greet you with this message!

<h2>Contents of '/'</h2>

Warning: scandir(/): failed to open dir: Capabilities insufficient in /docroot/index.php on line 27

Warning: scandir(): (errno 76): Capabilities insufficient in /docroot/index.php on line 27

Warning: array_diff(): Expected parameter 1 to be an array, bool given in /docroot/index.php on line 27

Warning: Invalid argument supplied for foreach() in /docroot/index.php on line 27


</body>
</html>
PHP in a container running index.php
When we use php from a traditional container we see

a Linux-based platform
a list of 14 environment variables that the script has access to
a hello message with the current time and date
a list with the contents of the root folder /
There is already a difference for the better compared to running this with php on the host machine. As the environment variables and contents of / are "virtual" and exist only within the container.

docker run --rm \
   -v $(pwd)/images/php/docroot:/docroot \
   php:7.4.32-cli \
   php -f /docroot/index.php


<html>
<body>
<h1>Hello from PHP 7.4.32 running on "Linux 227b2bc2f611 5.15.79.1-microsoft-standard-WSL2 #1 SMP Wed Nov 23 01:01:46 UTC 2022 x86_64"</h1>

<h2>List env variable names</h2>
Running with 14 environment variables:
HOSTNAME PHP_INI_DIR HOME PHP_LDFLAGS PHP_CFLAGS PHP_VERSION GPG_KEYS PHP_CPPFLAGS PHP_ASC_URL PHP_URL PATH PHPIZE_DEPS PWD PHP_SHA256

<h2>Hello</h2>
Today, Wednesday, 2022-12-14, at 10:15:35 we greet you with this message!

<h2>Contents of '/'</h2>
bin boot dev docroot etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var

</body>
</html>
php-aot-wasm in a container running index.php
When we use php-aot-wasm with Wasmedge we see

a wasi/wasm32 platform
just 2 infrastructural environment variables, pre-set with the WasmEdge shim that is running within containerd
a list of all the files and folders in / within the container, which is explicitly pre-opened for access by the Wasm application (part of the logic in the WasmEdge shim)
Note: If you are more observant you will see that to run a container out of this image we have to:

explicitly state the runtime via --runtime=io.containerd.wasmedge.v1pass command line arguments to php.wasm directly, without including the binary itself. Scroll back above and see that we could explicitly write the full command with the traditional PHP container, including the php binary (not that it is necessary).
As a final note, even with Docker, Wasm has tightened the security around running index.php, as far less is exposed to it.

docker run --rm \
   --runtime=io.containerd.wasmedge.v1 \
   -v $(pwd)/images/php/docroot:/docroot \
   ghcr.io/vmware-labs/php-wasm:7.4.32-cli-aot \
   -f /docroot/index.php


<html>
<body>
<h1>Hello from PHP 7.4.32 running on "wasi (none) 0.0.0 0.0.0 wasm32"</h1>

<h2>List env variable names</h2>
Running with 2 environment variables:
PATH HOSTNAME

<h2>Hello</h2>
Today, Wednesday, 2022-12-14, at 11:33:10 we greet you with this message!

<h2>Contents of '/'</h2>
docroot etc php.wasm

</body>
</html>
Traditional vs wasm containers
We managed to build and run a Wasm binary, and run it as a container, too. We saw the difference in output between a Wasm and a traditional container and the advanced "sandboxing" that Wasm brings in. Let's take a look at what other differences between the two types of containers we can easily see.

First, we will run two daemon containers and see how we can interpret some stats about them. Then we will examine the differences in the container images.

Comparing containers
Container stats
Let's run two daemon containers - one from the traditional php image, and another from the php-wasm image.
```
docker run --rm -d \
   -p 8083:8080 -v $(pwd)/images/php/docroot:/docroot \
   php:7.4.32-cli \
   -S 0.0.0.0:8080 -t /docroot
docker run --rm -d \
   --runtime=io.containerd.wasmedge.v1 \
   -p 8082:8080 -v $(pwd)/images/php/docroot:/docroot \
   ghcr.io/vmware-labs/php-wasm:7.4.32-cli-aot
   -S 0.0.0.0:8080 -t /docroot
```

If we look at docker stats, however, we will only see stats for the traditional container. This might change with time as Docker+Wasm is a beta feature. So, if one really wants to see what's going on one could monitor the control groups instead. Each traditional container gets its own control group as in docker/ee44.... On the other hand, Wasm containers are included as part of the podruntime/docker control group and one can indirectly observe their CPU or Memory consumption.

$ systemd-cgtop -kP --depth=10

Control Group           Tasks    %CPU     Memory
podruntime              145      0.1      636.3M
podruntime/docker       145      0.1      636.3M
docker                  2        0.0      39.7M
docker/ee444b...        1        0.0      6.7M
Image size
First, exploring the images, we see that Wasm container images are much smaller than the traditional ones. Even the alpine version of the php container is bigger than the Wasm one.

$ docker images


REPOSITORY                     TAG                 IMAGE ID       CREATED          SIZE
php                            7.4.32-cli          680c4ba36f1b   2 hours ago      166MB
php                            7.4.32-cli-alpine   a785f7973660   2 minutes ago    30.1MB
ghcr.io/vmware-labs/php-wasm   7.4.32-cli-aot      63460740f6d5   44 minutes ago   5.35MB
This is expected because with Wasm we only need to add the executable binary inside the container, while with traditional containers we still need some basic libs and files from the OS on which the binary will be running.

This difference in size can be quite beneficial for the speed of pulling an image for the first time as well as for the space that images take in a local repository.

Wasm portability
One of the best things about Wasm is its portability. Docker has made traditional containers the way to go when one wants a portable application. However, on top of the big image size, traditional containers are also bound to the architecture of the platform on which they run. Many of us have been through the ups and downs of having to build versions of our software that support different architectures and packaging those in different images for each architecture.

WebAssembly brings true portability to the picture. You can build a binary once and run it everywhere. As a testament to that portability, we have prepared several examples of running WordPress via the PHP interpreter which we built for WebAssembly.

PHP would serve WordPress when it's run as a standalone Wasm application. Just as well it could run in a Docker+Wasm container. Also, it could run in any application that embeds a Wasm runtime. In our example, this is apache httpd, which via mod_wasm can use Wasm applications as content handlers. Lastly, PHP.wasm can just as well run in a browser.

Comparing containers
Serving WordPress via WasmEdge
We have prepared a compact WordPress+Sqlite example for this demonstration. Since it's a part of the ghcr.io/vmware-labs/php-wasm:7.4.32-server-wordpress container image, let's first download it locally.

This command will just create a temporary container (pulling the image), copy the WordPress files into /tmp/wp/docroot and then remove the container.
```
container_id=$(docker create ghcr.io/vmware-labs/php-wasm:7.4.32-server-wordpress) && \
   mkdir /tmp/wp && \
   docker cp $container_id:/docroot /tmp/wp/ && \
   docker rm $container_id
Now that we have WordPress let's serve it with:

wasmedge --dir /docroot:/tmp/wp/docroot \
   build-output/php/php-7.4.32/bin/php-wasmedge-aot \
   -S 0.0.0.0:8085 -t /docroot
You can go to http://localhost:8085 and enjoy WordPress served by a PHP Wasm interpreter.

Serving WordPress via Docker+Wasm
Naturally, with Docker, things are much simpler.

docker run --rm --runtime=io.containerd.wasmedge.v1 \
   -p 8086:8080 -v /tmp/wp/docroot/:/docroot/ \
   ghcr.io/vmware-labs/php-wasm:7.4.32-cli-aot
   -S 0.0.0.0:8080 -t /docroot
```

You can go to http://localhost:8086 and enjoy WordPress served by a PHP Wasm interpreter, which this time runs in a Docker container.

Serving WordPress via mod_wasm in Apache HTTPD
Apache HTTPD is one of the most widely used HTTP servers. And now with mod_wasm it can also run WebAssembly applications. To avoid installing and configuring it locally we have prepared a container where we have Apache HTTPD, mod_wasm and WordPress.

docker run -p 8087:8080 projects.registry.vmware.com/wasmlabs/containers/php-mod-wasm:wordpress
You can go to http://localhost:8087 and enjoy WordPress served by a PHP Wasm interpreter, which is loaded by mod_wasm within Apache HTTPD.

Serving WordPress directly in a browser
Just go to [https://wordpress.wasmlabs.dev] for an example. You will see a frame in which the PHP Wasm interpreter is rendering WordPress on the spot.

Conclusion
Thank you for reading this article. It was a lot to digest, but we hope it was useful to understand the capabilities of WebAssembly and how it can work with your existing codebases and tools, including Docker. Looking forward to see what you build with Wasm!
