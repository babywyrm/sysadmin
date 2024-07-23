
##
#
https://github.com/cilium/ebpf?tab=readme-ov-file
#
https://github.com/zoidyzoidzoid/awesome-ebpf
#
##

Getting Started with eBPF in Go¶

In this guide, we'll walk you through building a new eBPF-powered Go application from scratch. We'll introduce the toolchain, write a minimal eBPF C example and compile it using bpf2go. Then, we'll put together a Go application that loads the eBPF program into the kernel and periodically displays its output.

The application attaches an eBPF program to an XDP hook that counts the number of packets received by a physical interface. Filtering and modifying packets is a major use case for eBPF, so you'll see a lot of its features being geared towards it. However, eBPF's capabilities are ever-growing, and it has been adopted for tracing, systems and application observability, security and much more.
eBPF C program¶

Dependencies

To follow along with the example, you'll need:

    Linux kernel version 5.7 or later, for bpf_link support
    LLVM 11 or later 1 (clang and llvm-strip)
    libbpf headers 2
    Linux kernel headers 3
    Go compiler version supported by ebpf-go's Go module

Let's begin by writing our eBPF C program, as its structure will be used as the basis for generating Go boilerplate.

Click the

annotations in the code snippet for a detailed explanation of the individual components.
counter.c
```

//go:build ignore

#include <linux/bpf.h>


#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 


    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 



// count_packets atomically increases a packet counter on every invocation.
SEC("xdp") 


int count_packets() {
    __u32 key    = 0; 


    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 


    if (count) { 


        __sync_fetch_and_add(count, 1); 


    }

    return XDP_PASS; 


}

char __license[] SEC("license") = "Dual MIT/GPL"; 
```

Create an empty directory and save this file as counter.c. In the next step, we'll set up the necessary bits to compile our eBPF C program using bpf2go.
Compile eBPF C and generate scaffolding using bpf2go¶

With the counter.c source file in place, create another file called gen.go containing a //go:generate statement. This invokes bpf2go when running go generate in the project directory.

Aside from compiling our eBPF C program, bpf2go will also generate some scaffolding code we'll use to load our eBPF program into the kernel and interact with its various components. This greatly reduces the amount of code we need to write to get up and running.
gen.go

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c

Using a dedicated file for your package's //go:generate statement(s) is neat for keeping them separated from application logic. At this point in the guide, we don't have a main.go file yet. Feel free to include it in existing Go source files if you prefer.

Before using the Go toolchain, Go wants us to declare a Go module. This command should take care of that:

go mod init ebpf-test



While eBPF is not exactly new (7 years old, at this moment), it's still early in terms of Linux kernel, where adoption of new technologies occurrs usually in a slow pace. And I've been eager for a while to start diving into it.

Recently, I had some time to dedicate to eBPF and BTF, so I just started reading the docs at kernel.org (really recommended!), and because doing is the best way of learning, I just simply wrote a library, sklookup-go, in Golang around sk_lookup, that would help me with some legacy TCP servers.
The library, what is sklookup-go?

sklookup-go is a project that provides:

    A cli to run against a program that’s binded into one socket, providing this program (specified by its PID) of some additional ports. (Max. 1024)
    It’s also a package that you can use from your Golang code. Maybe you have some program that binds into a port, and for some reason you don’t want to bind it anywhere else. That’s not a problem, import the library, pass the listener’s file descriptor and some additional ports and you’re ready to roll.
    This two capabilities rely on a sk_lookup eBPF program, compiled through bpf2go and the logic written thanks to the Golang package cilium/ebpf.

And what exactly is sk_lookup?

There are many eBPF program types, and sk_lookup (BPF_PROG_TYPE_SK_LOOKUP) is just one of them.

This type of program runs in the kernel protocol layer, just before attaching a connection to an existing receive buffer in a socket.

Or roughly speaking, when the kernel is trying to make sense of where to pass this specific chunk of data that it received, sk_lookup comes into it and pass the data to a file descriptor which points to a socket.
But… then, what is eBPF?

eBPF is undeniably a revolutionary technology. It introduces programmability in an space, the Linux kernel (Windows, as well), that traditionally was restricted to kernel modules.

A kernel is, for obvious reasons, the most critical piece of every OS, and its evolution is often slow, but thanks to eBPF this is no longer true. Everyone, as a system programmer, can load programs into the kernel and run them in a sandboxed fashion.
So, why is this useful for us?

First of all, because it's extremely cool. Never forget the rule of cool; you know… anything is acceptable to do, so long as it is cool.

And also, seriously speaking, imagine the scenario where you have to provide additional ports to a legacy application which happens to listen only in one socket, or just one IP. And you really need it to listen in more sockets.

Or maybe you want to implement a L7 proxy, while binding your proxy only to one IP or socket.

If you dream about it, you can do it.
Why using the ebpf package developed by Cilium?

There are many good libraries to interact with ebpf, but I chose cilium/ebpf because their approach as a pure Go implementation. It feels completely sane and reasonable, as we no longer rely on other build tools or workflows to get the job done.

Also, while used with bpf2go it allows you to interact with the program without having to compile the ELF binaries by yourself, and that's one thing less to worry about.

    Remember, bpf2go will compile the source code into eBPF bytecode, in a similar fashion as the cli bpftool gen skeleton.

Into some technical details in C and eBPF

eBPF programs are written in C, so far we're not free of writing the program as well. You can check the eBPF C program here. That's the sk_lookup program which acts as the backend of sklookup-go.

The implementation is based on this Jakub Sitnicki code, though I changed the maps to support BTF (we'll talk about this in a following article)

Also, it's critical to mention that the user interacts with eBPF programs through eBPF Maps loaded into kernel memory, that's the way an user is able to share information between userspace and the kernel, and what we'll be doing in the Go library.

The following two maps is where the magic resides:

    In the hashMap, up to a maximum of 1024 key:value are stored. The key is the actual port number, and we don't care about its value.
    In the sockMap there can be only one value at key 0; the destination socket's file descriptor.

/* List of additional service ports. Key is the port number. */
struct { 
  __uint(type, BPF_MAP_TYPE_HASH); 
  __type(key, __u16); 
  __type(value, __u8); 
  __uint(max_entries, 1024);} 
add_ports SEC(".maps");/* Target socket */
struct { 
  __uint(type, BPF_MAP_TYPE_SOCKMAP); 
  __type(key, __u32); 
  __type(value, __u64); 
  __uint(max_entries, 1);} 
target_socket SEC(".maps");

And, finally, the Go pumbling

By now you'll have noticed that I don't explicitly compile the C code into an ELF binary, though it's needed for us to run eBPF programs.

So take a look at ebpf.go, specifically at this little bit:

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf src/ebpf/sk_dispatch.c -- -Isrc/headers

This line calls bpf2go, and generates the needed ELF's and two go files, bpf_bpfeb.go and bpf_bpfel.go, for Big and Little Endian respectively, with all the functions you'll need to call from your Go code.

The code at ebpf.go is where the main magic resides, and it handles a fair bunch of stuff:

    It loads the BPF objects (maps and program) that needs to be loaded into kernel's memory.
    It Pin() these objects into the system.

    Pin() is the method used to create a file where the eBPF Map will be accessed. It requires a BPF filesystem, usually /sys/fs/bpf.

    Also, don't forget to Unpin() and Close() the maps and the program after using them, otherwise that would leave the maps and program mounted into the fs.
    It creates the dispatcher link, and clones the caller network namespace, so the communication between processes can happen.

func getDispatcherLink(p *ebpf.Program) (*link.NetNsLink, error) {
 // Get self net-namespace
 netns, err := os.Open("/proc/self/ns/net")
 if err != nil {
  return nil, err
 }
 defer netns.Close()// Attach the network namespace to the link
 lnk, err := link.AttachNetNs(int(netns.Fd()), p)
 if err != nil {
  return nil, err
 }return lnk, nil
}

    When attaching to an external process, the program also performs a systemcall of pidfd_getfd(pidfd_open(PID, o), FD, 0), to duplicate the target socket's file descriptor, so it can be used by our calling program. It looks like the following:

func (e *EbpfExternalDispatcher) getListenerFd() uintptr {
 // pidfd_open
 pidFd, err := pidfd.Open(e.TargetPID, 0)
 if err != nil {
  e.Log.Panic().Err(err).Msgf("Unable to open target pid %v", e.TargetPID)
 }
 e.Log.Trace().Msgf("getListenerFd.pidFd: %v", pidFd)// pidfd_getfd
 listenFd, err := pidFd.GetFd(int(pidFd), 0)
 if err != nil {
  e.Log.Panic().Err(err).Msgf("Unable to duplicate target fd %v", pidFd)
 }
 e.Log.Trace().Msgf("getListenerFd.listenFd: %v", listenFd)file := os.NewFile(uintptr(listenFd), "")return file.Fd()
}

    Finally it handles the addition of the target socket's file descriptor, add the origin ports to be used, and some boilerplate code.

Wrapping up

This library is under heavy development, it's now at v0.1.0-alpha version, as it's the first iteration I've rolled out.

I had a blast writing this, and already wrote a TCP proxy relying on it (which works!). So, if you're curious about eBPF and Go, please be more than welcome to use the package, modify, contribute.

As a conclusion, I'm extremely hyped by the eBPF technology and the use cases that we'll see in the future. Usually the kernel development moves slowly, and also is the process of creating kernel modules and pushing them to stable and broadly adopted by the community.

With this technology I'm sure we'll see amazing projects doing some cool things, starting from SDN, to Security and many other use cases.

Keep curious!

go mod tidy

We also need to manually add a dependency on bpf2go since it's not explicitly imported by a .go source file:

go get github.com/cilium/ebpf/cmd/bpf2go




Now we're ready to run go generate:

go generate







bpf2go built counter.c into counter_bpf*.o behind the scenes using clang. It generated two object files and two corresponding Go source files based on the contents of the object files. Do not remove any of these, we'll need them later.

Let's inspect one of the generated .go files:
counter_bpfel.go

type counterPrograms struct {
    CountPackets *ebpf.Program `ebpf:"count_packets"`
}

Neat! Looks like bpf2go automatically generated a scaffolding for interacting with our count_packets Program from Go. In the next step, we'll explore how to load our program into the kernel and put it to work by attaching it to an XDP hook!
The Go application¶

Finally, with our eBPF C code compiled and Go scaffolding generated, all that's left is writing the Go code responsible for loading and attaching the program to a hook in the Linux kernel.

Click the

annotations in the code snippet for some of the more intricate details. Note that we won't cover anything related to the Go standard library here.
main.go

package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "time"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 


        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs counterObjects 


    if err := loadCounterObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 



    ifname := "eth0" // Change this to an interface on your machine.
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 


        Program:   objs.CountPackets,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close() 



    log.Printf("Counting incoming packets on %s..", ifname)

    // Periodically fetch the packet counter from PktCount,
    // exit the program when interrupted.
    tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)
    for {
        select {
        case <-tick:
            var count uint64
            err := objs.PktCount.Lookup(uint32(0), &count) 


            if err != nil {
                log.Fatal("Map lookup:", err)
            }
            log.Printf("Received %d packets", count)
        case <-stop:
            log.Print("Received signal, exiting..")
            return
        }
    }
}

Save this file as main.go in the same directory alongside counter.c and gen.go.
Building and running the Go application¶

Now main.go is in place, we can finally compile and run our Go application!

go build && sudo ./ebpf-test






Generate some traffic on eth0 and you should see the counter increase.
Iteration Workflow¶

When iterating on the C code, make sure to keep generated files up-to-date. Without re-running bpf2go, the eBPF C won't be recompiled, and any changes made to the C program structure won't be reflected in the Go scaffolding.

go generate && go build && sudo ./ebpf-test

What's Next?¶

Congratulations, you've just built your (presumably) first eBPF-powered Go app! Hopefully, this guide piqued your interest and gave you a better sense of what eBPF can do and how it works.

With XDP, we've only barely scratched the surface of eBPF's many use cases and applications. For more easily-accessible examples, see the main repository's examples/ folder. It demonstrates use cases like tracing user space applications, extracting information from the kernel, attaching eBPF programs to network sockets and more.

Follow our other guides to continue on your journey of shipping a portable eBPF-powered application to your users.

    Use clang --version to check which version of LLVM you have installed. Refer to your distribution's package index to finding the right packages to install, as this tends to vary wildly across distributions. Some distributions ship clang and llvm-strip in separate packages. ↩

    For Debian/Ubuntu, you'll typically need libbpf-dev. On Fedora, it's libbpf-devel. ↩

    On AMD64 Debian/Ubuntu, install linux-headers-amd64. On Fedora, install kernel-devel.

    On Debian, you may also need ln -sf /usr/include/asm-generic/ /usr/include/asm since the example expects to find <asm/types.h>. ↩

