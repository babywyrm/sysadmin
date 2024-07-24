## Introduction

##
#
https://gist.github.com/satrobit/17eb0ddd4e122425d96f60f45def9627
#
##

If you're reading this, chances are you have some idea of eBPF and XDP. In this article, we'll write an eBPF program that will count and categorize packets based on the destination port.

### eBPF
Writing low-level tracing, monitoring, or network programs in Linux is not easy. Through all the layers of the kernel, people have been squeezing every bit of performance they could get.

And that's where eBPF comes in. eBPF is basically an extended and modern variation of BPF which is like a virtual machine inside the Linux kernel. It can execute user-defined programs inside a sandbox in the kernel. 

These programs can be executed in various hook points but we will focus on XDP for now.


### XDP
XDP provides a data path which we can intercept or even edit packets using an eBPF program. The execution can happen in 3 different places depending on your setup:

1. **Offloaded - NIC:** eBPF program can be offloaded to the network card itself, provided that the card supports XDP offloading.
2. **Native - NIC Driver:** eBPF will fallback to the driver if your card doesn't support offloading. The good news is that most drivers support this and performance is still impressive since this is all before entering the Linux network stack.
3. **Generic - Linux Network Stack:** This is the last option if the mentioned methods are not supported. Performance is not as good since the packet has entered the network stack.

The fate of packets is decided by action codes that your program returns:

1. **XDP_PASS:** let the packet continue through the network stack
2. **XDP_DROP:** silently drop the packet
3. **XDP_ABORTED:** drop the packet with trace point exception
4. **XDP_TX:** bounce the packet back to the same NIC it arrived on
5. **XDP_REDIRECT:** redirect the packet to another NIC or user space socket via the `AF_XDP` address family

### BCC

BCC is a toolkit for creating eBPF programs with bindings to a few languages like Python, Lua and etc. BCC makes it pleasantly easy to write eBPF programs and their GitHub page is filled with examples to get you started.

We'll use BCC in Python to write our program.


## eBPF Program in C

We start by writing the eBPF program itself before getting into the bcc stuff.

### Entry Point
eBPF is event-driven so it'll call our exposed function when a packet arrives. Hence, we'll define a function that receives packet metadata and returns an XDP action code.

```c
#define KBUILD_MODNAME "udp_counter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

int udp_counter(struct xdp_md *ctx) {
    bpf_trace_printk("packet received\n");
    // MORE CODE HERE
}
```

### UDP Packet Data
using the `ctx` we can extract everything we need about the arrived packet.
```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
struct ethhdr *eth = data;

if ((void *)eth + sizeof(*eth) <= data_end) {

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) <= data_end) {

        if (ip->protocol == IPPROTO_UDP) {

            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                // MORE CODE HERE
            }

        }

    }
    
}    
```
As you can see, we go through the eth and IP packet to get to the UDP packet. Here, we can get the destination port that needs to be stored in a histogram. But what histogram!? In the next section, we learn about BPF maps.

### BPF Maps
If you were wondering how will we be able to store our results, there is amazing news. BPF provides multiple useful data structures that we can use to store persisted data or even exchange data to and from userland.

Here is a list of some of the most noticeable data BPF data structures:
1. **BPF_TABLE**
2. **BPF_HASH**
3. **BPF_ARRAY**
4. **BPF_HISTOGRAM**
5. **BPF_PERF_ARRAY**

We'll use `BPF_HISTOGRAM` to count UDP packets based on their port.

Syntax:
```c
BPF_HISTOGRAM(name [, key_type [, size ]])
```

Now we define the histogram outside of the `udp_counter` like this:

```c
BPF_HISTOGRAM(counter, u64);
```
You'll need only one method to work with histograms: `increment()`.

`increment` will increment the value based on the key that you provided.
Syntax:
```c
map.increment(key[, increment_amount])
```
In the next section, we go back to the UDP packet and try to count them.

### Counter
In the `UDP Packet Data` section, we extracted the UDP packet and left a place to count them.

Since we have a histogram ready, the only thing you need to do is to increment the value based on the port that you extract from the UDP packet.
```c
u64 value = htons(udp->dest);
counter.increment(value);
```
> The htons() function converts the unsigned short integer hostshort from host byte order to network byte order.

### XDP Action Code
Now that we're done with the packet, we need to pass the packet so it can go through the network stack. We can just return `XDP_PASS` at the end of our function.
```c
return XDP_PASS;
```

### Final Code
```c
#define KBUILD_MODNAME "udp_counter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

BPF_HISTOGRAM(counter, u64);

int udp_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end)
    {

        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
        {

            if (ip->protocol == IPPROTO_UDP)
            {

                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    u64 value = htons(udp->dest);
                    counter.increment(value);
                }
            }
        }
    }
    return XDP_PASS;
}
```

## BCC Program
The only thing left to write is a simple bcc program to load our eBPF code and attach it to a device like loopback.
```python
from bcc import BPF #1
from bcc.utils import printb

device = "lo" #2
b = BPF(src_file="udp_counter.c") #3
fn = b.load_func("udp_counter", BPF.XDP) #4
b.attach_xdp(device, fn, 0) #5

try:
    b.trace_print() #6
except KeyboardInterrupt: #7

    dist = b.get_table("counter") #8
    for k, v in sorted(dist.items()): #9
        print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value)) #10

b.remove_xdp(device, 0) #11

```
As you can see, the program is fairly simple.

Steps explained:

1. Import the BPF python lib.
2. Specify which device you want your eBPF code to get attached to.
3. Create the BPF object and load the file.
4. Load the function.
5. Attach the function to the xdp hook of the device that was specified earlier.
6. Read the trace_pipe file so we can trace what's happening.
7. Catch the exit signal so we can exit gracefully.
8. Get the contents of the histogram.
9. Iterate over the content.
10. Print the results.
11. Deattach our code from the device.

### Execution
Simple run the python code:
```bash
sudo python main.py
```
Wait for some data to be gathered. You can send out some packets using `nc`:
```bash
nc -u 127.0.0.1 5005
```
Send multiple packets to different ports and then exit from the python program. You should see something like this:
```
DEST_PORT : 5007, COUNT : 1
DEST_PORT : 5005, COUNT : 5
DEST_PORT : 5006, COUNT : 2
```
As you can see, the result shows how many packets were sent to these ports separately.
## Conclusion
In this article, we learned about eBPF and XDP and why they matter so much. We also were able to write a program to count UDP packets based on their ports using the amazing BCC toolkit.

I really hope this article has been helpful. Thank you for your time.

## Links
1. https://en.wikipedia.org/wiki/Berkeley_Packet_Filter#Extensions_and_optimizations
2. https://docs.cilium.io/en/stable/bpf/
3. https://en.wikipedia.org/wiki/Express_Data_Path
4. https://ebpf.io/what-is-ebpf
5. https://github.com/iovisor/bcc
6. https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
7. https://linux.die.net/man/3/hton
