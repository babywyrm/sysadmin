// https://gist.github.com/florianl/8f421e57f419fa9a50eb5b085363de66
//
//

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/florianl/go-tc"
	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "tc_eBPF"
#include <uapi/linux/bpf.h>


int tc_eBPF(struct __sk_buff *skb) {
	bpf_trace_printk("hello world\n");
	return 0;
}
`

func main() {
	module := bpf.NewModule(source, []string{"-w"})
	defer module.Close()

	fn, err := module.Load("tc_eBPF", C.BPF_PROG_TYPE_SCHED_CLS, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load ebpf prog: %v\n", err)
		return
	}

	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	devID, err := net.InterfaceByName("lo")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  tc.BuildHandle(0xFFFF, 0x0000),
			Parent:  0xFFFFFFF1,
			Info:    0,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := rtnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to lo: %v\n", err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer rtnl.Qdisc().Delete(&qdisc)

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  tc.Ingress,
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			
			BPF: &tc.Bpf{
				FD:    uint32(fn),
				Name:  "tc_prog",
				Flags: 0x1,
			},
			
		},
	}
	if err := rtnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}
	time.Sleep(30*time.Second)

	// cat sys/kernel/debug/tracing/trace_pipe
}
