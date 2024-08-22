// This just my **non-working** version of
// https://gist.github.com/NathanFrench/d38ab24b98a3d5c9536e8993e7964997
//   which tries to capture both the read+write ssl (i.,e outbound and inbound)
// https://gist.githubusercontent.com/salrashid123/a84ae1fe3d6c6f407ec5150683df0518/raw/b916f866e4f3f2490616ce73dd41b187daa456d5/main.go
//
//

package main

import (
	"C"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#define MAX_BUF_SIZE 400
struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        u32 tid;
        u32 uid;
        u32 len;
        u32 buf_filled;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};
#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))
BPF_PERCPU_ARRAY(ssl_data, struct probe_SSL_data_t, 1);
BPF_PERF_OUTPUT(perf_SSL_write);
int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;
        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = num;
        data->buf_filled = 0;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)num);
        if (buf != 0)
                ret = bpf_probe_read_user(data->buf, buf_copy_size, buf);
        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;
        perf_SSL_write.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}
BPF_PERF_OUTPUT(perf_SSL_read);
BPF_HASH(bufs, u32, u64);
int probe_SSL_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        bufs.update(&tid, (u64*)&buf);
        return 0;
}
int probe_SSL_read_exit(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();
        int ret;

        u64 *bufp = bufs.lookup(&tid);
        if (bufp == 0)
                return 0;
        int len = PT_REGS_RC(ctx);
        if (len <= 0) // read failed
                return 0;
        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;
        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = (u32)len;
        data->buf_filled = 0;
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        if (bufp != 0)
                ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);
        bufs.delete(&tid);
        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;
        perf_SSL_read.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}
`

const MAX_BUF_SIZE int = 400

// ProbeEnter the UProbe function name
const ProbeWrite string = "probe_SSL_write"

// ProbeEnter the UProbe function name
const ProbeEnter string = "probe_SSL_read_enter"

// ProbeExit the URETprobe function name
const ProbeExit string = "probe_SSL_read_exit"

// LibSSLPath the path of the library for our UProbe
const LibSSLPath string = "ssl"

// LibSSLSymb the symbol to probe from LibSSLPath
const LibSSLReadSymb string = "SSL_read"

// LibSSLSymb the symbol to probe from LibSSLPath
const LibSSLWriteSymb string = "SSL_write"

// perfTblName is the bpf table to read events from
const perfTblReadName string = "perf_SSL_read"

const perfTblWriteName string = "perf_SSL_write"

type sslDataEvent struct {
	TimeStamp uint64             `json:"TimeStamp"`
	Pid       uint32             `json:"Pid"`
	Tid       uint32             `json:"Tid"`
	Uid       uint32             `json:"Uid"`
	Len       uint32             `json:"DataLen"`
	BufFilled uint32             `json:"BufFilled"`
	Comm      [16]byte           `json:"Comm"`
	Data      [MAX_BUF_SIZE]byte `json:"SSLData"`
}

func main() {

	mod := bpf.NewModule(source, []string{})
	defer mod.Close()

	uWriteProbe, err := mod.LoadUprobe(ProbeWrite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init ProbeWrite map: %s\n", err)
		os.Exit(1)
	}

	uEnterProbe, err := mod.LoadUprobe(ProbeEnter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init ProbeEnter map: %s\n", err)
		os.Exit(1)
	}
	uExitProbe, err := mod.LoadUprobe(ProbeExit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init ProbeExit map: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d %d %d\n", uWriteProbe, uExitProbe, uEnterProbe)

	mod.AttachUprobe(
		LibSSLPath,
		LibSSLWriteSymb,
		uWriteProbe, -1)

	mod.AttachUprobe(
		LibSSLPath,
		LibSSLReadSymb,
		uEnterProbe, -1)

	err = mod.AttachUretprobe(
		LibSSLPath,
		LibSSLReadSymb,
		uExitProbe, -1)

	if err != nil {
		log.Fatal(err)
	}

	rtable := bpf.NewTable(mod.TableId(perfTblReadName), mod)
	wtable := bpf.NewTable(mod.TableId(perfTblWriteName), mod)
	bpfch := make(chan []byte)

	signl := make(chan os.Signal, 1)

	prmap, err := bpf.InitPerfMap(rtable, bpfch, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	wrmap, err := bpf.InitPerfMap(wtable, bpfch, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	signal.Notify(signl, os.Interrupt, os.Kill)

	go func() {
		for {
			data := <-bpfch
			var event sslDataEvent
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("error: %s\n", err)
				continue
			}

			var realLen = event.Len

			if realLen > uint32(MAX_BUF_SIZE) {
				event.Len = uint32(MAX_BUF_SIZE)
			}
			fmt.Printf("\npid:%d (%s)\n--------\n%s",
				event.Pid,
				event.Comm,
				hex.Dump(event.Data[:]))

		}
	}()

	wrmap.Start()
	prmap.Start()
	<-signl
	prmap.Stop()
	wrmap.Stop()
}
