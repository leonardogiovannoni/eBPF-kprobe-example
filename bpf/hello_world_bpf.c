#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#define __attribute_const__ __attribute__((const))
#include <uapi/linux/if_ether.h>
#include <stddef.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ptrace.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 256);
} EVENTS SEC(".maps");


struct Data {
    char filename[128];
};

SEC("kprobe/__x64_sys_execve")
int get_file_name(struct pt_regs *ctx) {
    int ret;
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char *filename = NULL;
    ret = bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx2));
    if (ret < 0) {
        return ret;
    }
    char buf[128] = {};
    ret = bpf_probe_read(buf, sizeof(buf), filename);
    if (ret < 0) {
        return ret;
    }
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
}

char _license[] SEC("license") = "GPL";

