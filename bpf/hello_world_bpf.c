#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "../src/common/data.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 512);
} EVENTS SEC(".maps");


int to_string(char* output, unsigned int input) {
    int i = 0;
    for (int j = 0; j < 64; j++) {
        if (input > 0) {
            output[i] = input % 10 + '0';
            input /= 10;
            i++;
        }
    }
    
    output[i] = '\0';
    return i;
}


SEC("fentry/vfs_read")
int BPF_PROG(get_file_name, struct file *f, char *buffer, size_t count, loff_t *pos) {
    int ret = 0;
    struct path path;
    struct qstr qstr;


    ret = bpf_probe_read(&path, sizeof(path), &f->f_path);
    if (ret < 0) {
        return 0;
    }

    ret = bpf_probe_read(&qstr, sizeof(qstr), &path.dentry->d_name);
    if (ret < 0) return 0;

    struct Data buf = {};
    ret = bpf_probe_read_str(buf.filename, sizeof(buf.filename), (void *)qstr.name);
    if (ret < 0) return 0;


    ret = bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
    if (ret) return 0;
    return 0;
}


char _license[] SEC("license") = "GPL";



