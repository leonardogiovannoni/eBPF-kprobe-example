#include "vmlinux.h"

//#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

//#define __attribute_const__ __attribute__((const))
//#include <uapi/linux/if_ether.h>
//#include <stddef.h>
//#include <uapi/linux/ip.h>
//#include <uapi/linux/ptrace.h>
//#include <bpf/bpf_core_read.h>
#include "../src/common/data.h"
//#include <linux/fs.h>
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 512);
} EVENTS SEC(".maps");





/*
SEC("kprobe/__x64_sys_openat")
int get_file_name(struct pt_regs *ctx) {
    int ret;
    struct pt_regs *ctx2 = (struct pt_regs *) PT_REGS_PARM1(ctx);

    // fromt ctx2, get params, inspect inode and check permissions

    char *filename = NULL;
    ret = bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(ctx2));
    if (ret < 0) {
        return ret;
    }
    struct Data buf = {};
    ret = bpf_probe_read(buf.filename, sizeof(buf), filename);
    if (ret < 0) {
        return ret;
    }
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
    return 0;
}*/

// for read
/*SEC("kprobe/__x64_sys_read")
int get_file_name(struct pt_regs *ctx) {
    int ret;
    struct pt_regs *ctx2 = (struct pt_regs *) PT_REGS_PARM1(ctx);

    //(struct file *, char __user *, size_t, loff_t *)
    
    struct file *f = (struct file*) bpf_fdget(PT_REGS_PARM1(ctx2));

    struct Data buf = {};
    ret = bpf_probe_read(buf.filename, sizeof(buf), f->f_path.dentry->d_iname);
    if (ret < 0) {
        return ret;
    }

    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));

    return 0;
}
*/




/*
SEC("kprobe/vfs_read")
int get_file_name(struct pt_regs *ctx) {
    struct file *f = (struct file*)PT_REGS_PARM1(ctx);
    if (!f) return 0; // Safety check

    int ret = 0;

    struct path path;
    struct dentry *dentry;
    struct qstr qstr;

    ret = bpf_probe_read(&path, sizeof(path), &f->f_path);
    if (ret < 0) return 0;
    dentry = path.dentry; 

    ret = bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
    if (ret < 0) return 0;

    struct Data buf = {};
    ret = bpf_probe_read_str(buf.filename, sizeof(buf.filename), (void *)qstr.name);
    if (ret < 0) return 0;


    ret = bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
    if (ret) return 0;

    return 0;
}*/


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

int check_file(struct file *f) {
    struct inode *inode;
    kgid_t qstr;

    int ret = bpf_probe_read(&inode, sizeof(inode), &f->f_inode);
    if (ret < 0 || inode == NULL) return 0;

    ret = bpf_probe_read(&qstr, sizeof(qstr), &inode->i_gid);
    if (ret < 0) return 0;

    gid_t gid = qstr.val;
    if (gid != 1001) 
        return -1;
    return 0;
}



__noinline int check_params(struct pt_regs *ctx) {
    struct file *f = (struct file*)PT_REGS_PARM1(ctx);
    if (!f) return -1; // Safety check

    int ret = check_file(f);
    if (ret != 0) return -1;

    return 0;
}

SEC("kprobe/vfs_read")
int get_file_name(struct pt_regs *ctx) {
   // if (check_params(ctx) < 0) return 0;
    int ret = 0;
    struct file *f = (struct file*) PT_REGS_PARM1(ctx);
    struct path path;
    struct dentry *dentry;
    struct qstr qstr;

    ret = bpf_probe_read(&path, sizeof(path), &f->f_path);
    if (ret < 0) return 0;
    dentry = path.dentry; 

    ret = bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
    if (ret < 0) return 0;

    struct Data buf = {};
    ret = bpf_probe_read_str(buf.filename, sizeof(buf.filename), (void *)qstr.name);
    if (ret < 0) return 0;


    ret = bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &buf, sizeof(buf));
    if (ret) return 0;
    return 0;
}


char _license[] SEC("license") = "GPL";



