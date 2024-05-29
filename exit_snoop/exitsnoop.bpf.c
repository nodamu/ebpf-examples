#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <exitsnoop.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF)
    
};