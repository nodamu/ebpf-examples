#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <sys/types.h>
// #include <vmlinux.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
  unsigned int pid;
  unsigned int tpid;
  int sig;
  int ret;
  char comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u32);
  __type(value, struct event);

} values SEC(".maps");

struct trace_event_raw_sys_enter {
  __u64 args[0];
};

struct syscalls_enter_kill_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long pid;
    long sig;
};
// struct trace_event_raw_sys_exit {
//   __s64 ret;
// };

static int probe_entry(pid_t tpid, int sig) {
  struct event event = {};
  __u64 pid_tgid;
  __u32 tid;

  pid_tgid = bpf_get_current_pid_tgid();
  tid = (__u32)pid_tgid;
  event.pid = pid_tgid >> 32;
  event.tpid = tpid;
  event.sig = sig;
  bpf_get_current_comm(event.comm, sizeof(event.comm));
  bpf_map_update_elem(&values, &tid, &event, BPF_ANY);

  return 0;
}

static int probe_exit(void *ctx, int ret) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  struct event *eventp;

  eventp = bpf_map_lookup_elem(&values, &tid);
  if (!eventp)
    return 0;

  eventp->ret = ret;
  bpf_printk("PID %d (%s) sent signal %d", eventp->pid, eventp->comm,
             eventp->sig);

  bpf_printk("to PID %d, ret = %d", eventp->tpid, ret);

cleanup:
  bpf_map_delete_elem(&values, &tid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct syscalls_enter_kill_args* ctx) {
  pid_t tpid = (pid_t)ctx->pid;
  int sig = (int)ctx->sig;

  return probe_entry(tpid, sig);
}
struct syscalls_exit_kill_args{
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  int __syscall_nr;
  long ret;
};


SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct syscalls_exit_kill_args* ctx) {

  return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
