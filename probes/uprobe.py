from bcc import BPF


bpf_source = """
int do_sys_execve(struct pt_regs *ctx, void filename, void argv, void envp) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("executing program: %s", comm);
    return 0;
}
"""

bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = execve_function,fn_name="do_sys_execve")
bpf.trace_print()