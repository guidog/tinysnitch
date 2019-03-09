import shell

assert shell.run('cat /proc/sys/kernel/ftrace_enabled') == '1'

probe_name = "opensnitch_exec_probe"
syscall_name = "do_execve"
max_arguments = 16
enabled_status_file = "/proc/sys/kernel/ftrace_enabled"
system_probes_file = "/sys/kernel/debug/tracing/kprobe_events"
events_pipe_file = "/sys/kernel/debug/tracing/trace_pipe"
probe_file_format = "/sys/kernel/debug/tracing/events/kprobes/%s/enable"
event_file_format = "/sys/kernel/debug/tracing/events/%s/enable"
sub_events = ["sched/sched_process_fork",
              "sched/sched_process_exec",
              "sched/sched_process_exit"]
descriptor = f"p:kprobes/{probe_name} {syscall_name}"
for i in range(max_arguments):
    descriptor += f" arg{i}=+0(+{i * 8}(%si)):string"
events = {}
for e in sub_events:
    events[e.split('/')[-1]] = event_file_format % e

def enable():
    for name, path in events.items():
        with open(path, 'w') as f:
            f.write('1')
    with open(system_probes_file, 'w') as f:
        f.write(descriptor)
    with open(probe_file_format % probe_name, 'w') as f:
        f.write('1')

def disable():
    for name, path in events.items():
        with open(path, 'w') as f:
            f.write('0')
    with open(probe_file_format % probe_name, 'w') as f:
        f.write('0')
    with open(system_probes_file, 'w') as f:
        f.write(f'-:{probe_name}')

def tail():
    pipe = open(events_pipe_file, 'rb')
    for line in pipe:
        if b'opensnitch_exec_probe' in line:
            try:
                print(line.strip().decode('utf-8'))
            except:
                print(line.strip())

try:
    disable()
except:
    pass
enable()
tail()
