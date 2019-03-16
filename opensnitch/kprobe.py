# This file is part of OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import logging
import contextlib
import subprocess
import opensnitch.bpftrace

comms = {}
filenames = {}

co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()

assert co('cat /proc/sys/kernel/ftrace_enabled') == '1', 'ftrace needs to be enabled'

probe_name = "opensnitch_exec_probe"
syscall_name = "do_execve"
max_arguments = 16
system_probes_file = "/sys/kernel/debug/tracing/kprobe_events"
events_pipe_file = "/sys/kernel/debug/tracing/trace_pipe"
probe_file_format = f"/sys/kernel/debug/tracing/events/kprobes/{probe_name}/enable"
event_file_format = "/sys/kernel/debug/tracing/events/%s/enable"
sub_events = ["sched/sched_process_fork", "sched/sched_process_exec", "sched/sched_process_exit"]
descriptor = f"p:kprobes/{probe_name} {syscall_name}"
for i in range(max_arguments):
    descriptor += f" arg{i}=+0(+{i * 8}(%si)):string"
events = {}
for e in sub_events:
    events[e.split('/')[-1]] = event_file_format % e

def enable():
    disable()
    for name, path in events.items():
        with open(path, 'w') as f:
            f.write('1')
    with open(system_probes_file, 'w') as f:
        f.write(descriptor)
    with open(probe_file_format, 'w') as f:
        f.write('1')

@contextlib.contextmanager
def ignore_exceptions():
    try:
        yield
    except:
        pass

def disable():
    with open(events_pipe_file, 'wb') as f:
        f.write(b'')
    for name, path in events.items():
        with ignore_exceptions():
            with open(path, 'w') as f:
                f.write('0')
    with ignore_exceptions():
        with open(probe_file_format, 'w') as f:
            f.write('0')
    with ignore_exceptions():
        with open(system_probes_file, 'w') as f:
            f.write(f'-:{probe_name}')

def start():
    enable()
    opensnitch.bpftrace.run_thread(tail)

def tail():
    with open(events_pipe_file, 'rb') as pipe:
        for line in pipe:
            # print(line)
            parts = line.split()

            try:
                name_pid, _, _, _, probe, *rest = parts
            except ValueError:
                logging.error(f'not enough parts: {line}')
                continue
            pid = name_pid.split(b'-')[-1].decode('utf-8')

            if False:
                pass

            elif b'opensnitch_exec_probe:' == probe:
                arg_string = b''
                comm = rest[1].split(b'=')[-1].replace(b'"', b'').decode('utf-8')
                for r in rest[2:]:
                    r = r.split(b'=')[-1]
                    if r == b'(fault)':
                        break
                    arg_string += b' ' + r
                arg_string = arg_string.replace(b'"', b'')
                comms[pid] = (comm, arg_string)

            elif b'sched_process_exit:' == probe:
                comms.pop(pid, None)
                filenames.pop(pid, None)

            elif b'sched_process_exec:' == probe:
                filename, _pid, _old_pid = rest
                filename = filename.split(b'=')[-1].decode('utf-8')
                filenames[pid] = filename

            elif b'sched_process_fork:' == probe:
                comm, _pid, _child_comm, child_pid = rest
                comm = comm.split(b'=')[-1].decode('utf-8')
                child_pid = child_pid.split(b'=')[-1].decode('utf-8')
                try:
                    comms[child_pid] = comms[pid]
                except KeyError:
                    comms[child_pid] = comm, ''
                try:
                    filenames[child_pid] = filenames[pid]
                except KeyError:
                    pass

            # else:
                # logging.info(f'kprobe unknown: {probe} {pid} {rest}')









                    # elif token == 'opensnitch_exec_probe:':
