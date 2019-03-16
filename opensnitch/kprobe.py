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
            print(line)
            parts = line.split()

            # try:
            #     name_pid, _, _, _, probe, _, *rest = parts
            # except ValueError:
            #     logging.error(f'not enough parts: {line}')
            #     continue
            # pid = name_pid.split(b'-')[-1]
            # if b'opensnitch_exec_probe:' == probe:
            #     logging.info(f'got: {pid} {rest}')

            # try:
            #     line = line.decode('utf-8').rstrip()
            # except UnicodeDecodeError:
            #     logging.info(f'failed to decode {line}')
            # else:
            #     try:
            #         token, *line = line.split()[4:]
            #     except ValueError:
            #         logging.info(f'bad kprobe line: {line}')
            #     else:
            #         if False:
            #             pass

                    # elif token == 'sched_process_exit:':
                    #     _comm, pid, _prio = line
                    #     pid = pid.split('=')[-1]
                    #     comms.pop(pid, None)
                    #     filenames.pop(pid, None)

                    # elif token == 'sched_process_fork:':
                    #     comm, pid, _child_comm, child_pid = line
                    #     comm = comm.split('=')[-1]
                    #     pid = pid.split('=')[-1]
                    #     child_pid = child_pid.split('=')[-1]
                    #     if pid in comms:
                    #         comms[child_pid] = comms[pid]
                    #     else:
                    #         comms[child_pid] = comm, ''
                    #     if pid in filenames:
                    #         filenames[child_pid] = filenames[pid]

                    # elif token == 'sched_process_exec:':
                    #     filename, pid, _old_pid = line
                    #     filename = filename.split('=')[-1]
                    #     pid = pid.split('=')[-1]
                    #     filenames[pid] = filename

                    # elif token == 'opensnitch_exec_probe:':
                        # logging.info(line)
                        # _, path, *args = line
                        # path = path.split('=')[-1].replace('"', '')
                        # arg_string = ''
                        # for arg in args:
                        #     if '(fault)' in arg:
                        #         break
                        #     arg_string += ' ' + arg.split('=')[-1].replace('"', '')
                        # comms[pid] = (path, arg_string)
