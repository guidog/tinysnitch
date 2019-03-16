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

import contextlib
import subprocess

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

def tail():
    pipe = open(events_pipe_file, 'rb')
    for line in pipe:
        try:
            print(line.strip().decode('utf-8'))
        except:
            print(line.strip())

def start():
    disable()
    try:
        enable()
        tail()
    finally:
        disable()
