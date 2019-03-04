# This file is part of OpenSnitch.
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
import collections
import threading
import logging
import re

def write_file(path, value, mode="w"):
    with open(path, mode) as f:
        return f.write(value)

probe_name = "opensnitch_sys_execve"

pids = collections.defaultdict(dict)

def enable():
    disable()
    logging.info("Enabling ProcMon ...")
    for d in ('sched_process_fork', 'sched_process_exec', 'sched_process_exit'):

        write_file(f"/sys/kernel/debug/tracing/events/sched/{d}/enable", "1")
    # Create the custom execve kprobe consumer
    # Command line args will be in %si, we're asking ftrace for them
    with open("/sys/kernel/debug/tracing/kprobe_events", "w") as f:
        f.write(f"p:kprobes/{probe_name} sys_execve")
        for i in range(1, 16):
            f.write(f" arg{i}=+0(+{i * 8}(%si)):string")
    write_file(f"/sys/kernel/debug/tracing/events/kprobes/{probe_name}/enable", "1")

def disable():
    logging.info("Disabling ProcMon ...")
    try:
        for d in ('sched_process_fork', 'sched_process_exec', 'sched_process_exit'):
            write_file(f"/sys/kernel/debug/tracing/events/sched/{d}/enable", "0")
        write_file(f"/sys/kernel/debug/tracing/events/kprobes/{probe_name}/enable", "0")
        write_file(f"/sys/kernel/debug/tracing/kprobe_events", "-:{probe_name}", mode="a+")
        write_file("/sys/kernel/debug/tracing/trace", "")
    except:
        logging.exception('?')

def is_ftrace_available():
    try:
        with open("/proc/sys/kernel/ftrace_enabled", "rt") as fp:
            return fp.read().strip() == '1'
    except:
        pass
    return False

def get_app(pid):
    return pids[pid] or None

def _on_exec(pid, filename):
    p = pids[pid]
    p['filename'] = filename
    logging.debug("(pid=%d) %s %s", pid, filename, p.get('args', ''))

def _on_args(pid, args):
    pids[pid]['args'] = args

def _on_exit(pid):
    try:
        del pids[pid]
    except KeyError:
        logging.info(f'missed: {pid}')

def _run():
    logging.info("ProcMon running ...")
    with open("/sys/kernel/debug/tracing/trace_pipe", 'rb') as pipe:
        pn = probe_name.encode()
        while True:
            try:
                line = pipe.readline()
                if pn in line:
                    m = re.search(b'^.*?\-(\d+)\s*\[', line)
                    if m is None:
                        continue
                    pid = int(m.group(1))
                    # "walk" over every argument field, 'fault' is our terminator.  # noqa
                    # If we see it it means that there are more cmdline args.  # noqa
                    if b'(fault)' in line:
                        line = line[:line.find(b'(fault)')]
                    args = b' '.join(
                        re.findall(b'arg\d+="(.*?)"', line))
                    _on_args(pid, args.decode())
                else:
                    m = re.search(b'sched_process_(.*?):', line)
                    if m is None:
                        continue
                    event = m.group(1)
                    if event == b'exec':
                        filename = re.search(
                            b'filename=(.*?)\s+pid=', line).group(1)
                        pid = int(
                            re.search(b'\spid=(\d+)', line).group(1))
                        _on_exec(pid, filename.decode())
                    elif event == b'exit':
                        mm = re.search(
                            b'\scomm=(.*?)\s+pid=(\d+)', line)
                        # command = mm.group(1)
                        pid = int(mm.group(2))
                        _on_exit(pid)
            except Exception as e:
                logging.warning(e)

def run():
    obj = threading.Thread(target=_run)
    obj.daemon = True
    obj.start()
