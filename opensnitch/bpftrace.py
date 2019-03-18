# This file is part of OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
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

import time
import subprocess
import threading
import logging
import sys
import functools
import os
import signal

seconds = 15
pids = {}
paths = {}

def _exceptions_kill_parent(decoratee):
    pid = os.getpid()
    @functools.wraps(decoratee)
    def decorated(*a, **kw):
        try:
            return decoratee(*a, **kw)
        except SystemExit:
            os.kill(pid, signal.SIGTERM)
        except:
            logging.exception('')
            os.kill(pid, signal.SIGTERM)
    return decorated

def run_thread(fn, *a, **kw):
    obj = threading.Thread(target=_exceptions_kill_parent(fn), args=a, kwargs=kw)
    obj.daemon = True
    obj.start()

def _monitor(proc):
    while True:
        if proc.poll() is not None:
            logging.error('bpftrace exited prematurely')
            sys.exit(1)
        time.sleep(1)
    logging.error('_monitor exited prematurely')
    sys.exit(1)

def _tail_tcp_udp(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8').rstrip()
        if not line:
            break
        try:
            token, line = line.split(': ', 1)
        except ValueError:
            logging.info(f'bpftrace skipping: {line.rstrip()}')
        else:
            try:
                pid, _comm, saddr, sport, daddr, dport = line.split()
            except ValueError:
                logging.error(f'bad bpftrace line: {[line]}')
            else:
                sport, dport = int(sport), int(dport)
                start = time.monotonic()
                pids[(daddr, dport, saddr, sport)] = pid, start
                pids[(saddr, sport, daddr, dport)] = pid, start
                # logging.info(f'bpftrace: {line}')
    logging.error('tail exited prematurely')
    sys.exit(1)

def _gc():
    while True:
        now = time.monotonic()
        for k, (_pid, start) in list(pids.items()):
            if now - start > seconds:
                del pids[k]
        time.sleep(1)
    logging.error('gc exited prematurely')
    sys.exit(1)

def start():
    run_thread(_gc)
    for trace, tail in [('tcp', _tail_tcp_udp), ('udp', _tail_tcp_udp)]:
        proc = subprocess.Popen(['sudo', 'stdbuf', '-o0', f'opensnitch-bpftrace-{trace}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_thread(_monitor, proc)
        run_thread(tail, proc)
        logging.info(f'started trace: {trace}')

# def tail():
#     with open(events_pipe_file, 'rb') as pipe:
#         for line in pipe:
#             parts = line.split()
#             try:
#                 name_pid, _, _, _, probe, *rest = parts
#             except ValueError:
#                 logging.error(f'not enough parts: {line}')
#                 continue
#             try:
#                 pid = name_pid.split(b'-')[-1].decode('utf-8')
#                 if b'opensnitch_exec_probe:' == probe:
#                     arg_string = [b' ']
#                     comm = rest[1].split(b'=')[-1].replace(b'"', b'').decode('utf-8')
#                     for r in rest[2:]:
#                         r = r.split(b'=')[-1]
#                         if r == b'(fault)':
#                             break
#                         arg_string.append(r)
#                     arg_string = b' '.join(arg_string).replace(b'"', b'').decode('utf-8')
#                     comms[pid] = (comm, arg_string)
#                 elif b'sched_process_exit:' == probe:
#                     comms.pop(pid, None)
#                     filenames.pop(pid, None)
#                 elif b'sched_process_exec:' == probe:
#                     filename, _pid, _old_pid = rest
#                     filename = filename.split(b'=')[-1].decode('utf-8')
#                     filenames[pid] = filename
#                 elif b'sched_process_fork:' == probe:
#                     comm, _pid, _child_comm, child_pid = rest
#                     comm = comm.split(b'=')[-1].decode('utf-8')
#                     child_pid = child_pid.split(b'=')[-1].decode('utf-8')
#                     try:
#                         comms[child_pid] = comms[pid]
#                     except KeyError:
#                         comms[child_pid] = comm, ''
#                     try:
#                         filenames[child_pid] = filenames[pid]
#                     except KeyError:
#                         pass
#             except UnicodeDecodeError:
#                 logging.error(f'failed to utf-8 decode kprobe line: {line}')

def tail_execve(proc):
    while True:
        line = proc.stdout.readline().rstrip().decode('utf-8')
        if not line:
            break
        try:
            pid, path, *args = line.split()
        except ValueError:
            logging.error(f'bad execve line: {[line]}')
        else:
            paths[pid] = (path, args)
            logging.info(f'execve: {line}')
    logging.error('tail execve prematurely')
    sys.exit(1)

def tail_exit(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            pid, path = line.split(None, 1)
        except ValueError:
            logging.error(f'bad exit line: {[line]}')
        else:
            paths.pop(pid, None)
    logging.error('tail exited prematurely')
    sys.exit(1)

def tail_fork(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            pid, path = line.split(None, 1)
        except ValueError:
            logging.error(f'bad fork line: {[line]}')
        else:
            ...
    logging.error('tail fork prematurely')
    sys.exit(1)
