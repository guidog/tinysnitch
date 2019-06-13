# This file is part of tinysnitch, formerly known as OpenSnitch.
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
import tinysnitch.lib
import subprocess
import sys
import threading
import time
import queue
from tinysnitch.lib import log

_queue_size = 1024 * 1024

class state:
    _lock = threading.RLock()
    _pids = {} # {pid: (path, args)}
    _listening_lock = threading.RLock()
    _listening_conns = {} # {port: pid}
    _conns = {} # {(src, src_port, dst, dst_port): pid}
    _gc_queue = queue.Queue(_queue_size)
    _gc_exit_queue = queue.Queue(_queue_size)

def start():
    _load_existing_pids()
    tinysnitch.lib.run_thread(_gc)
    _pairs = [('tinysnitch-bpftrace-tcp', _cb_tcp_udp),
              ('tinysnitch-bpftrace-udp', _cb_tcp_udp),
              ('tinysnitch-bpftrace-fork', _cb_fork),
              ('tinysnitch-bpftrace-exit', _cb_exit),
              ('tinysnitch-bcc-execve', _cb_execve)]
    for program, cb in _pairs:
        proc = subprocess.Popen(['stdbuf', '-o0', program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tinysnitch.lib.run_thread(tinysnitch.lib.monitor, proc)
        tinysnitch.lib.run_thread(_tail, program, proc, cb)

def rm_conn(src, dst, src_port, dst_port, _proto, _pid, _path, _args):
    state._gc_queue.put((src, src_port, dst, dst_port))

def is_alive(_src, _dst, _src_port, _dst_port, _proto, pid, _path, _args):
    return pid == '-' or pid in state._pids

def online_meta_lookup(src, dst, src_port, dst_port, proto, pid, path, args):
    xs = tinysnitch.lib.check_output('ss -tupnH').splitlines()
    for x in xs:
        try:
            _proto, _state, _, _, _src, _dst, _program = x.split()
        except ValueError:
            print('ERROR bad ss line output:', [x])
        else:
            if f'{src}:{src_port}' == _src and f'{dst}:{dst_port}' == _dst:
                pid = _program.split('pid=')[-1].split(',')[0]
                try:
                    path, *args = tinysnitch.lib.check_output('ps --no-heading -o args', pid).split()
                    path = _resolve_relative_path(pid, path)
                    args = ' '.join(args)
                except subprocess.CalledProcessError:
                    pass # the pid could be gone by ps time
    return src, dst, src_port, dst_port, proto, pid, path, args

def _listening_conns():
    acquired = state._listening_lock.acquire(blocking=False) # only run one of these a time, the others just immediately exit
    if acquired:
        try:
            xs = tinysnitch.lib.check_output('ss -tuplnH').splitlines()
            for x in xs:
                try:
                    _proto, _state, _, _, src, dst, program = x.split()
                    port = src.split(':')[-1]
                    port = int(port)
                    pid = program.split('pid=')[-1].split(',')[0]
                    state._listening_conns[port] = pid
                except:
                    print('ERROR bad ss -l output', [x])
        finally:
            state._listening_lock.release()

def add_meta(src, dst, src_port, dst_port, proto, pid, path, args):
    # note: meta data has to happen on un-resolved src/dst addresses, ie ipv4 addresses
    if proto in tinysnitch.lib.protos:
        if tinysnitch.dns.is_localhost(dst):
            try:
                with state._lock:
                    pid = state._listening_conns[dst_port]
                    path, args = state._pids[pid]
            except KeyError:
                tinysnitch.lib.run_thread(_listening_conns) # if we miss on a listening server, lookup all listening pids
                raise
        else:
            with state._lock:
                pid = state._conns[(src, src_port, dst, dst_port)]
                path, args = state._pids[pid]
    return src, dst, src_port, dst_port, proto, pid, path, args

def _cb_execve(pid, path, *args):
    state._pids[pid] = path, ' '.join(args)

def _cb_tcp_udp(pid, src, src_port, dst, dst_port):
    k = src, int(src_port), dst, int(dst_port)
    state._conns[k] = pid

def _cb_exit(pid):
    state._gc_exit_queue.put(pid)

def _cb_fork(pid, child_pid):
    with state._lock:
        if pid in state._pids:
            state._pids[child_pid] = state._pids[pid]

def _gc():
    lru_size = int(_queue_size / 2)
    while True:
        # gc exits
        size = state._gc_exit_queue.qsize()
        for _ in range(min(0, size - lru_size)):
            pid = state._gc_exit_queue.get()
            ports = {_pid: _port for _port, _pid in state._listening_conns.items()}
            with state._lock:
                state._pids.pop(pid, None)
                state._listening_conns.pop(ports.get(pid), None)
        # gc conns
        size = state._gc_queue.qsize()
        for _ in range(min(0, size - lru_size)):
            src, src_port, dst, dst_port = state._gc_queue.get()
            state._conns.pop((src, src_port, dst, dst_port), None)
        time.sleep(15)
    log('ERROR trace gc exited prematurely')
    sys.exit(1)

def _tail(name, proc, callback):
    log(f'INFO start tailing {name}')
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            log(f'WARN failed to utf-8 decode {name} line {[line]}')
        else:
            if not line:
                break
            elif line.startswith('fatal error:'):
                log(f'FATAL {name} {line}')
                sys.exit(1)
            else:
                try:
                    callback(*line.split())
                except TypeError:
                    log(f'WARN bad {name} line {[line]}')
    log(f'FATAL tail {name} exited prematurely')
    sys.exit(1)

def _resolve_relative_path(pid, path):
    if '/' not in path:
        try:
            path = tinysnitch.lib.check_output(f'sudo ls -l /proc/{pid}/exe 2>/dev/null').split(' -> ')[-1]
        except subprocess.CalledProcessError:
            pass
    return path

def _load_existing_pids():
    xs = tinysnitch.lib.check_output('ps -eo pid,args --no-heading').splitlines()
    xs = (x.split(None, 1) for x in xs)
    xs = ((pid, path) for pid, path in xs if not path.startswith('['))
    for pid, path in xs:
        path, *args = path.split()
        path = _resolve_relative_path(pid, path)
        print('DEBUG: load existing pid:', pid, path, *args)
        _cb_execve(pid, path, *args)
