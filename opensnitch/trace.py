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
import opensnitch.lib
import subprocess
import sys
import threading
import time
import queue
from opensnitch.lib import log

class state:
    _lock = threading.RLock()
    _pids = {} # {pid: (path, args)}
    _conns = {} # {(src, src_port, dst, dst_port): (pid, time)}
    _cleanup_queue = queue.Queue(1024 * 1024)

def start():
    _load_existing_pids()
    opensnitch.lib.run_thread(_gc)
    _pairs = [('opensnitch-bpftrace-tcp', _cb_tcp_udp),
              ('opensnitch-bpftrace-udp', _cb_tcp_udp),
              ('opensnitch-bpftrace-fork', _cb_fork),
              ('opensnitch-bpftrace-exit', _cb_exit),
              ('opensnitch-bcc-execve', _cb_execve)]
    for program, cb in _pairs:
        proc = subprocess.Popen(['stdbuf', '-o0', program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        opensnitch.lib.run_thread(opensnitch.lib.monitor, proc)
        opensnitch.lib.run_thread(_tail, program, proc, cb)

def rm_conn(src, dst, src_port, dst_port, _proto, _pid, _path, _args):
    state._cleanup_queue.put((src, src_port, dst, dst_port, time.monotonic()))

def is_alive(_src, _dst, _src_port, _dst_port, _proto, pid, _path, _args):
    return pid in state._pids

def add_meta(src, dst, src_port, dst_port, proto, _pid, _path, _args):
    # TODO add meta for the server pid on incoming connections. tcp can be seen
    # via opensnitch-bpftrace-tcp-accept, udp can be seen via
    # opensnitch-bpftrace-udp with source and dest address as 0.0.0.0
    if proto in opensnitch.lib.protos:
        with state._lock:
            pid, _ = state._conns[(src, src_port, dst, dst_port)]
            path, args = state._pids[pid]
    return src, dst, src_port, dst_port, proto, pid, path, args

def _cb_execve(pid, path, *args):
    state._pids[pid] = path, ' '.join(args)

def _cb_tcp_udp(pid, src, src_port, dst, dst_port):
    k = src, int(src_port), dst, int(dst_port)
    start = time.monotonic()
    state._conns[k] = pid, start

def _cb_exit(pid):
    state._pids.pop(pid, None)

def _cb_fork(pid, child_pid):
    with state._lock:
        if pid in state._pids:
            state._pids[child_pid] = state._pids[pid]

def _gc():
    grace_seconds = 5 # TODO ideal value?
    while True:
        now = time.monotonic()
        for _ in range(state._cleanup_queue.qsize()):
            src, src_port, dst, dst_port, start = state._cleanup_queue.get()
            if now - start > grace_seconds: # sometimes dns request reuse the same port, so a grace period before cleanup
                state._conns.pop((src, src_port, dst, dst_port), None)
            else:
                state._cleanup_queue.put((src, src_port, dst, dst_port, start))
        time.sleep(grace_seconds)
    log('error: trace gc exited prematurely')
    sys.exit(1)

def _tail(name, proc, callback):
    log(f'info: start tailing: {name}')
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            log(f'warn: failed to utf-8 decode {name} line: {[line]}')
        else:
            if not line:
                break
            try:
                callback(*line.split())
            except TypeError:
                pass # log(f'warn: bad {name} line: {[line]}')
    log(f'fatal: tail {name} exited prematurely')
    sys.exit(1)

def _load_existing_pids():
    xs = opensnitch.lib.check_output('ps -ef | sed 1d').splitlines()
    xs = (x.split(None, 7) for x in xs)
    xs = ((pid, path) for uid, pid, ppid, c, stime, tty, time, path in xs)
    xs = ((pid, path) for pid, path in xs if not path.startswith('['))
    for pid, path in xs:
        path, *args = path.split()
        if '/' not in path:
            try:
                path = opensnitch.lib.check_output(f'sudo ls -l /proc/{pid}/exe 2>/dev/null').split(' -> ')[-1]
            except subprocess.CalledProcessError:
                pass
        _cb_execve(pid, path, *args)
