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
    _netstat_lock = threading.RLock()
    _netstat_conns = {} # {port: pid}
    _conns = {} # {(src, src_port, dst, dst_port): pid}
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
    return pid == '-' or pid in state._pids

def netstat_online_lookup(src, dst, src_port, dst_port, proto, pid, path, args):
    xs = opensnitch.lib.check_output('ss -tupnH').splitlines()
    for x in xs:
        try:
            _proto, _state, _, _, _src, _dst, _program = x.split()
        except ValueError:
            print('ERROR bad ss line output:', [x])
        else:
            if f'{src}:{src_port}' == _src and f'{dst}:{dst_port}' == _dst:
                pid = _program.split('pid=')[-1].split(',')[0]
                try:
                    path, *args = opensnitch.lib.check_output('ps --no-heading -o args', pid).split()
                    args = ' '.join(args)
                except subprocess.CalledProcessError:
                    pass # the pid could be gone by ps time
    return src, dst, src_port, dst_port, proto, pid, path, args

def _netstat_conns():
    acquired = state._netstat_lock.acquire(blocking=False)
    if acquired:
        try:
            xs = opensnitch.lib.check_output('netstat -lpn').splitlines() # TODO replace netstat with: sudo ss -tupanH
            xs = [x for x in xs if '/' in x.split()[-1]]
            for line in xs:
                cols = line.split()
                port = cols[3].split(':')[-1]
                try:
                    port = int(port)
                except ValueError:
                    continue
                else:
                    pid = cols[-1].split('/')[0]
                    state._netstat_conns[port] = pid
        finally:
            state._netstat_lock.release()

def add_meta(src, dst, src_port, dst_port, proto, pid, path, args):
    # note: meta data has to happen on un-resolved src/dst addresses, ie ipv4 addresses
    if proto in opensnitch.lib.protos:
        if opensnitch.dns.get_hostname(dst) == 'localhost' and opensnitch.dns.get_hostname(src) != 'localhost':
            try:
                with state._lock:
                    pid = state._netstat_conns[dst_port]
                    path, args = state._pids[pid]
            except KeyError:
                opensnitch.lib.run_thread(_netstat_conns) # if we miss on a listening server, lookup all listening pids
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
    state._pids.pop(pid, None)
    ports = {_pid: _port for _port, _pid in state._netstat_conns.items()}
    state._netstat_conns.pop(ports.get(pid), None)

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
            try:
                callback(*line.split())
            except TypeError:
                # log(f'WARN bad {name} line {[line]}')
                pass
    log(f'FATAL tail {name} exited prematurely')
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
