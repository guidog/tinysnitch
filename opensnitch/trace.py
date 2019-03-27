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
import logging
import sys
import opensnitch.lib
import subprocess
import threading

class state:
    lock = threading.RLock()
    pids_ttl = 5
    filenames_ttl = 5
    pids = {}
    reverse_pids = set()
    exits = {}
    filenames = {}

    def get_filename(pid):
        path, args = opensnitch.trace.state.filenames[pid]
        return path, args

    def add_filename(pid, path, args):
        state.filenames[pid] = path, args

    def get_pid(src, src_port, dst, dst_port):
        k = src, src_port, dst, dst_port
        pid, _start = state.pids[k]
        return pid

    def add_pid(pid, src, src_port, dst, dst_port):
        src_port, dst_port = int(src_port), int(dst_port)
        start = time.monotonic()
        k1 = src, src_port, dst, dst_port
        k2 = dst, dst_port, src, src_port
        with state.lock:
            state.pids[k1] = pid, start
            state.pids[k2] = pid, start
            state.reverse_pids.add(pid)

    def gc():
        while True:
            now = time.monotonic()
            pids_inflight = opensnitch.rules.state.pids_inflight()
            for k, (pid, start) in list(state.pids.items()):
                if now - start > state.pids_ttl and pid not in pids_inflight:
                    logging.info(f'gc stale pid: {k}')
                    with state.lock:
                        del state.pids[k]
                        state.reverse_pids.discard(pid)
            for pid, start in list(state.exits.items()):
                if now - start > state.filenames_ttl and pid not in pids_inflight:
                    logging.info(f'gc exited pid: {state.filenames[pid]}')
                    with state.lock:
                        del state.exits[pid]
                        del state.filenames[pid]
            time.sleep(1)
        logging.error('trace gc exited prematurely')
        sys.exit(1)

def _tail_execve(proc):
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            logging.error(f'failed to utf-8 decode bpftrace execve line: {[line]}')
        else:
            if not line:
                break
            try:
                pid, path, *args = line.split()
            except ValueError:
                logging.debug(f'bad execve line: {[line]}')
            else:
                state.add_filename(pid, path, ' '.join(args))
    logging.error('tail execve exited prematurely')
    sys.exit(1)

def _tail_tcp_udp(proc):
    proc.stdout.readline()
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            logging.error(f'failed to utf-8 decode bpftrace tcp/udp line: {[line]}')
        else:
            if not line:
                break
            try:
                pid, _comm, src, src_port, dst, dst_port = line.split()
            except ValueError:
                logging.error(f'bad tcp/udp line: {[line]}')
            else:
                state.add_pid(pid, src, src_port, dst, dst_port)
    logging.error('tail tcp/udp exited prematurely')
    sys.exit(1)

def _tail_exit(proc):
    proc.stdout.readline()
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            logging.error(f'failed to utf-8 decode bpftrace exit line: {[line]}')
        else:
            if not line:
                break
            try:
                pid, path = line.split()
            except ValueError:
                logging.error(f'bad exit line: {[line]}')
            else:
                with state.lock:
                    if pid in state.reverse_pids:
                        logging.info(f'exited: {state.filenames[pid]}')
                        state.exits[pid] = time.monotonic()
    logging.error('tail exit exited prematurely')
    sys.exit(1)

def _tail_fork(proc):
    proc.stdout.readline()
    while True:
        try:
            line = proc.stdout.readline().rstrip().decode('utf-8')
        except UnicodeDecodeError:
            logging.error(f'failed to utf-8 decode bpftrace fork line: {[line]}')
        else:
            if not line:
                break
            try:
                pid, child_pid, comm = line.split()
            except ValueError:
                logging.error(f'bad fork line: {[line]}')
            else:
                try:
                    with state.lock:
                        path, args = state.get_filename(pid)
                        state.add_filename(pid, path, args)
                except KeyError:
                    pass
    logging.error('tail fork exited prematurely')
    sys.exit(1)

def _load_existing_pids():
    xs = opensnitch.lib.check_output('ps -ef | sed 1d').splitlines()
    xs = (x.split(None, 7) for x in xs)
    xs = ((pid, path) for uid, pid, ppid, c, stime, tty, time, path in xs)
    xs = ((pid, path) for pid, path in xs if not path.startswith('['))
    for pid, path in xs:
        try:
            path, args = path.split(None, 1)
        except ValueError:
            args = ''
        if '/' not in path:
            try:
                path = opensnitch.lib.check_output(f'sudo ls -l /proc/{pid}/exe 2>/dev/null').split(' -> ')[-1]
            except subprocess.CalledProcessError:
                pass
        state.add_filename(pid, path, args)

pairs = [
    ('opensnitch-bpftrace-tcp', _tail_tcp_udp),
    ('opensnitch-bpftrace-udp', _tail_tcp_udp),
    ('opensnitch-bpftrace-fork', _tail_fork),
    ('opensnitch-bpftrace-exit', _tail_exit),
    ('opensnitch-bcc-execve', _tail_execve),
]

def start():
    _load_existing_pids()
    # opensnitch.lib.run_thread(state.gc)
    for program, tail in pairs:
        proc = subprocess.Popen(['stdbuf', '-oL', program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        opensnitch.lib.run_thread(opensnitch.lib.monitor, proc)
        opensnitch.lib.run_thread(tail, proc)
        logging.info(f'started trace: {program}')
