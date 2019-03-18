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
filenames = {}

def run_thread(fn, *a, **kw):
    obj = threading.Thread(target=_exceptions_kill_parent(fn), args=a, kwargs=kw)
    obj.daemon = True
    obj.start()

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

def _monitor(proc):
    while True:
        if proc.poll() is not None:
            logging.error('bpftrace exited prematurely')
            sys.exit(1)
        time.sleep(1)
    logging.error('_monitor exited prematurely')
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
                logging.error(f'bad execve line: {[line]}')
            else:
                filenames[pid] = path, ' '.join(args)
    logging.error('tail execve prematurely')
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
                pid, _comm, saddr, sport, daddr, dport = line.split()
            except ValueError:
                logging.error(f'bad tcp/udp line: {[line]}')
            else:
                sport, dport = int(sport), int(dport)
                start = time.monotonic()
                pids[(daddr, dport, saddr, sport)] = pid, start
                pids[(saddr, sport, daddr, dport)] = pid, start
    logging.error('tail exited prematurely')
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
                filenames.pop(pid, None)
    logging.error('tail exited prematurely')
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
                    filenames[child_pid] = filenames[pid]
                except KeyError:
                    pass
    logging.error('tail fork prematurely')
    sys.exit(1)

pairs = [
    ('opensnitch-bpftrace-tcp', _tail_tcp_udp),
    ('opensnitch-bpftrace-udp', _tail_tcp_udp),
    ('opensnitch-bpftrace-fork', _tail_fork),
    ('opensnitch-bpftrace-exit', _tail_exit),
    ('opensnitch-bcc-execve', _tail_execve),
]

def start():
    run_thread(_gc)
    for program, tail in pairs:
        proc = subprocess.Popen(['sudo', 'stdbuf', '-o0', program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_thread(_monitor, proc)
        run_thread(tail, proc)
        logging.info(f'started trace: {program}')
