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

paths = {}
pids = {}

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

def _run_thread(fn, *a, **kw):
    obj = threading.Thread(target=_exceptions_kill_parent(fn), args=a, kwargs=kw)
    obj.daemon = True
    obj.start()

def monitor(proc):
    while True:
        if proc.poll() is not None:
            logging.error('bpftrace exited prematurely')
            sys.exit(1)
        time.sleep(1)
    logging.error('monitor exited prematurely')
    sys.exit(1)

def tail_tcp_udp(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            token, line = line.rstrip().split(': ', 1)
        except ValueError:
            logging.info(f'trace tcp udp skipping: {line.rstrip()}')
        else:
            try:
                pid, _comm, saddr, sport, daddr, dport = line.split()
            except ValueError:
                logging.error(f'bad inet line: {[line]}')
            else:
                pids[(daddr, int(dport), saddr, int(sport))] = pid, time.monotonic()
                # logging.info(f'inet: {line}')
    logging.error('tail exited prematurely')
    sys.exit(1)

def tail_execve(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            token, line = line.rstrip().split(': ', 1)
        except ValueError:
            logging.info(f'trace execve skipping: {line.rstrip()}')
        else:
            try:
                pid, path_and_args = line.split(None, 1)
            except ValueError:
                logging.error(f'bad execve line: {[line]}')
            else:
                paths[pid] = path_and_args
                # logging.info(f'execve: {line}')
    logging.error('tail exited prematurely')
    sys.exit(1)

def tail_exec(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            token, line = line.rstrip().split(': ', 1)
        except ValueError:
            logging.info(f'trace fork skipping: {line.rstrip()}')
        else:
            try:
                pid, path = line.split(None, 1)
            except ValueError:
                logging.error(f'bad fork line: {[line]}')
            else:
                if pid not in paths:
                    paths[pid] = path
    logging.error('tail exited prematurely')
    sys.exit(1)

def tail_exit(proc):
    while True:
        line = proc.stdout.readline().decode('utf-8')
        if not line:
            break
        try:
            token, line = line.rstrip().split(': ', 1)
        except ValueError:
            logging.info(f'trace exit skipping: {line.rstrip()}')
        else:
            try:
                pid, path = line.split(None, 1)
            except ValueError:
                logging.error(f'bad exit line: {[line]}')
            else:
                paths.pop(pid, None)
    logging.error('tail exited prematurely')
    sys.exit(1)

traces = [
    ('execve', tail_execve),
    ('fork', tail_exec),
    ('exec', tail_exec),
    ('tcp', tail_tcp_udp),
    ('udp', tail_tcp_udp),
    # ('exit', tail_exit),
]

def start():
    for trace, tail in traces:
        proc = subprocess.Popen(['sudo', 'stdbuf', '-o0', f'opensnitch-bpftrace-{trace}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _run_thread(monitor, proc)
        _run_thread(tail, proc)
        logging.info(f'started trace: {trace}')
