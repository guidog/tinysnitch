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

def _tail(proc):
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
    for trace in ['tcp', 'udp']:
        proc = subprocess.Popen(['sudo', 'stdbuf', '-o0', f'opensnitch-bpftrace-{trace}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_thread(_monitor, proc)
        run_thread(_tail, proc)
        logging.info(f'started trace: {trace}')

# def tail_execve(proc):
#     while True:
#         line = proc.stdout.readline().decode('utf-8')
#         if not line:
#             break
#         try:
#             token, line = line.rstrip().split(': ', 1)
#         except ValueError:
#             logging.info(f'trace execve skipping: {line.rstrip()}')
#         else:
#             try:
#                 pid, path_and_args = line.split(None, 1)
#             except ValueError:
#                 logging.error(f'bad execve line: {[line]}')
#             else:
#                 paths[pid] = path_and_args
#                 # logging.info(f'execve: {line}')
#     logging.error('tail exited prematurely')
#     sys.exit(1)

# def tail_exec(proc):
#     while True:
#         line = proc.stdout.readline().decode('utf-8')
#         if not line:
#             break
#         try:
#             token, line = line.rstrip().split(': ', 1)
#         except ValueError:
#             logging.info(f'trace fork skipping: {line.rstrip()}')
#         else:
#             try:
#                 pid, path = line.split(None, 1)
#             except ValueError:
#                 logging.error(f'bad fork line: {[line]}')
#             else:
#                 if pid not in paths:
#                     paths[pid] = path
#     logging.error('tail exited prematurely')
#     sys.exit(1)

# def tail_exit(proc):
#     while True:
#         line = proc.stdout.readline().decode('utf-8')
#         if not line:
#             break
#         try:
#             token, line = line.rstrip().split(': ', 1)
#         except ValueError:
#             logging.info(f'trace exit skipping: {line.rstrip()}')
#         else:
#             try:
#                 pid, path = line.split(None, 1)
#             except ValueError:
#                 logging.error(f'bad exit line: {[line]}')
#             else:
#                 paths.pop(pid, None)
#     logging.error('tail exited prematurely')
#     sys.exit(1)
