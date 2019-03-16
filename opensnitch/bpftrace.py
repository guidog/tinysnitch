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
        logging.info(f'bpftrace got: {line}')
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
                pids[(daddr, int(dport), saddr, int(sport))] = pid, time.monotonic()
                # logging.info(f'bpftrace: {line}')
    logging.error('tail exited prematurely')
    sys.exit(1)

def start():
    for trace in ['tcp', 'udp']:
        proc = subprocess.Popen(['sudo', 'stdbuf', '-o0', f'opensnitch-bpftrace-{trace}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_thread(_monitor, proc)
        run_thread(_tail, proc)
        logging.info(f'started trace: {trace}')
