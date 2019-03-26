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

import subprocess
import threading
import os
import functools
import logging
import signal
import sys
import time

def check_call(*a):
    subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

def check_output(*a):
    return subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()

def run_thread(fn, *a, **kw):
    obj = threading.Thread(target=exceptions_kill_parent(fn), args=a, kwargs=kw)
    obj.daemon = True
    obj.start()

def exceptions_kill_parent(decoratee):
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

def monitor(proc):
    while True:
        if proc.poll() is not None:
            logging.error('bpftrace exited prematurely')
            sys.exit(1)
        time.sleep(1)
    logging.error('_monitor exited prematurely')
    sys.exit(1)
