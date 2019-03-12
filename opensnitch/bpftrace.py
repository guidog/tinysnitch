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
import logging
import sys
import functools
import os
import signal

state = {}


def exceptions_kill_parent(decoratee):
    exit1 = lambda: os.kill(os.getpid(), signal.SIGTERM)
    @functools.wraps(decoratee)
    def f(*a, **kw):
        try:
            return decoratee(*a, **kw)
        except SystemExit:
            exit1()
        except:
            logging.exception('')
            exit1()
    return f

def start():
    state['proc'] = subprocess.Popen(['opensnitch-bpftrace-inet-connect'], stdout=subprocess.PIPE)

def monitor():
    proc = state['proc']
    while True:
        if not proc.is_alive():
            logging.error('bpftrace exited prematurely')
            sys.exit(1)

def tail():
    proc = state['proc']
    while True:
        line = proc.readline()
        if not line:
            break
        line = line.rstrip()
        token, line = line.split(': ', 1)
        if token == 'inet: ':
            pid, comm, saddr, sport, daddr, dport = line.split()
        elif token == 'exec: ':
            path, args = line.split(None, 1)
    logging.error('bpftrace exited prematurely')
    sys.exit(1)
