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
