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

import traceback
import opensnitch.lib
import opensnitch.trace
import os
import queue
import sys
import time
from opensnitch.lib import log

_actions = {'allow', 'deny'}
_rules_file = '/etc/opensnitch.rules'

class state:
    _rules = {}
    _queue = queue.Queue(1024)
    _delay_queue = queue.Queue(1024)
    _prompt_queue = queue.Queue(1024)

def start():
    _load_permanent_rules()
    opensnitch.lib.run_thread(_gc)
    opensnitch.lib.run_thread(_process_queue)
    opensnitch.lib.run_thread(_process_delay_queue)
    opensnitch.lib.run_thread(_process_prompt_queue)

def enqueue(finalize, conn):
    repeats = 0
    state._queue.put((finalize, conn, repeats))

def match_rule(_src, dst, _src_port, dst_port, proto, _pid, path, args):
    keys = [(dst, dst_port, proto, path, args), # addr, port, path, args
            (dst, dst_port, proto, path, '-'),  # addr, port, path
            (dst, dst_port, proto, '-', '-'),   # addr, port
            (dst, '-', proto, path, args),      # addr, path, args
            (dst, '-', proto, path, '-'),       # addr, path
            (dst, '-', proto, '-', '-')]        # addr
    for k in keys:
        try:
            return state._rules[k]
        except KeyError:
            pass

def check(finalize, conn):
    conn = opensnitch.dns.resolve(*conn)
    rule = match_rule(*conn)
    if rule:
        action, _duration, _start = rule
        finalize(action, conn)
    else:
        state._prompt_queue.put((finalize, conn))

def _add_rule(action, duration, start, dst, dst_port, proto, path, args):
    k = dst, dst_port, proto, path, args
    v = action, duration, start
    state._rules[k] = v

def _gc():
    while True:
        pids = {pid for pid in os.listdir('/proc') if pid.isdigit()}
        for k, (action, duration, start) in list(state._rules.items()):
            dst, dst_port, proto, path, args = k
            if isinstance(duration, int) and time.monotonic() - start > duration:
                log(f'info: gc expired rule: {action} {dst} {dst_port} {proto} {path} {args}')
                del state._rules[k]
            if isinstance(duration, str) and duration != 'forever' and duration not in pids:
                log(f'info: gc rule for pid {duration} expired: {action} {dst} {dst_port} {proto} {path} {args}')
                del state._rules[k]
        time.sleep(3)
    log('fatal: rules gc exited prematurely')
    sys.exit(1)

def _process_queue():
    while True:
        finalize, conn, repeats = state._queue.get()
        try:
            if repeats < 100: # TODO instead of polling should we react to trace events?
                conn = opensnitch.trace.add_meta(*conn)
                if repeats:
                    log(f'debug: resolved meta after spinning {repeats} times for: {opensnitch.dns.format(*conn)}')
            else:
                log(f'debug: gave up trying to add meta to: {opensnitch.dns.format(*conn)}')
        except KeyError:
            state._delay_queue.put((finalize, conn, repeats + 1))
        else:
            check(finalize, conn)
    log('fatal: rules process-queue exited prematurely')
    sys.exit(1)

def _process_delay_queue():
    while True:
        time.sleep(.0001)
        state._queue.put(state._delay_queue.get())
    log('fatal: rules process-delay-queue exited prematurely')
    sys.exit(1)

def _parse_rule(line):
    try:
        action, dst, dst_port, proto, path, args = line.split(None, 5)
    except ValueError:
        log(f'error: invalid rule, should have been "action dst dst_port proto path args", was: {line}')
        traceback.print_exc()
        return
    try:
        if dst_port != '-':
            dst_port = int(dst_port)
    except ValueError:
        log(f'error: invalid rule: {line}')
        log(f'error: ports should be numbers, was: {dst_port}')
        return
    if proto not in opensnitch.lib.protos:
        log(f'error: invalid rule: {line}')
        log(f'error: bad proto, should be one of {opensnitch.lib.protos}, was: {proto}')
        return
    if action not in _actions:
        log(f'error: invalid rule: {line}')
        log(f'error: bad action, should be one of {_actions}, was: {action}')
        return
    return action, dst, dst_port, proto, path, args

def _load_permanent_rules():
    try:
        with open(_rules_file) as f:
            lines = reversed(f.read().splitlines()) # lines at top of file are higher priority
    except FileNotFoundError:
        with open(_rules_file, 'w') as f:
            lines = []
    i = 0
    lines = [l.split('#')[-1] for l in lines]
    lines = [l for l in lines if l.strip()]
    for i, line in enumerate(lines):
        rule = _parse_rule(line)
        if rule:
            action, dst, dst_port, proto, path, args = rule
            duration = start = None
            _add_rule(action, duration, start, dst, dst_port, proto, path, args)
    for i, ((dst, dst_port, proto, path, args), (action, _, _)) in enumerate(sorted(state._rules.items(), key=str)):
        log(f'info: loaded rule: {action} {dst} {dst_port} {proto} {path} {args}')
        if i > 20:
            log('info: stopped logging rules...')
            break
    if list(lines):
        log(f'info: loaded {i + 1} rules from: {_rules_file}')

def _process_prompt_queue():
    while True:
        finalize, conn = state._prompt_queue.get()
        if not opensnitch.trace.is_alive(*conn):
            finalize('deny', conn)
        else:
            rule = match_rule(*conn)
            if rule:
                action, _duration, _start = rule
                finalize(action, conn)
            else:
                try:
                    duration, scope, action, granularity = opensnitch.lib.check_output(f'DISPLAY=:0 opensnitch-prompt "{opensnitch.dns.format(*conn)}" 2>/dev/null').split()
                except:
                    log('error: failed run opensnitch-prompt')
                    finalize('deny', conn)
                else:
                    action = _process_rule(conn, duration, scope, action, granularity)
                    finalize(action, conn)
    log('fatal: process-prompt-queue exited prematurely')
    sys.exit(1)

def _process_rule(conn, duration, scope, action, granularity):
    _src, dst, _src_port, dst_port, proto, pid, path, args = conn
    if granularity == 'just-path':
        args = '-'
    args = args or '-'
    if duration == 'once':
        return action
    else:
        _duration = duration
        if duration == 'until-quit':
            duration = pid
        elif '-minute' in duration:
            minutes = int(duration.split('-')[0])
            duration = 60 * minutes
        elif duration == 'forever':
            duration = None
        if scope == 'domain':
            dst_port = '-'
        start = time.monotonic()
        _add_rule(action, duration, start, dst, dst_port, proto, path, args)
        if duration is None:
            with open(_rules_file, 'a') as f:
                f.write(f'{action} {dst} {dst_port} {proto} {path} {args}\n')
            log(f'info: add permanent rule: {action} {dst} {dst_port} {proto} {path} {args}')
        else:
            log(f'info: add temporary rule: {action} {_duration} {dst} {dst_port} {proto} {path} {args}')
        return action
