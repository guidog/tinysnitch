# This file is part of tinysnitch, formerly known as OpenSnitch.
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
import tinysnitch.lib
import os
import queue
import sys
import time
from tinysnitch.lib import log

assert '1' == tinysnitch.lib.check_output('ls /home | wc -l') or 'TINYSNITCH_PROMPT_USER' in os.environ, 'in a multi-user environment please specify the user to display X11 prompts as via env variable $TINYSNITCH_PROMPT_USER'
_prompt_user = os.environ.get('TINYSNITCH_PROMPT_USER', tinysnitch.lib.check_output('ls /home | head -n1'))
_actions = {'allow', 'deny'}

class state:
    rules_file = None
    _rules = {}
    _prompt_queue = queue.Queue(1024)

def start():
    _load_permanent_rules()
    tinysnitch.lib.run_thread(_gc)
    tinysnitch.lib.run_thread(_process_prompt_queue)

def match_rule(_src, dst, _src_port, dst_port, proto):
    if proto not in tinysnitch.lib.protos:
        return 'allow', None, None # allow all non tcp/udp
    else:
        dst_wildcard_subdomains = '*.' + '.'.join(dst.split('.')[-2:])
        keys = [
            (dst, dst_port, proto),
            (dst, '-', proto),
            (dst_wildcard_subdomains, dst_port, proto),
            (dst_wildcard_subdomains, '-', proto),
        ]
        for k in keys:
            try:
                return state._rules[k]
            except KeyError:
                pass

def check(finalize, conn):
    conn = tinysnitch.dns.resolve(*conn)
    _src, dst, _src_port, dst_port, _proto = conn
    rule = match_rule(*conn)
    if rule:
        action, _duration, _start = rule
        finalize(action, conn)
    else:
        state._prompt_queue.put((finalize, conn))

def _add_rule(action, duration, start, dst, dst_port, proto):
    k = dst, dst_port, proto
    v = action, duration, start
    state._rules[k] = v

def _gc():
    while True:
        for k, (action, duration, start) in list(state._rules.items()):
            dst, dst_port, proto = k
            if isinstance(duration, int) and time.monotonic() - start > duration:
                log(f'INFO gc expired rule {action} {dst} {dst_port} {proto}')
                del state._rules[k]
        time.sleep(3)
    log('FATAL rules gc exited prematurely')
    sys.exit(1)

def _parse_rule(line):
    try:
        action, dst, dst_port, proto = line.split(None, 3)
    except ValueError:
        log(f'ERROR invalid rule, should have been "action dst dst_port proto", was {line}')
        traceback.print_exc()
        return
    try:
        if dst_port != '-':
            dst_port = int(dst_port)
    except ValueError:
        log(f'ERROR invalid rule {line}')
        log(f'ERROR ports should be numbers, was {dst_port}')
        return
    if proto not in tinysnitch.lib.protos:
        log(f'ERROR invalid rule {line}')
        log(f'ERROR bad proto, should be one of {tinysnitch.lib.protos}, was {proto}')
        return
    if action not in _actions:
        log(f'ERROR invalid rule {line}')
        log(f'ERROR bad action, should be one of {_actions}, was {action}')
        return
    return action, dst, dst_port, proto

def _load_permanent_rules():
    try:
        with open(state.rules_file) as f:
            lines = reversed(f.read().splitlines()) # lines at top of file are higher priority
    except FileNotFoundError:
        with open(state.rules_file, 'w') as f:
            lines = []
    i = 0
    lines = [l.split('#')[-1] for l in lines]
    lines = [l for l in lines if l.strip()]
    for i, line in enumerate(lines):
        rule = _parse_rule(line)
        if rule:
            action, dst, dst_port, proto = rule
            duration = start = None
            _add_rule(action, duration, start, dst, dst_port, proto)
            log(f'INFO loaded rule {action} {dst} {dst_port} {proto}')
    if list(lines):
        log(f'INFO loaded {i + 1} rules from {state.rules_file}')

def _prompt(finalize, conn, prompt_conn):
    # we match rule again here in case a rule was added while this conn was waiting in the queue
    rule = match_rule(*conn)
    if rule:
        action, _duration, _start = rule
        if action == 'deny':
            finalize('deny', conn)
            return 'deny'
        else:
            return 'allow'
    else:
        formatted = tinysnitch.dns.format(*prompt_conn)
        formatted = formatted.replace('$', '\$').replace('(', '\(').replace(')', '\)').replace('`', '\`')
        try:
            duration, subdomains, action, ports = tinysnitch.lib.check_output(f'su {_prompt_user} -c \'DISPLAY=:0 tinysnitch-prompt "{formatted}"\' 2>/tmp/tinysnitch_prompt.log').split()
        except:
            log('ERROR failed to run tinysnitch-prompt\n' + tinysnitch.lib.check_output('cat /tmp/tinysnitch_prompt.log || true'))
            finalize('deny', conn)
            return 'deny'
        else:
            action = _process_rule(conn, duration, subdomains, action, ports)
            if action == 'deny':
                finalize('deny', conn)
                return 'deny'
            else:
                return 'allow'

def _process_prompt_queue():
    while True:
        finalize, conn = state._prompt_queue.get()
        _src, dst, _src_port, dst_port, _proto = conn
        action = _prompt(finalize, conn, conn)
        finalize(action, conn)
    log('FATAL process-prompt-queue exited prematurely')
    sys.exit(1)

def _process_rule(conn, duration, subdomains, action, ports):
    _src, dst, _src_port, dst_port, proto = conn
    if ports == "no":
        dst_port = '-'
    if duration == 'once':
        return action
    else:
        _duration = duration
        if '-minute' in duration:
            minutes = int(duration.split('-')[0])
            duration = 60 * minutes
        elif duration == 'forever':
            duration = None
        if subdomains == 'yes':
            dst = '*.' + '.'.join(dst.split('.')[-2:])
        start = time.monotonic()
        _add_rule(action, duration, start, dst, dst_port, proto)
        if duration is None:
            with open(state.rules_file, 'a') as f:
                f.write(f'{action} {dst} {dst_port} {proto}\n')
            log(f'INFO add permanent rule {action} {dst} {dst_port} {proto}')
        else:
            log(f'INFO add temporary rule {action} {_duration} {dst} {dst_port} {proto}')
        return action
