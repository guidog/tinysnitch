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

from typing import Dict, Tuple, Optional
import traceback
import tinysnitch.lib
import os
import stat
import subprocess
import queue
import sys
import time
import uuid
from tinysnitch.lib import log

assert '1' == tinysnitch.lib.check_output('ls /home | wc -l') or 'TINYSNITCH_PROMPT_USER' in os.environ, 'in a multi-user environment please specify the user to display X11 prompts as via env variable $TINYSNITCH_PROMPT_USER'
_prompt_user = os.environ.get('TINYSNITCH_PROMPT_USER', tinysnitch.lib.check_output('ls /home | head -n1'))
_actions = {'allow', 'deny'}
_ephemeral_port_low, _ephemeral_port_high = [int(port) for port in tinysnitch.lib.check_output('cat /proc/sys/net/ipv4/ip_local_port_range').split()]

class state:
    rules_file = None
    temp_rules_file = None
    adblock_rules_file = None
    _rules: Dict[Tuple[str, str, str], Tuple[str, str, Optional[int]]] = {}
    _prompt_queue: queue.Queue = queue.Queue(1024)

def start():
    tinysnitch.lib.run_thread(_watch_temp_rules)
    tinysnitch.lib.run_thread(_watch_permanent_rules)
    tinysnitch.lib.run_thread(_gc_temporary_rules)
    tinysnitch.lib.run_thread(_process_prompt_queue)

def match_rule(src, dst, src_port, dst_port, proto):
    if proto not in tinysnitch.lib.protos:
        return 'allow', None, None # allow all non tcp/udp
    else:
        dst_wildcard_subdomains = '*.' + '.'.join(dst.split('.')[-2:])
        keys = [
            (dst,                     dst_port, proto),
            (dst,                     '*',      proto),
            (dst_wildcard_subdomains, dst_port, proto),
            (dst_wildcard_subdomains, '*',      proto),
        ]
        if dst.replace('.', '').isdigit():
            a, b, c, d = dst.split('.')
            keys += [
                (f'{a}.{b}.{c}.*', dst_port, proto),
                (f'{a}.{b}.*.*',   dst_port, proto),
                (f'{a}.*.*.*',     dst_port, proto),
                (f'{a}.{b}.{c}.*', '*',      proto),
                (f'{a}.{b}.*.*',   '*',      proto),
                (f'{a}.*.*.*',     '*',      proto),
            ]
        for k in keys:
            try:
                matched = state._rules[k]
                # log(f'matched rule: {k} {tinysnitch.dns.format(src, dst, src_port, dst_port, proto)}')
                return matched
            except KeyError:
                pass

def check(finalize, conn):
    conn = tinysnitch.dns.resolve(*conn)
    src, dst, src_port, dst_port, proto = conn
    if (
        not tinysnitch.dns.is_localhost(src)
        and tinysnitch.dns.is_localhost(dst)
        and dst_port != '*'
        and _ephemeral_port_low <= dst_port <= _ephemeral_port_high
    ):
        src, dst, src_port, dst_port = dst, src, dst_port, src_port # check return inbound connections on ephemeral ports as if it were outbound traffic
    conn = src, dst, src_port, dst_port, proto
    rule = match_rule(*conn)
    if rule:
        action, _duration, _start = rule
        finalize(action, conn)
    else:
        state._prompt_queue.put((finalize, conn))

def _add_rule(action, duration, start, dst, dst_port, proto, nolog=False):
    k = dst, dst_port, proto
    v = action, duration, start
    if state._rules.get(k) != v:
        state._rules[k] = v
        if not nolog:
            log(f'INFO added rule {action} {dst} {dst_port} {proto}')

def _gc_temporary_rules():
    while True:
        for k, (action, duration, start) in list(state._rules.items()):
            dst, dst_port, proto = k
            if isinstance(duration, int) and time.monotonic() - start > duration:
                log(f'INFO gc expired rule {action} {dst} {dst_port} {proto}')
                del state._rules[k]
        time.sleep(1)
    log('FATAL rules gc exited prematurely')
    sys.exit(1)

def _parse_rule(line):
    try:
        action, dst, dst_port, proto = line.split(None, 3)
    except ValueError:
        log(f'ERROR invalid rule, should have been "action dst dst_port proto", was {line}\n{traceback.format_exc()}')
        return
    try:
        if dst_port != '*':
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

def _watch_temp_rules():
    while True:
        tempfile = f'/tmp/{uuid.uuid4()}'
        try:
            os.rename(state.temp_rules_file, tempfile)
        except FileNotFoundError:
            time.sleep(1)
        else:
            with open(tempfile) as f:
                for line in f:
                    line = line.rstrip()
                    try:
                        duration, _line = line.split(None, 1)
                        duration_amount, duration_unit = duration.split('-')
                        assert duration_amount.isdigit()
                        assert duration_unit in {'hour', 'minute'}
                        start = time.monotonic()
                        action, dst, dst_port, proto = _parse_rule(_line)
                        _add_rule(action, duration, start, dst, dst_port, proto)
                        log(f'INFO add temporary rule {action} {duration} {dst} {dst_port} {proto}')
                    except:
                        log(f'INFO bad temp rule: {line}')
            os.remove(tempfile)

def _watch_permanent_rules():
    files = [state.rules_file, state.adblock_rules_file]
    last = {}
    for file in files:
        last[file] = None
    while True:
        new_rules = set()
        for file in files:
            try:
                mtime = os.stat(file).st_mtime
            except FileNotFoundError:
                mtime = 0
            if last[file] != mtime:
                last[file] = mtime
                break
        else:
            time.sleep(1)
            continue

        for file in files:
            try:
                with open(file) as f:
                    lines = reversed(f.read().splitlines()) # lines at top of file are higher priority and overwrite later entries
            except FileNotFoundError:
                with open(file, 'w') as f:
                    lines = []
            lines = [l.split('#')[-1] for l in lines]
            lines = [l for l in lines if l.strip()]
            new_rules = new_rules.union(_upsert_permanent_rules(lines, file))
        _gc_permanent_rules(new_rules)

def _gc_permanent_rules(new_rules):
    for rule in list(state._rules):
        dst, dst_port, proto = rule
        action, duration, start = state._rules.get(rule, ('', '', 0))
        if rule not in new_rules and duration is None:
            state._rules.pop(rule)
            log(f'INFO removed rule {action} {dst} {dst_port} {proto}')

def _upsert_permanent_rules(lines, file):
    rules = set()
    for line in lines:
        rule = _parse_rule(line)
        if rule:
            action, dst, dst_port, proto = rule
            duration = start = None
            _add_rule(action, duration, start, dst, dst_port, proto, nolog=file == state.adblock_rules_file)
            rules.add((dst, dst_port, proto))
    return rules

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
            output = tinysnitch.lib.check_output(f'su {_prompt_user} -c \'DISPLAY=:0 tinysnitch-prompt "{formatted}"\' 2>/tmp/tinysnitch_prompt.log')
            duration, subdomains, action, ports = output.split()
        except (ValueError, subprocess.CalledProcessError):
            log(f'output: {output}')
            log('ERROR failed to run tinysnitch-prompt\n' + tinysnitch.lib.check_output('cat /tmp/tinysnitch_prompt.log || true'))
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
        dst_port = '*'
    if duration == 'once':
        return action
    else:
        _duration = duration
        if '-minute' in duration:
            minutes = int(duration.split('-')[0])
            duration = 60 * minutes
        elif '-hour' in duration:
            hours = int(duration.split('-')[0])
            duration = 60 * 60 * hours
        elif duration == 'forever':
            duration = None
        else:
            assert False, _duration
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
