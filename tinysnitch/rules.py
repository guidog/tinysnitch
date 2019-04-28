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
import tinysnitch.trace
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
    _queue = queue.Queue(1024)
    _online_meta_lookup_queue = queue.Queue(1024)
    _delay_queue = queue.Queue(1024)
    _prompt_queue = queue.Queue(1024)

def start():
    _load_permanent_rules()
    tinysnitch.lib.run_thread(_gc)
    tinysnitch.lib.run_thread(_process_queue)
    tinysnitch.lib.run_thread(_process_delay_queue)
    tinysnitch.lib.run_thread(_process_prompt_queue)
    tinysnitch.lib.run_thread(_process_online_meta_lookups_queue)

def enqueue(finalize, conn):
    repeats = 0
    state._queue.put((finalize, conn, repeats))

def match_rule(_src, dst, _src_port, dst_port, proto, _pid, path, args):
    if proto not in tinysnitch.lib.protos:
        return 'allow', None, None # allow all non tcp/udp
    else:
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

def to_src_proto(src, dst, src_port, dst_port, proto, pid, path, args):
    proto = proto.split('-')[0] + '-src'
    return src, dst, src_port, dst_port, proto, pid, path, args

def to_src_conn(src, dst, src_port, dst_port, proto, pid, path, args):
    # src rules are differentiated by a suffix on proto, which
    # indicates that what is normally the dst is in fact now src
    proto = proto.split('-')[0] + '-src'
    src, dst = dst, src
    return src, dst, src_port, dst_port, proto, pid, path, args

def check(finalize, conn):
    conn = tinysnitch.dns.resolve(*conn)
    _src, dst, _src_port, _dst_port, _proto, _pid, _path, _args = conn
    # when the destination is localhost, two rules are required. one to allow
    # that localhost destination, and a second to allow the inbound request
    # based on the remote src. ie you can allow localhost 8000 independently of
    # allowing a remote ipv4 to hit localhost 8000.
    if tinysnitch.dns.is_localhost(dst):
        dst_rule = match_rule(*conn)
        if dst_rule:
            action, _duration, _start = dst_rule
            if action == 'deny':
                return finalize('deny', conn)
        src_conn = to_src_conn(*conn)
        src_rule = match_rule(*src_conn)
        if src_rule:
            action, _duration, _start = src_rule
            if action == 'deny':
                return finalize('deny', src_conn)
        if not dst_rule or not src_rule:
            state._prompt_queue.put((finalize, conn))
        else:
            finalize('allow', conn)
    # when dst is not localhost, only one rule is required
    else:
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
                log(f'INFO gc expired rule {action} {dst} {dst_port} {proto} {path} {args}')
                del state._rules[k]
            if isinstance(duration, str) and duration != 'forever' and duration not in pids:
                log(f'INFO gc rule for pid {duration} expired {action} {dst} {dst_port} {proto} {path} {args}')
                del state._rules[k]
        time.sleep(3)
    log('FATAL rules gc exited prematurely')
    sys.exit(1)

def _process_queue():
    while True:
        finalize, conn, repeats = state._queue.get()
        try:
            assert repeats < 100 # TODO instead of polling should we react to trace events?, tbh this is prob fine
            conn = tinysnitch.trace.add_meta(*conn)
            if repeats:
                log(f'DEBUG resolved meta after spinning {repeats} times for {tinysnitch.dns.format(*conn)}')
        except KeyError:
            state._delay_queue.put((finalize, conn, repeats + 1))
        except AssertionError:
            log(f'DEBUG fallback to online meta lookup for {tinysnitch.dns.format(*conn)}')
            state._online_meta_lookup_queue.put((finalize, conn))
        else:
            check(finalize, conn)
    log('FATAL rules process-queue exited prematurely')
    sys.exit(1)

def _process_delay_queue():
    while True:
        time.sleep(.0001)
        state._queue.put(state._delay_queue.get())
    log('FATAL rules process-delay-queue exited prematurely')
    sys.exit(1)

def _parse_rule(line):
    try:
        action, dst, dst_port, proto, path, args = line.split(None, 5)
    except ValueError:
        log(f'ERROR invalid rule, should have been "action dst dst_port proto path args", was {line}')
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
    return action, dst, dst_port, proto, path, args

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
            action, dst, dst_port, proto, path, args = rule
            duration = start = None
            _add_rule(action, duration, start, dst, dst_port, proto, path, args)
            log(f'INFO loaded rule {action} {dst} {dst_port} {proto} {path} {args}')
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
        try:
            duration, scope, action, granularity = tinysnitch.lib.check_output(f'su {_prompt_user} -c \'DISPLAY=:0 tinysnitch-prompt "{tinysnitch.dns.format(*prompt_conn)}"\' 2>/dev/null').split()
        except:
            log('ERROR failed run tinysnitch-prompt')
            finalize('deny', conn)
            return 'deny'
        else:
            action = _process_rule(conn, duration, scope, action, granularity)
            if action == 'deny':
                finalize('deny', conn)
                return 'deny'
            else:
                return 'allow'

def _process_prompt_queue():
    while True:
        finalize, conn = state._prompt_queue.get()
        _src, dst, _src_port, _dst_port, _proto, _pid, _path, _args = conn
        if not tinysnitch.trace.is_alive(*conn):
            finalize('deny', conn)
        # inbound connection
        elif tinysnitch.dns.is_localhost(dst):
            # first rule: localhost and local port
            action = _prompt(finalize, conn, conn)
            if action == 'deny':
                continue
            # second rule: remote source and local port
            action = _prompt(finalize, to_src_conn(*conn), to_src_proto(*conn))
            if action == 'deny':
                continue
            finalize('allow', conn)
        # outbound connection: remote destination and remote port
        else:
            action = _prompt(finalize, conn, conn)
            finalize(action, conn)
    log('FATAL process-prompt-queue exited prematurely')
    sys.exit(1)

def _process_online_meta_lookups_queue():
    while True:
        finalize, conn = state._online_meta_lookup_queue.get()
        conn = tinysnitch.trace.online_meta_lookup(*conn)
        check(finalize, conn)
    log('FATAL process-online-meta-lookups-queue exited prematurely')
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
            with open(state.rules_file, 'a') as f:
                f.write(f'{action} {dst} {dst_port} {proto} {path} {args}\n')
            log(f'INFO add permanent rule {action} {dst} {dst_port} {proto} {path} {args}')
        else:
            log(f'INFO add temporary rule {action} {_duration} {dst} {dst_port} {proto} {path} {args}')
        return action
