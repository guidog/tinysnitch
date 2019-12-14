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

import tinysnitch.dns
import tinysnitch.lib
import tinysnitch.netfilter
import tinysnitch.rules
import os
import sys
import time
from tinysnitch.lib import log

assert tinysnitch.lib.check_output('whoami') == 'root', 'tinysnitchd must run as root'

def _log_sizes():
    while True:
        states = [tinysnitch.dns.state, tinysnitch.rules.state, tinysnitch.netfilter.state]
        sizes = [f'{state.__module__.split(".")[-1]}.{k}:{len(v)}' for state in states for k, v in state.__dict__.items() if isinstance(v, dict)]
        log(f"INFO sizes {' '.join(sizes)}")
        time.sleep(5)
    log('FATAL log sizes exited prematurely')
    sys.exit(1)

def main(rules='/etc/tinysnitch.rules'):
    tinysnitch.rules.state.rules_file = rules
    trace_pids = tinysnitch.lib.check_output('ps -ef | grep "bin/tinysnitch\-b" | grep -v grep | awk "{print \$2}"').splitlines()
    if trace_pids:
        for pid in trace_pids:
            print('DEBUG killing existing trace program:', tinysnitch.lib.check_output('ps', pid))
            tinysnitch.lib.check_call('sudo kill', pid)
    if 'TINYSNITCH_LOG_SIZES' in os.environ:
        tinysnitch.lib.run_thread(_log_sizes)
    tinysnitch.dns.start()
    tinysnitch.rules.start()
    nfq_handle, nfq_q_handle = tinysnitch.netfilter.create()
    try:
        nfq_fd = tinysnitch.netfilter.setup(nfq_handle, nfq_q_handle)
        tinysnitch.netfilter.run(nfq_handle, nfq_fd)
    except KeyboardInterrupt:
        pass
    finally:
        tinysnitch.netfilter.destroy(nfq_q_handle, nfq_handle)
