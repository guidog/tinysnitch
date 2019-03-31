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

import opensnitch.dns
import opensnitch.lib
import opensnitch.netfilter
import opensnitch.rules
import opensnitch.trace
import sys
import time
from opensnitch.lib import log

_iptables_rules = [
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0",             # catch dns packets on the way back in so we can read the resolved address
    "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0", # potentially block incoming traffic
    "INPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",  # potentially block outgoing traffic
    "INPUT -m mark --mark 101285 -j REJECT",                                # inbound rejection mark
    "OUTPUT -m mark --mark 101285 -j REJECT",                               # outbound rejection mark
]

assert opensnitch.lib.check_output('whoami') == 'root', 'opensnitchd must run as root'
output = opensnitch.lib.check_output('ps -ef | grep bin/opensnitch- | grep -v grep || true')

def _log_sizes():
    while True:
        states = [opensnitch.dns.state, opensnitch.trace.state, opensnitch.rules.state, opensnitch.netfilter.state]
        sizes = [f'{state.__module__.split(".")[-1]}.{opensnitch.lib.yellow(k)}:{len(v)}' for state in states for k, v in state.__dict__.items() if isinstance(v, dict)]
        log(f"info: sizes: {' '.join(sizes)}")
        time.sleep(2)
    log('fatal: log sizes exited prematurely')
    sys.exit(1)

def main(setup_firewall=False, teardown_firewall=False, log_sizes=False):
    if setup_firewall:
        for rule in _iptables_rules:
            opensnitch.lib.check_call('iptables -I', rule)
    elif teardown_firewall:
        for rule in _iptables_rules:
            opensnitch.lib.check_call('iptables -D', rule, '|| echo failed to delete:', rule)
    else:
        assert not output, f'you have zombie traces running from an unclean exit, kill them before restarting opensnitch: {output}'
        if log_sizes:
            opensnitch.lib.run_thread(_log_sizes)
        opensnitch.dns.start()
        opensnitch.trace.start()
        opensnitch.rules.start()
        nfq_handle, nfq_q_handle = opensnitch.netfilter.create()
        try:
            nfq_fd = opensnitch.netfilter.setup(nfq_handle, nfq_q_handle)
            opensnitch.netfilter.run(nfq_handle, nfq_fd)
        except KeyboardInterrupt:
            pass
        finally:
            opensnitch.netfilter.destroy(nfq_q_handle, nfq_handle)
