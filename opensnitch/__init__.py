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

import logging
import opensnitch.dns
import opensnitch.netfilter
import opensnitch.bpftrace
import opensnitch.kprobe
import subprocess

iptables_rules = [
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0",
    "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "INPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "OUTPUT --protocol tcp -m mark --mark 101285 -j REJECT",
]

cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')
co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()

assert co('whoami') == 'root', 'opensnitchd must run as root'

def main(setup_firewall=False, teardown_firewall=False):
    logging.basicConfig(
        level='INFO',
        # level='ERROR',
        format='%(message)s',
    )
    if setup_firewall:
        for rule in iptables_rules:
            cc('iptables -I', rule)
    elif teardown_firewall:
        for rule in iptables_rules:
            cc('iptables -D', rule, '|| echo failed to delete:', rule)
    else:
        opensnitch.dns.populate_localhosts()
        opensnitch.bpftrace.start()
        opensnitch.kprobe.start()
        nfq_handle, nfq_q_handle = opensnitch.netfilter.create(0)
        try:
            nfq_fd = opensnitch.netfilter.setup(nfq_handle, nfq_q_handle)
            opensnitch.netfilter.run(nfq_handle, nfq_fd)
        except KeyboardInterrupt:
            pass
        finally:
            opensnitch.netfilter.destroy(nfq_q_handle, nfq_handle)
            # opensnitch.kprobe.disable()
