# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
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

import argh
import pprint
import netfilterqueue
import scapy.layers.inet
import logging
import prctl
import opensnitch.connection
import opensnitch.dns
import subprocess

iptables_rules = (
    # TODO what happens if we drop mangle here?
    # TODO what happens if we enqueue ALL traffic in and out, tcp and udp?
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0",
    "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "INPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "OUTPUT --protocol tcp -m mark --mark 101285 -j REJECT",
)

required_caps = ((prctl.CAP_NET_RAW, prctl.ALL_FLAGS, True),
                 (prctl.CAP_DAC_OVERRIDE, prctl.ALL_FLAGS, True),
                 (prctl.CAP_NET_ADMIN, prctl.ALL_FLAGS, True))

cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

def drop_packet(pkt, conn):
    pkt.set_mark(101285)
    pkt.drop()

def pkt_callback(pkt):
    data = pkt.get_payload()
    ip = scapy.layers.inet.IP(data)
    opensnitch.dns.add_response(ip)
    conn = opensnitch.connection.Connection(data)
    if conn.src_addr == conn.dst_addr == '127.0.0.1':
        pkt.accept()
    elif True:
        logging.info('allow %s"', conn)
        pkt.accept()
    else:
        logging.info('deny %s"', conn)
        drop_packet(pkt, conn)

def _main(setup_firewall=False, teardown_firewall=False):
    logging.basicConfig(level='DEBUG', format='%(message)s')
    if setup_firewall:
        for rule in iptables_rules:
            cc('iptables -I', rule)
    elif teardown_firewall:
        for rule in iptables_rules:
            cc('iptables -D', rule, '|| echo failed to delete:', rule)
    else:
        # prctl.set_keepcaps(True)
        # prctl.set_caps(*required_caps)
        q = netfilterqueue.NetfilterQueue()
        q.bind(0, pkt_callback, 1024 * 4)
        try:
            q.run()
        finally:
            q.unbind()


def main():
    argh.dispatch_command(_main)
