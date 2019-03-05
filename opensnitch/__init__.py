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
# import netfilterqueue
import logging
import opensnitch.connection
import opensnitch.dns
import opensnitch.netfilter
import subprocess
import scapy.layers.inet

iptables_rules = [
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0",
    "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "INPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0",
    "OUTPUT --protocol tcp -m mark --mark 101285 -j REJECT",
]

cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

def drop_packet(pkt, conn):
    pkt.set_mark(101285)
    pkt.drop()

def pkt_callback(pkt):
    data = pkt.get_payload()
    packet = scapy.layers.inet.IP(data)
    opensnitch.dns.add_response(packet)
    conn = opensnitch.connection.parse(packet)
    if (conn['src'] == conn['dst'] == '127.0.0.1' or conn['proto'] == 'hopopt'):
        pkt.accept()
    elif True:
        logging.info('allow %s', opensnitch.connection.format(conn))
        pkt.accept()
    else:
        logging.info('deny %s', opensnitch.connection.format(conn))
        drop_packet(pkt, conn)

# def _main(setup_firewall=False, teardown_firewall=False):
#     logging.basicConfig(level='INFO', format='%(message)s')
#     if setup_firewall:
#         for rule in iptables_rules:
#             cc('iptables -I', rule)
#     elif teardown_firewall:
#         for rule in iptables_rules:
#             cc('iptables -D', rule, '|| echo failed to delete:', rule)
#     else:
#         opensnitch.dns.populate_localhosts()
#         q = netfilterqueue.NetfilterQueue()
#         q.bind(0, pkt_callback, 1024 * 4)
#         try:
#             q.run()
#         finally:
#             q.unbind()

def _main(setup_firewall=False, teardown_firewall=False):
    logging.basicConfig(level='INFO', format='%(message)s')
    if setup_firewall:
        for rule in iptables_rules:
            cc('iptables -I', rule)
    elif teardown_firewall:
        for rule in iptables_rules:
            cc('iptables -D', rule, '|| echo failed to delete:', rule)
    else:
        opensnitch.dns.populate_localhosts()
        nfq_handle, nfq_q_handle = opensnitch.netfilter.create(0)
        nfq_fd = opensnitch.netfilter.setup(nfq_handle, nfq_q_handle)
        opensnitch.netfilter.run(nfq_handle, nfq_fd)
        # TODO try/finally destroy()

def main():
    argh.dispatch_command(_main)
