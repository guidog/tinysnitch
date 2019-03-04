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
import scapy.layers.dns
import logging

hosts = {'127.0.0.1': 'localhost'}

def parse_dns(packet):
    ip = packet['IP']
    udp = packet['UDP']
    dns = packet['DNS']
    if int(udp.dport) == 53:
        qname = dns.qd.qname
        yield ip.src, udp.sport, ip.dst, udp.dport, qname, None
    # dns reply packet
    elif int(udp.sport) == 53:
        # dns DNSRR count (answer count)
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            yield ip.src, udp.sport, ip.dst, udp.dport, dnsrr.rrname, dnsrr.rdata

def add_response(packet):
    if packet and packet.haslayer('UDP') and packet.haslayer('DNS'):
        for _, _, _, _, name, addr in parse_dns(packet):
            if addr:
                logging.info(f'{addr} => {name}')
                hosts[addr] = name

def get_hostname(address):
    try:
        return hosts[address]
    except KeyError:
        logging.debug("No hostname found for address %s" % address)
        return address
