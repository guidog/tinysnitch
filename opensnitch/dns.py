# This file is part of OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
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

import logging
import opensnitch.shell
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP

with open('/etc/hostname') as f:
    hostname = f.read().strip()
hosts = {}
localhosts = set()

def _decode(x):
    try:
        return x.decode('utf-8').rstrip('.')
    except:
        return x.rstrip()

def populate_localhosts():
    for line in opensnitch.shell.co('ip a | grep inet').splitlines():
        _, addr, *_ = line.strip().split()
        addr = addr.split('/')[0]
        hosts[addr] = hostname
        localhosts.add(addr)
        logging.info(f'dns: {hostname} {addr}')

def _parse_dns(packet):
    udp = packet['UDP']
    dns = packet['DNS']
    if int(udp.dport) == 53:
        yield _decode(dns.qd.qname), None
    elif int(udp.sport) == 53:
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            yield _decode(dnsrr.rrname), _decode(dnsrr.rdata)

def update_hosts(packet):
    if UDP in packet and DNS in packet:
        addrs = []
        for name, addr in _parse_dns(packet):
            if addr:
                hosts[addr] = name
                addrs.append(addr)
        if addrs:
            logging.info(f'dns: {name} {" ".join(addrs)}')

def get_hostname(address):
    return hosts.get(address, address)
