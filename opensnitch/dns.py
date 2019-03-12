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
import subprocess
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP

co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()

hosts = {}

def _decode(x):
    try:
        return x.decode('utf-8').rstrip('.')
    except:
        return x

def populate_localhosts():
    with open('/etc/hostname') as f:
        hostname = f.read().strip()
    for line in co('ip a | grep inet').splitlines():
        _, addr, *_ = line.strip().split()
        addr = addr.split('/')[0]
        hosts[addr] = hostname
        logging.info(f'dns: {addr} => {hostname}')

def parse_dns(packet):
    udp = packet['UDP']
    dns = packet['DNS']
    if int(udp.dport) == 53:
        yield _decode(dns.qd.qname), None
    elif int(udp.sport) == 53:
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            yield _decode(dnsrr.rrname), _decode(dnsrr.rdata)

def add_response(packet):
    if UDP in packet and DNS in packet:
        for name, addr in parse_dns(packet):
            if addr:
                logging.info(f'dns: {addr} => {name}')
                hosts[addr] = name
            else:
                logging.info(f'dns: {name}')

def get_hostname(address):
    return hosts.get(address, '')
