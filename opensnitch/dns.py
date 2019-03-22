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

import time
import logging
import opensnitch.shell
import opensnitch.trace
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP

hostname = 'localhost'
hosts = {}
localhosts = set()
_hosts_file = '/etc/opensnitch.hosts'
_new_addrs = []

def _decode(x):
    try:
        return x.decode('utf-8').rstrip('.')
    except:
        return x.rstrip()

def start():
    _populate_localhosts()
    _populate_hosts()
    opensnitch.trace.run_thread(_persister)

def _populate_hosts():
    try:
        with open(_hosts_file) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        with open(_hosts_file, 'w') as _:
            lines = []
    for line in lines:
        addr, hostname = line.split()
        hosts[addr] = hostname
        logging.debug(f'load dns: {hostname} {addr}')

def _populate_localhosts():
    for line in opensnitch.shell.co('ip a | grep inet').splitlines():
        _, addr, *_ = line.strip().split()
        addr = addr.split('/')[0]
        hosts[addr] = hostname
        localhosts.add(addr)
        logging.info(f'localhost dns: {hostname} {addr}')

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
                _new_addrs.append(addr)
        if addrs:
            logging.info(f'dns: {name} {" ".join(addrs)}')

def get_hostname(address):
    return hosts.get(address, address)

def _persister():
    while True:
        while True:
            with open(_hosts_file, 'a') as f:
                try:
                    addr = _new_addrs.pop()
                except IndexError:
                    break
                else:
                    f.write(f'{addr} {hosts[addr]}\n')
        time.sleep(1)
