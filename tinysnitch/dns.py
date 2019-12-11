# This file is part of tinysnitch, formerly known as OpenSnitch.
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

import sys
import time
import tinysnitch.lib
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
from tinysnitch.lib import log

_hosts_file = '/etc/tinysnitch.hosts'

class state:
    _localhosts = set()
    _hosts = {}
    _new_addrs = []

def start():
    _populate_hosts()
    tinysnitch.lib.run_thread(_populate_localhosts)
    tinysnitch.lib.run_thread(_persister)

def format(src, dst, src_port, dst_port, proto):
    return f'{proto} | {src}:{src_port} -> {dst}:{dst_port}'

def is_inbound_dns(src, dst, src_port, dst_port, proto):
    return is_localhost(dst) and src_port == 53

def is_localhost(addr):
    return addr in state._localhosts

def update_hosts(packet):
    if UDP in packet and DNS in packet:
        addrs = []
        for name, addr in _parse_dns(packet):
            if addr:
                state._hosts[addr] = name
                addrs.append(addr)
                state._new_addrs.append(addr)
        if addrs:
            log(f'INFO dns {name} {" ".join(addrs)}')

def resolve(src, dst, src_port, dst_port, proto):
    return get_hostname(src), get_hostname(dst), src_port, dst_port, proto

def _populate_hosts():
    try:
        with open(_hosts_file) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        with open(_hosts_file, 'w') as _:
            lines = []
    for line in lines:
        addr, hostname = line.split()
        state._hosts[addr] = hostname

def _populate_localhosts():
    while True:
        for line in tinysnitch.lib.check_output('ip a | grep inet').splitlines() + ['- localhost -']:
            _, addr, *_ = line.strip().split()
            addr = addr.split('/')[0]
            state._hosts[addr] = 'localhost'
            state._localhosts.add(addr)
        time.sleep(5)
    print('fatal: populate hosts exited prematurely')
    sys.exit(1)

def _parse_dns(packet):
    udp = packet['UDP']
    dns = packet['DNS']
    if int(udp.dport) == 53:
        yield tinysnitch.lib.decode(dns.qd.qname), None
    elif int(udp.sport) == 53:
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            yield tinysnitch.lib.decode(dnsrr.rrname), tinysnitch.lib.decode(dnsrr.rdata)

def get_hostname(address):
    return state._hosts.get(address, address)

def _persister():
    while True:
        while True:
            with open(_hosts_file, 'a') as f:
                try:
                    addr = state._new_addrs.pop()
                except IndexError:
                    break
                else:
                    f.write(f'{addr} {state._hosts[addr]}\n')
        time.sleep(1)
    log('FATAL dns persister exited prematurely')
    sys.exit(1)
