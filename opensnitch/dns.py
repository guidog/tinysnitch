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

import sys
import time
import opensnitch.lib
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
from opensnitch.lib import log

_hosts_file = '/etc/opensnitch.hosts'

class state:
    _localhosts = set()
    _hosts = {}
    _new_addrs = []

def start():
    _populate_localhosts()
    _populate_hosts()
    opensnitch.lib.run_thread(_persister)

def format(src, dst, src_port, dst_port, proto, pid, path, args):
    if opensnitch.dns.is_localhost(dst):
        return f'{proto} | {dst}:{dst_port} <- {src}:{src_port} | {pid} {path} | {args}'
    else:
        return f'{proto} | {src}:{src_port} -> {dst}:{dst_port} | {pid} {path} | {args}'

def is_inbound_dns(src, dst, src_port, dst_port, proto, pid, path, args):
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
            log(f'info: dns: {name} {" ".join(addrs)}')

def resolve(src, dst, src_port, dst_port, proto, pid, path, args):
    return _get_hostname(src), _get_hostname(dst), src_port, dst_port, proto, pid, path, args

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
    for line in opensnitch.lib.check_output('ip a | grep inet').splitlines() + ['- localhost -']:
        _, addr, *_ = line.strip().split()
        addr = addr.split('/')[0]
        state._localhosts.add(addr)

def _parse_dns(packet):
    udp = packet['UDP']
    dns = packet['DNS']
    if int(udp.dport) == 53:
        yield opensnitch.lib.decode(dns.qd.qname), None
    elif int(udp.sport) == 53:
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            yield opensnitch.lib.decode(dnsrr.rrname), opensnitch.lib.decode(dnsrr.rdata)

def _get_hostname(address):
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
    log('fatal: dns persister exited prematurely')
    sys.exit(1)
