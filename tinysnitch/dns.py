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

from typing import Set, Dict, List, Tuple
import traceback
import dnslib
import sys
import time
import uuid
import pickle
import tinysnitch.lib
from tinysnitch.lib import log

_dns_file = '/etc/tinysnitch.hosts'

class state:
    _localhosts: Set[str] = set()
    _hosts: Dict[str, str] = {} # TODO this should LRU cache
    _dns_to_log: List[Tuple[str, str]] = []

def start():
    _populate_hosts()
    tinysnitch.lib.run_thread(_localhost_watcher)
    tinysnitch.lib.run_thread(_dns_logger)

def format(src, dst, src_port, dst_port, proto):
    return f'{proto} | {src}:{src_port} -> {dst}:{dst_port}'

def should_log(*conn):
    return (
        not is_inbound_dns(*conn)
        and not is_icmp(*conn)
        and not is_udp_loopback(*conn)
        # and not is_outbound_dns(*conn)
        # and not is_local_traffic(*conn)
    )

def is_icmp(src, dst, src_port, dst_port, proto):
    return proto == 'icmp'

def is_inbound_dns(src, dst, src_port, dst_port, proto):
    return is_localhost(dst) and src_port == 53

def is_outbound_dns(src, dst, src_port, dst_port, proto):
    return is_localhost(src) and dst_port == 53

def is_local_traffic(src, dst, src_port, dst_port, proto):
    return is_localhost(src) and is_localhost(dst)

def is_udp_loopback(src, dst, src_port, dst_port, proto):
    return src == dst and src_port == dst_port and proto == "udp"

def is_localhost(addr):
    return addr in state._localhosts

def update_hosts(packet):
    addrs = []
    for name, addr in _parse_dns(packet):
        log(f'INFO dns {name} {addr}')
        if name != state._hosts.get(addr):
            state._dns_to_log.append((name, addr))
        state._hosts[addr] = name
        addrs.append(addr)

def resolve(src, dst, src_port, dst_port, proto):
    return get_hostname(src), get_hostname(dst), src_port, dst_port, proto

def _localhost_watcher():
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
    if 'UDP' in packet:
        p = packet['UDP']
    elif 'TCP' in packet:
        p = packet['TCP']
    else:
        return
    if not (p.sport == 53 or p.dport == 53):
        return
    try:
        raw = p['Raw']
    except IndexError:
        return
    else:
        try:
            dns = dnslib.DNSRecord.parse(raw)
        except:
            debug = f'/tmp/dns.fail.{uuid.uuid4()}.pkl'
            with open(debug, 'wb') as f:
                f.write(pickle.dumps(raw))
            log(f'dumped raw dns failure packet to: {debug}\n{traceback.format_exc()}')
        else:
            cnames = set()
            anames = set()
            addrs = set()
            for rr in dns.rr:
                if rr.rtype == 5: # CNAME
                    cnames.add(str(rr.rname).rstrip('. '))
                elif rr.rtype == 1: # A
                    anames.add(str(rr.rname).rstrip('. '))
                    addrs.add(str(rr.rdata))
            for name in cnames or anames:
                for addr in addrs:
                    yield name, addr

def get_hostname(address):
    return state._hosts.get(address, address)

def _populate_hosts():
    try:
        with open(_dns_file) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        with open(_dns_file, 'w') as _:
            lines = []
    for line in lines:
        name, addr = line.split()
        state._hosts[addr] = name

def _dns_logger():
    while True:
        while True:
            with open(_dns_file, 'a') as f:
                try:
                    name, addr = state._dns_to_log.pop()
                except IndexError:
                    break
                else:
                    f.write(f'{name} {addr}\n')
        time.sleep(1)
    log('FATAL dns persister exited prematurely')
    sys.exit(1)
