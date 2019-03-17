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
import opensnitch.dns
import opensnitch.bpftrace
import opensnitch.kprobe
import logging

def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]

def parse(packet):
    src = packet.src
    dst = packet.dst
    src_port = dst_port = proto = path = args = ''
    pid = '?'
    proto = packet.get_field('proto').i2s[packet.proto]
    if 'TCP' in packet or 'UDP' in packet:
        ip = packet['IP']
        src_port = ip.sport
        dst_port = ip.dport
    return src, dst, src_port, dst_port, proto, pid, path, args

def add_meta(packet, conn):
    # TODO add meta for the server pid on incoming connections. tcp can be seen
    # via opensnitch-bpftrace-tcp-accept, udp can be seen via
    # opensnitch-bpftrace-udp with source and dest address as 0.0.0.0
    src, dst, src_port, dst_port, proto, _pid, _path, _args = conn
    if proto in {'tcp', 'udp'}:
        try:
            pid, start = opensnitch.bpftrace.pids[(src, src_port, dst, dst_port)]
        except KeyError:
            # logging.info(f'pids missed lookup: {(src, src_port, dst, dst_port)} {proto}')
            raise
        try:
            path, args = opensnitch.kprobe.comms[pid]
        except KeyError:
            # logging.info(f'comms missed lookup: {pid}')
            raise
        try:
            path = opensnitch.kprobe.filenames[pid]
        except KeyError:
            # logging.info(f'filenames missed lookup: {pid}')
            raise
    return src, dst, src_port, dst_port, proto, pid, path, args

def format(conn):
    src, dst, src_port, dst_port, proto, pid, path, args = conn
    src = opensnitch.dns.get_hostname(src)
    dst = opensnitch.dns.get_hostname(dst)
    if dst == opensnitch.dns.hostname:
        return ' '.join(f'{proto} | {dst}:{dst_port} <- {src}:{src_port} | {pid} {path + args}'.split())
    else:
        return ' '.join(f'{proto} | {src}:{src_port} -> {dst}:{dst_port} | {pid} {path + args}'.split())
