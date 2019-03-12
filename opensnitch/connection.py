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

import opensnitch.dns
import opensnitch.bpftrace
import logging

def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]

def parse(packet):
    src = packet.src
    dst = packet.dst
    hostname = opensnitch.dns.get_hostname(dst)
    src_port = dst_port = proto = pid = path_and_args = ''
    proto = packet.get_field('proto').i2s[packet.proto]
    if 'TCP' in packet or 'UDP' in packet:
        ip = packet['IP']
        src_port = ip.sport
        dst_port = ip.dport
    if 'UDP' in packet:
        src_port, dst_port = dst_port, src_port
        src, dst = dst, src
    if proto in {'tcp',
                 'udp'
                 }:
        try:
            pid = opensnitch.bpftrace.pids[(src, src_port, dst, dst_port)]
        except KeyError:
            logging.info(f'missed pids lookup of: {src, dst, hostname, src_port, dst_port, proto, pid, path_and_args}')
            raise
        try:
            path_and_args  = opensnitch.bpftrace.paths[pid]
        except KeyError:
            logging.info(f'missed paths lookup of: {src, dst, hostname, src_port, dst_port, proto, pid, path_and_args}')
            raise
    return src, dst, hostname, src_port, dst_port, proto, pid, path_and_args

def format(conn):
    src, dst, hostname, src_port, dst_port, proto, pid, path_and_args = conn
    return ' '.join(f'{src}:{src_port} => {hostname} {dst}:{dst_port} {proto} {pid} {path_and_args}'.split())
