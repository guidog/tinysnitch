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

import socket
import opensnitch.proc
import opensnitch.dns
import dpkt.ip

def parse(payload):
    data = payload
    pkt = dpkt.ip.IP(data)
    src = socket.inet_ntoa(pkt.src)
    dst = socket.inet_ntoa(pkt.dst)
    hostname = opensnitch.dns.get_hostname(dst)
    src_port = dst_port = proto = pid = path = args = ''
    if pkt.p == dpkt.ip.IP_PROTO_TCP:
        proto = 'tcp'
        src_port = pkt.tcp.sport
        dst_port = pkt.tcp.dport
    elif pkt.p == dpkt.ip.IP_PROTO_UDP:
        proto = 'udp'
        src_port = pkt.udp.sport
        dst_port = pkt.udp.dport
    elif pkt.p == dpkt.ip.IP_PROTO_ICMP:
        proto = 'icmp'
        src_port = dst_port = ''
    if proto == 'icmp':
        pid = path = args = ''
    elif '' not in (proto, src, dst):
        pid = opensnitch.proc.get_pid_by_connection(src, src_port, dst, dst_port, proto)
        path, args = opensnitch.proc.get_app_path_and_cmdline(pid)
    return {'src': src, 'dst': dst, 'hostname': hostname, 'src_port': src_port, 'dst_port': dst_port, 'proto': proto, 'pid': pid, 'path': path, 'args': args}

def format(conn):
    return ' '.join('{pid} {path} {args} {proto} {src}:{src_port} => {hostname} {dst}:{dst_port}'.format(**conn).split())
