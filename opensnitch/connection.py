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

import opensnitch.proc
import opensnitch.dns

def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]

def parse(packet):
    src = packet.src
    dst = packet.dst
    hostname = opensnitch.dns.get_hostname(dst)
    src_port = dst_port = proto = pid = path = args = ''
    proto = packet.get_field('proto').i2s[packet.proto]
    if 'TCP' in packet or 'UDP' in packet:
        ip = packet['IP']
        src_port = ip.sport
        dst_port = ip.dport
    if proto in {'tcp', 'udp'}:
        pid = opensnitch.proc.get_pid_by_connection(src, src_port, dst, dst_port, proto)
        path, args = opensnitch.proc.get_app_path_and_cmdline(pid)
    return {'src': src, 'dst': dst, 'hostname': hostname, 'src_port': src_port, 'dst_port': dst_port, 'proto': proto, 'pid': pid, 'path': path, 'args': args}

def format(conn):
    return ' '.join('{src}:{src_port} => {hostname} {dst}:{dst_port} [{pid} {path} {args} {proto}]'.format(**conn).split())
