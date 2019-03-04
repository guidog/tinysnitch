# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# https://www.evilsocket.net
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
import psutil
import os

def get_pid_by_connection(src_addr, src_p, dst_addr, dst_p, proto='tcp'):
    # We always take the first element as we assume it contains only one
    # It should not be possible to keep two connections which are the same.
    for conn in psutil.net_connections(kind=proto):
        if proto == 'tcp':
            if conn.laddr != (src_addr, int(src_p)):
                continue
            if conn.raddr != (dst_addr, int(dst_p)):
                continue
        # UDP gives us a very limited dataset to work with
        elif proto == 'udp':
            if conn.laddr[1] != int(src_p):
                continue
        return conn.pid
    logging.debug("could not find process for %s connection %s:%s -> %s:%s", proto, src_addr, src_p, dst_addr, dst_p)
    return ''

def get_app_path_and_cmdline(pid):
    path = args = ''
    if not pid:
        return path, args
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except:
        logging.exception('proc lookup failed')
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            args = f.read().replace('\0', ' ').strip()
    except:
        logging.exception('failed cmdline lookup')
    return path, args
