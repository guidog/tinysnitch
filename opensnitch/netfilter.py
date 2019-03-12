# This file is part of OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
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

try:
    from opensnitch._netfilter import ffi, lib
except ModuleNotFoundError:
    import opensnitch.netfilter_build
    import os
    orig = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print(os.getcwd(), flush=True)
    for path in os.listdir('.'):
        if path.endswith('.c') or path.endswith('.o') or path.endswith('.so'):
            os.remove(path)
    opensnitch.netfilter_build.ffibuilder.compile(verbose=True)
    os.chdir(orig)
    from opensnitch._netfilter import ffi, lib

import scapy.layers.inet
import logging
import time
import opensnitch.connection
import opensnitch.dns

ALLOW = ffi.cast('int', 0)
DENY = ffi.cast('int', 1)
AF_INET = ffi.cast('int', 2)
AF_INET6 = ffi.cast('int', 10)
NF_MARK_SET = ffi.cast('unsigned int', 1)
NF_DEFAULT_QUEUE_SIZE = ffi.cast('unsigned int', 4096)
NF_DEFAULT_PACKET_SIZE = ffi.cast('unsigned int', 4096)
DEFAULT_TOTAL_SIZE = ffi.cast('unsigned int', 4096 * 4096)

def create(queue_num):
    queue_num = ffi.cast('unsigned int', queue_num)
    queue_id = ffi.cast('unsigned int', time.time())
    nfq_handle = lib.nfq_open()
    assert lib.nfq_unbind_pf(nfq_handle, AF_INET) >= 0
    assert lib.nfq_unbind_pf(nfq_handle, AF_INET6) >= 0
    assert lib.nfq_bind_pf(nfq_handle, AF_INET) >= 0
    assert lib.nfq_bind_pf(nfq_handle, AF_INET6) >= 0
    nfq_q_handle = lib.create_queue(nfq_handle, queue_num, queue_id)
    return nfq_handle, nfq_q_handle

def setup(nfq_handle, nfq_q_handle):
    assert lib.nfq_set_queue_maxlen(nfq_q_handle, NF_DEFAULT_QUEUE_SIZE) >= 0
    assert lib.nfq_set_mode(nfq_q_handle, ffi.cast('unsigned int', 2), NF_DEFAULT_PACKET_SIZE) >= 0
    nfq_fd = lib.nfq_fd(nfq_handle)
    assert lib.nfnl_rcvbufsiz(lib.nfq_nfnlh(nfq_handle), DEFAULT_TOTAL_SIZE) >= 0
    return nfq_fd

def run(nfq_handle, nfq_fd):
    assert lib.run(nfq_handle, nfq_fd) == 0

def destroy(nfq_q_handle, nfq_handle):
    if nfq_q_handle:
        assert lib.nfq_destroy_queue(nfq_q_handle) == 0
    if nfq_handle:
        assert lib.nfq_close(nfq_handle) == 0

@ffi.def_extern()
def py_callback(data, length):
    unpacked = bytes(ffi.unpack(data, length))
    packet = scapy.layers.inet.IP(unpacked)
    opensnitch.dns.add_response(packet)
    conn = opensnitch.connection.parse(packet)
    src, dst, hostname, src_port, dst_port, proto, pid, path, args = conn
    1/0
    if (src == dst == '127.0.0.1'
        or proto == 'hopopt'):
        logging.debug(f'allow: {opensnitch.connection.format(conn)}')
    if True:
        logging.info(f'allow: {opensnitch.connection.format(conn)}')
        return ALLOW
    else:
        logging.info(f'deny: {opensnitch.connection.format(conn)}')
        return DENY
