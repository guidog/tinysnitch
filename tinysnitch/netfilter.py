# This file is part of tinysnitch, formerly known as OpenSnitch.
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

from tinysnitch.lib import log

try:
    from tinysnitch._netfilter import ffi, lib
    log('use existing ffi binaries')
except ModuleNotFoundError:
    log('recompile ffi binaries')
    import tinysnitch.netfilter_build
    import os
    orig = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print(os.getcwd(), flush=True)
    for path in os.listdir('.'):
        if path.endswith('.c') or path.endswith('.o') or path.endswith('.so'):
            os.remove(path)
    tinysnitch.netfilter_build.ffibuilder.compile(verbose=True)
    os.chdir(orig)
    from tinysnitch._netfilter import ffi, lib

import tinysnitch.dns
import tinysnitch.lib
import tinysnitch.rules
import scapy.layers.inet
import time

class state:
    _nfq_q_handle = None

NULL = ffi.NULL
ZERO = ffi.cast('int', 0)
ONE = ffi.cast('int', 1)
MARK = ffi.cast('int', 101285)

_AF_INET = ffi.cast('int', 2)
_AF_INET6 = ffi.cast('int', 10)
_NF_DEFAULT_QUEUE_SIZE = ffi.cast('unsigned int', 4096)
_NF_DEFAULT_PACKET_SIZE = ffi.cast('unsigned int', 4096)
_DEFAULT_TOTAL_SIZE = ffi.cast('unsigned int', 4096 * 4096)

def create():
    queue_num = ffi.cast('unsigned int', 0)
    queue_id = ffi.cast('unsigned int', time.time())
    nfq_handle = lib.nfq_open()
    assert lib.nfq_unbind_pf(nfq_handle, _AF_INET) >= 0
    assert lib.nfq_unbind_pf(nfq_handle, _AF_INET6) >= 0
    assert lib.nfq_bind_pf(nfq_handle, _AF_INET) >= 0
    assert lib.nfq_bind_pf(nfq_handle, _AF_INET6) >= 0
    state._nfq_q_handle = nfq_q_handle = lib.create_queue(nfq_handle, queue_num, queue_id)
    return nfq_handle, nfq_q_handle

def setup(nfq_handle, nfq_q_handle):
    assert lib.nfq_set_queue_maxlen(nfq_q_handle, _NF_DEFAULT_QUEUE_SIZE) >= 0
    assert lib.nfq_set_mode(nfq_q_handle, ffi.cast('unsigned int', 2), _NF_DEFAULT_PACKET_SIZE) >= 0
    nfq_fd = lib.nfq_fd(nfq_handle)
    assert lib.nfnl_rcvbufsiz(lib.nfq_nfnlh(nfq_handle), _DEFAULT_TOTAL_SIZE) >= 0
    return nfq_fd

def run(nfq_handle, nfq_fd):
    assert lib.run(nfq_handle, nfq_fd) == 0

def destroy(nfq_q_handle, nfq_handle):
    if nfq_q_handle:
        assert lib.nfq_destroy_queue(nfq_q_handle) == 0
    if nfq_handle:
        assert lib.nfq_close(nfq_handle) == 0

def _finalize(nfq, id, data, size, action, conn):
    _src, _dst, _src_port, _dst_port, proto = conn
    if not tinysnitch.dns.is_inbound_dns(*conn) and proto in tinysnitch.lib.protos:
        log(f'INFO {action} {tinysnitch.dns.format(*conn)}')
    if action == 'allow':
        lib.nfq_set_verdict(nfq, id, ONE, ZERO, NULL)
    elif action == 'deny':
        lib.nfq_set_verdict2(nfq, id, ONE, MARK, size, data)
    else:
        assert False, f'bad action: {action}'

@ffi.def_extern()
def _py_callback(id, data, size):
    unpacked = bytes(ffi.unpack(data, size))
    packet = scapy.layers.inet.IP(unpacked)
    tinysnitch.dns.update_hosts(packet)
    conn = tinysnitch.lib.conn(packet)
    finalize = lambda action, new_conn: _finalize(state._nfq_q_handle, id, data, size, action, new_conn)
    # auto allow and dont double print dns packets, the only ones we track after --ctstate NEW, so that we can log the solved addr
    if tinysnitch.dns.is_inbound_dns(*conn):
        finalize('allow', conn)
    else:
        tinysnitch.rules.check(finalize, conn)
