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

import collections
import logging
import opensnitch.conn
import opensnitch.dns
import opensnitch.rules
import opensnitch.trace
import scapy.layers.inet
import sys
import time
import time
import xxhash

_repeats = collections.defaultdict(int)
_repeats_start = {}

_AF_INET = ffi.cast('int', 2)
_AF_INET6 = ffi.cast('int', 10)
_NF_DEFAULT_QUEUE_SIZE = ffi.cast('unsigned int', 4096)
_NF_DEFAULT_PACKET_SIZE = ffi.cast('unsigned int', 4096)
_DEFAULT_TOTAL_SIZE = ffi.cast('unsigned int', 4096 * 4096)

def create(queue_num):
    queue_num = ffi.cast('unsigned int', queue_num)
    queue_id = ffi.cast('unsigned int', time.time())
    nfq_handle = lib.nfq_open()
    assert lib.nfq_unbind_pf(nfq_handle, _AF_INET) >= 0
    assert lib.nfq_unbind_pf(nfq_handle, _AF_INET6) >= 0
    assert lib.nfq_bind_pf(nfq_handle, _AF_INET) >= 0
    assert lib.nfq_bind_pf(nfq_handle, _AF_INET6) >= 0
    nfq_q_handle = lib.create_queue(nfq_handle, queue_num, queue_id)
    return nfq_handle, nfq_q_handle

def setup(nfq_handle, nfq_q_handle):
    assert lib.nfq_set_queue_maxlen(nfq_q_handle, _NF_DEFAULT_QUEUE_SIZE) >= 0
    assert lib.nfq_set_mode(nfq_q_handle, ffi.cast('unsigned int', 2), _NF_DEFAULT_PACKET_SIZE) >= 0
    nfq_fd = lib.nfq_fd(nfq_handle)
    assert lib.nfnl_rcvbufsiz(lib.nfq_nfnlh(nfq_handle), _DEFAULT_TOTAL_SIZE) >= 0
    return nfq_fd

def run(nfq_handle, nfq_fd):
    opensnitch.trace.run_thread(_gc)
    assert lib.run(nfq_handle, nfq_fd) == 0

def destroy(nfq_q_handle, nfq_handle):
    if nfq_q_handle:
        assert lib.nfq_destroy_queue(nfq_q_handle) == 0
    if nfq_handle:
        assert lib.nfq_close(nfq_handle) == 0

def _gc():
    while True:
        now = time.monotonic()
        for checksum, start in list(_repeats_start.items()):
            if now - start > opensnitch.trace.seconds:
                del _repeats[checksum]
                del _repeats_start[checksum]
        time.sleep(1)
    logging.error('trace gc exited prematurely')
    sys.exit(1)

@ffi.def_extern()
def _py_callback(data, length):
    unpacked = bytes(ffi.unpack(data, length))
    packet = scapy.layers.inet.IP(unpacked)
    opensnitch.dns.update_hosts(packet)
    conn = opensnitch.conn.parse(packet)
    try:
        conn = opensnitch.conn.add_meta(conn)
        src, dst, src_port, dst_port, proto, pid, path, args = conn
    except KeyError:
        src, dst, src_port, dst_port, proto, pid, path, args = conn
        action = opensnitch.rules.check(conn, prompt=False)
        if action:
            return action
        checksum = xxhash.xxh64_hexdigest(unpacked) # TODO update to xx3hash
        _repeats_start[checksum] = time.monotonic()
        _repeats[checksum] += 1
        if _repeats[checksum] > 100: # this has to be high to give trace.py a chance to catch up, otherwise you are missing pid/path/args data often
            action = opensnitch.rules.check(conn)
        else:
            action = opensnitch.rules.REPEAT
    else:
        if dst in opensnitch.dns.localhosts and src_port == 53: # auto allow and dont double print dns packets, the only ones we track after --ctstate NEW, so that we can log the solved addr
            return opensnitch.rules.ALLOW
        action = opensnitch.rules.check(conn)
    if action is opensnitch.rules.ALLOW:
        logging.info(f'allow: {opensnitch.conn.format(conn)}')
    elif action is opensnitch.rules.DENY:
        logging.info(f'deny: {opensnitch.conn.format(conn)}')
    return action
