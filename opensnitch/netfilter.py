from opensnitch._netfilter import ffi, lib
import scapy.layers.inet
import logging
import time
import opensnitch.connection
import opensnitch.dns
import opensnitch.netfilter

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
def py_callback(data, length, vc):
    unpacked = bytes(ffi.unpack(data, length))
    packet = scapy.layers.inet.IP(unpacked)
    opensnitch.dns.add_response(packet)
    conn = opensnitch.connection.parse(packet)
    if (
        # conn['src'] == conn['dst'] == '127.0.0.1' or
        conn['proto'] == 'hopopt'
        ):
        logging.debug(f'allow: {opensnitch.connection.format(conn)}')
    elif True:
        logging.info(f'allow: {opensnitch.connection.format(conn)}')
    else:
        logging.info(f'deny: {opensnitch.connection.format(conn)}')
        vc.mark_set = NF_MARK_SET
