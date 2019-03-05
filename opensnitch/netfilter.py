from opensnitch._netfilter import ffi, lib
import scapy.layers.inet
import logging
import opensnitch.connection
import opensnitch.dns
import opensnitch.netfilter
import time

AF_INET = ffi.cast('int', 2)
AF_INET6 = ffi.cast('int', 10)
NF_MARK_SET = ffi.cast('unsigned int', 1)
NF_MARK = ffi.cast('unsigned int', 101285)
NF_DROP = ffi.cast('unsigned int', 0)
NF_ACCEPT = ffi.cast('unsigned int', 1)
NF_STOLEN = ffi.cast('unsigned int', 2)
NF_QUEUE = ffi.cast('unsigned int', 3)
NF_REPEAT = ffi.cast('unsigned int', 4)
NF_STOP = ffi.cast('unsigned int', 5)
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
    nfq_q_handle = lib.CreateQueue(nfq_handle, queue_num, queue_id)
    return nfq_handle, nfq_q_handle
    # TODO destroy() on error

def setup(nfq_handle, nfq_q_handle):
    assert lib.nfq_set_queue_maxlen(nfq_q_handle, NF_DEFAULT_QUEUE_SIZE) >= 0
    assert lib.nfq_set_mode(nfq_q_handle, ffi.cast('unsigned int', 2), NF_DEFAULT_PACKET_SIZE) >= 0
    nfq_fd = lib.nfq_fd(nfq_handle)
    assert lib.nfnl_rcvbufsiz(lib.nfq_nfnlh(nfq_handle), DEFAULT_TOTAL_SIZE) >= 0
    return nfq_fd
    # TODO destroy() on error

def run(nfq_handle, nfq_fd):
    assert lib.Run(nfq_handle, nfq_fd) == 0

@ffi.def_extern()
def py_callback(_id, data, length, mark, idx, vc):
    vc.verdict = NF_ACCEPT
    vc.data = ffi.NULL
    vc.mark_set = ffi.cast('unsigned int', 0)
    vc.length = ffi.cast('unsigned int', 0)
    xdata = bytes(ffi.unpack(data, length))
    packet = scapy.layers.inet.IP(xdata)
    opensnitch.dns.add_response(packet)
    conn = opensnitch.connection.parse(packet)
    if conn['src'] == conn['dst'] == '127.0.0.1':
        vc.verdict = NF_ACCEPT
    elif True:
        logging.info('allow %s', opensnitch.connection.format(conn))
        vc.verdict = NF_ACCEPT
        vc.data = data
        vc.length = length
    else:
        logging.info('deny %s', opensnitch.connection.format(conn))
        vc.mark_set = NF_MARK_SET
        vc.mark = mark # NF_MARK
