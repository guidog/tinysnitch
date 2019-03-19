# This file is part of OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
#
# Copyright(c) 2018 Simone Margaritelli
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
#
# based on: https://github.com/evilsocket/opensnitch/blob/5c8f7102c29caf94e967f8433a68b861a4b1666f/daemon/netfilter/queue.h

from cffi import FFI
ffibuilder = FFI()

ffibuilder.cdef(r"""

extern "Python" int _py_callback(unsigned char* data, unsigned int len);
static inline struct nfq_q_handle* create_queue(struct nfq_handle *h, unsigned int queue, unsigned int idx);
static inline int run(struct nfq_handle *h, int fd);
struct nfq_handle * nfq_open (void);
struct nfnl_handle * nfq_nfnlh (struct nfq_handle *h);
unsigned int nfnl_rcvbufsiz (const struct nfnl_handle *h, unsigned int size);
int nfq_close (struct nfq_handle *h);
int nfq_bind_pf (struct nfq_handle *h, uint16_t pf);
int nfq_unbind_pf (struct nfq_handle *h, uint16_t pf);
int nfq_set_queue_maxlen (struct nfq_q_handle *qh, uint32_t queuelen);
int nfq_set_mode (struct nfq_q_handle *qh, uint8_t mode, uint32_t range);
int nfq_fd (struct nfq_handle *h);
int nfq_destroy_queue (struct nfq_q_handle *qh);

""")

ffibuilder.set_source(
    "_netfilter",
    r"""

#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define NF_MARK 101285
#define NF_ACCEPT 1
#define NF_REPEAT 4

static int _py_callback(unsigned char* data, unsigned int len);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg) {
    unsigned char *buffer = NULL;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    unsigned int id = ntohl(ph->packet_id);
    unsigned int size = nfq_get_payload(nfa, &buffer);
    int response = _py_callback(buffer, size);
    if (response == 0)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, NF_MARK, size, buffer);
    else if (response == 1)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else if (response == 2)
        return nfq_set_verdict(qh, id, NF_REPEAT, 0, NULL);
}

static inline struct nfq_q_handle* create_queue(struct nfq_handle *h, unsigned int queue, unsigned int idx) {
    return nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
}

static inline int run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) && rcvd >= 0)
        nfq_handle_packet(h, buf, rcvd);
    return errno;
}

    """,
    libraries=['netfilter_queue'],
    extra_compile_args=['-O3', '-march=native', '-ffast-math'],
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
