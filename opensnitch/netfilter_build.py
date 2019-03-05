# take from: https://github.com/evilsocket/opensnitch/blob/5c8f7102c29caf94e967f8433a68b861a4b1666f/daemon/netfilter/queue.h

from cffi import FFI
ffibuilder = FFI()

ffibuilder.cdef(r"""

typedef struct {
    unsigned int verdict;
    unsigned int mark;
    unsigned int mark_set;
    unsigned int length;
    unsigned char *data;
} verdictContainer;
extern "Python" void py_callback(int id, unsigned char* data, int len, unsigned int mark, unsigned int idx, verdictContainer *vc);
static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg);
static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, unsigned int queue, unsigned int idx);
static inline int Run(struct nfq_handle *h, int fd);
struct nfq_handle * nfq_open (void);
int nfq_close (struct nfq_handle *h);
int nfq_bind_pf (struct nfq_handle *h, uint16_t pf);
int nfq_unbind_pf (struct nfq_handle *h, uint16_t pf);
int nfq_set_queue_maxlen (struct nfq_q_handle *qh, uint32_t queuelen);
int nfq_set_mode (struct nfq_q_handle *qh, uint8_t mode, uint32_t range);
int nfq_fd (struct nfq_handle *h);
unsigned int nfnl_rcvbufsiz (const struct nfnl_handle *h, unsigned int size);
struct nfnl_handle * nfq_nfnlh (struct nfq_handle *h);
""")

ffibuilder.set_source("_netfilter", r"""

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct {
    unsigned int verdict;
    unsigned int mark;
    unsigned int mark_set;
    unsigned int length;
    unsigned char *data;
} verdictContainer;

static void py_callback(int id, unsigned char* data, int len, unsigned int mark, unsigned int idx, verdictContainer *vc);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg) {
    unsigned int id = -1, idx = 0, mark = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int size = 0;
    verdictContainer vc = {0};
    mark = nfq_get_nfmark(nfa);
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    size = nfq_get_payload(nfa, &buffer);
    idx = (unsigned int)((uintptr_t)arg);
    py_callback(id, buffer, size, mark, idx, &vc);
    if (vc.mark_set == 1)
      return nfq_set_verdict2(qh, id, vc.verdict, vc.mark, vc.length, vc.data);
    else
      return nfq_set_verdict(qh, id, vc.verdict, vc.length, vc.data);
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, unsigned int queue, unsigned int idx) {
    return nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
}

static inline int Run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) && rcvd >= 0)
        nfq_handle_packet(h, buf, rcvd);
    return errno;
}

""", libraries=['netfilter_queue'])

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
