#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void go_callback(unsigned int id, unsigned char* data, unsigned int len);
static inline struct nfq_q_handle* nf_create_queue(struct nfq_handle *h, unsigned int queue, unsigned int idx);
static inline int nf_run(struct nfq_handle *h, int fd);
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
int nfq_set_verdict (struct nfq_q_handle *qh, uint32_t id, uint32_t verdict, uint32_t data_len, const unsigned char *buf);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg) {
    unsigned char *buffer = NULL;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    unsigned int id = ntohl(ph->packet_id);
    int size = nfq_get_payload(nfa, &buffer);
    if (size > 0)
        go_callback(id, buffer, size);
    return 0;
}

static inline struct nfq_q_handle* nf_create_queue(struct nfq_handle *h, unsigned int queue, unsigned int idx) {
    return nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
}

static inline int nf_run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) && rcvd >= 0)
        nfq_handle_packet(h, buf, rcvd);
    return errno;
}
