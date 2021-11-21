package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -O3 -march=native -mtune=native
#include "netfilter.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

type callbackFunc func(int, []byte)

const (
	zero                   = C.uint(0)
	af_inet                = C.ushort(2)
	af_inet6               = C.ushort(10)
	nf_default_queue_size  = C.uint(4096)
	nf_default_packet_size = C.uint(4096)
	default_total_size     = C.uint(4096 * 4096)
	nfqnl_copy_packet      = C.uchar(2)
)

var (
	nfqh     *C.struct_nfq_q_handle
	callback callbackFunc
)

func assert(cond bool, message string) {
	if !cond {
		panic(message)
	}
}

func Create(cb callbackFunc) (*C.struct_nfq_handle, *C.struct_nfq_q_handle) {
	callback = cb
	queueNum := C.uint(0)
	queueID := C.uint(time.Now().UnixNano())
	nfqHandle := C.nfq_open()
	assert(C.nfq_unbind_pf(nfqHandle, af_inet) >= 0, "failed to unbind af_inet")
	assert(C.nfq_unbind_pf(nfqHandle, af_inet6) >= 0, "failed to unbind af_inet6")
	assert(C.nfq_bind_pf(nfqHandle, af_inet) >= 0, "failed to unbind af_inet")
	assert(C.nfq_bind_pf(nfqHandle, af_inet6) >= 0, "failed to unbind af_inet6")
	nfqQHandle := C.nf_create_queue(nfqHandle, queueNum, queueID)
	nfqh = nfqQHandle
	return nfqHandle, nfqQHandle
}

func Setup(nfqHandle *C.struct_nfq_handle, nfqQHandle *C.struct_nfq_q_handle) C.int {
	assert(C.nfq_set_queue_maxlen(nfqQHandle, nf_default_queue_size) >= 0, "failed to set queue size")
	assert(C.nfq_set_mode(nfqQHandle, nfqnl_copy_packet, nf_default_packet_size) >= 0, "failed to set queue mode")
	nfqFd := C.nfq_fd(nfqHandle)
	C.nfnl_rcvbufsiz(C.nfq_nfnlh(nfqHandle), default_total_size)
	return nfqFd
}

func Run(nfqHandle *C.struct_nfq_handle, nfqFd C.int) {
	assert(C.nf_run(nfqHandle, nfqFd) == 0, "failed to run")
}

func Destroy(nfqHandle *C.struct_nfq_handle, nfqQHandle *C.struct_nfq_q_handle) {
	if nfqQHandle != nil {
		assert(C.nfq_destroy_queue(nfqQHandle) == 0, "failed to destroy queue")
	}
	if nfqHandle != nil {
		assert(C.nfq_close(nfqHandle) == 0, "failed to close")
	}
}

func Finalize(id int, action int) {
	C.nfq_set_verdict(nfqh, C.uint(id), C.uint(action), zero, nil)
}

//export go_callback
func go_callback(id C.uint, data *C.uchar, len C.uint) {
	callback(int(id), C.GoBytes(unsafe.Pointer(data), C.int(len)))
}
