package sysfs

import (
	"bufio"
	"io"
	"syscall"
	"time"
)

type nbreader struct {
	rd    *bufio.Reader
	rreq  chan req
	rresp chan resp
}

var errEAGAIN error = syscall.EAGAIN

type req struct {
	tpe int
	n   int
}

type resp struct {
	res []byte
	err error
}

func (r *nbreader) Read(p []byte) (n int, err error) {
	r.rreq <- req{tpe: 0, n: len(p)}
	select {
	case rr := <-r.rresp:
		if rr.err != io.EOF {
			err = rr.err
		}
		copy(p, rr.res)
		r.rreq <- req{tpe: 0, n: len(p)}
		return len(rr.res), err
	case <-time.After(1 * time.Millisecond):
		return 0, errEAGAIN
	}
}

func (r *nbreader) readAsync() {
	for {
		m := <-r.rreq
		if m.tpe == 0 {
			peek, err := r.rd.Peek(m.n)
			r.rresp <- resp{
				res: peek,
				err: err,
			}
		}
		if m.tpe == 1 {
			p := make([]byte, m.n)
			_, _ = r.rd.Read(p)
		}
	}
}

func (r *nbreader) Close() error {
	close(r.rresp)
	close(r.rreq)
	return nil
}

func newNbreader(rd io.Reader) *nbreader {
	r := &nbreader{
		rd:    bufio.NewReader(rd),
		rreq:  make(chan req),
		rresp: make(chan resp),
	}
	go r.readAsync()
	return r
}
