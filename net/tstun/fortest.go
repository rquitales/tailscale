// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"bytes"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/util/testenv"
)

// readAllResult is the outcome of a single [tun.Queue.Read] in [Wrapper.ReadAll].
type readAllResult struct {
	pkts [][]byte
	err  error
}

// ReadAll reads from every queue of t concurrently and returns the packets
// from whichever read completes first.
//
// ReadAll is for tests only. The packets are copies.
func (t *Wrapper) ReadAll() ([][]byte, error) {
	testenv.AssertInTest()

	qs := t.Queues()
	// Do not block on the send.
	ch := make(chan readAllResult, len(qs))
	for _, q := range qs {
		go func() {
			// Reads are in place, so every goroutine needs its own buffers.
			batch := t.BatchSize()
			slab := make([]byte, batch*(MaxPacketSize+(2*tun.ReadPacketSpacing)))
			packets := make([]tun.ReadPacket, batch)

			n, err := q.Read(slab, packets)
			pkts := make([][]byte, 0, n)
			for _, meta := range packets[:n] {
				pkts = append(pkts, bytes.Clone(slab[meta.Offset:meta.Offset+meta.Size]))
			}
			ch <- readAllResult{pkts, err}
		}()
	}
	r := <-ch // Reads return and this unblocks once t is closed.
	return r.pkts, r.err
}
