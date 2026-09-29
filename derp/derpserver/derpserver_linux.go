// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package derpserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/net/tcpinfo"
)

// recordSavedSyn retrieves the SYN packet the kernel saved on the client's
// connection (which requires that the listening socket had TCP_SAVE_SYN set;
// see SetTCPSaveSyn) and records the MSS the client advertised in it to the
// tcpSavedSynMSS histogram. It is called once per client, at the start of
// [sclient.run].
func (c *sclient) recordSavedSyn() {
	if !c.s.tcpSaveSyn {
		return
	}
	conn := c.tcpConn()
	if conn == nil {
		c.s.tcpSavedSynStatus.Add("non-tcp", 1)
		return
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}

	// The kernel returns the saved SYN packet as-is: an IP header
	// (v4 or v6, possibly with extension headers) followed by the TCP
	// header and its options. 256 bytes is enough even with generous
	// IPv6 extension headers.
	syn := make([]byte, 256)
	synLen := uint32(len(syn))
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		// TCP_SAVED_SYN has no typed helper in golang.org/x/sys/unix,
		// so do the raw getsockopt here. On success, synLen is the
		// number of bytes written into syn.
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_SAVED_SYN,
			uintptr(unsafe.Pointer(&syn[0])), uintptr(unsafe.Pointer(&synLen)), 0)
		if errno != 0 {
			sysErr = errno
			return
		}
		syn = syn[:synLen]
	})
	if err != nil {
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}
	if sysErr != nil {
		c.logf("error fetching saved SYN: %v", sysErr)
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}

	mss, err := mssFromSavedSyn(syn)
	if err != nil {
		c.logf("error parsing saved SYN: %v", err)
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}
	c.s.tcpSavedSynMSS.Add(mssToLabel(mss), 1)
	c.s.tcpSavedSynStatus.Add("ok", 1)
}

// mssFromSavedSyn parses the MSS option out of the TCP header of a raw SYN
// packet, as returned by the TCP_SAVED_SYN socket option. The packet starts
// with an IP header (either v4 or v6, possibly with extension headers),
// followed by the TCP header and its options.
func mssFromSavedSyn(pkt []byte) (uint16, error) {
	const (
		tcpHeaderLen = 20
		ipProtoTCP   = 6
	)
	if len(pkt) < 40 {
		return 0, fmt.Errorf("saved SYN packet too short: %d bytes", len(pkt))
	}
	var tcpOff int
	switch v := int(pkt[0] >> 4); v {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+tcpHeaderLen {
			return 0, fmt.Errorf("bad IPv4 header length %d", ihl)
		}
		if pkt[9] != ipProtoTCP {
			return 0, fmt.Errorf("saved SYN is not a TCP packet (IP protocol %d)", pkt[9])
		}
		tcpOff = ihl
	case 6:
		if len(pkt) < 40+tcpHeaderLen {
			return 0, fmt.Errorf("short IPv6 saved SYN packet: %d bytes", len(pkt))
		}
		if pkt[6] != ipProtoTCP {
			return 0, fmt.Errorf("saved SYN is not a TCP packet (IPv6 next header %d)", pkt[6])
		}
		tcpOff = 40
	default:
		return 0, fmt.Errorf("bad IP version %d in saved SYN packet", v)
	}
	dataOff := int(pkt[tcpOff+12]>>4) * 4
	if dataOff < tcpHeaderLen || tcpOff+dataOff > len(pkt) {
		return 0, fmt.Errorf("bad TCP data offset %d", dataOff)
	}

	// Walk the TCP options looking for the MSS option (kind 2, length 4).
	for pos := tcpOff + tcpHeaderLen; pos+1 < tcpOff+dataOff; {
		kind := pkt[pos]
		if kind == 0 { // end of options list
			break
		}
		if kind == 1 { // no-op padding
			pos++
			continue
		}
		if pos+2 > tcpOff+dataOff || pkt[pos+1] < 2 {
			return 0, fmt.Errorf("malformed TCP option at offset %d", pos-tcpOff)
		}
		optLen := int(pkt[pos+1])
		if pos+optLen > tcpOff+dataOff {
			return 0, fmt.Errorf("malformed TCP option at offset %d", pos-tcpOff)
		}
		if kind == 2 && optLen == 4 {
			return binary.BigEndian.Uint16(pkt[pos+2 : pos+4]), nil
		}
		pos += optLen
	}
	return 0, errors.New("no MSS option in saved SYN packet")
}

// mssToLabel maps an advertised MSS to a histogram bucket label. The labels
// are the inclusive upper bounds of the buckets, in bytes, for use with
// Grafana's histogram visualizations. The named thresholds cover common
// client MTUs: the TCP minimum (536), IPv6 minimum (1240), PPPoE (1360,
// 1452), tunnels/VPNs (1400-1440), standard Ethernet (1460), and jumbo
// frames (8940).
func mssToLabel(mss uint16) string {
	switch {
	case mss <= 536:
		return "536"
	case mss <= 1220:
		return "1220"
	case mss <= 1240:
		return "1240"
	case mss <= 1360:
		return "1360"
	case mss <= 1400:
		return "1400"
	case mss <= 1420:
		return "1420"
	case mss <= 1440:
		return "1440"
	case mss <= 1452:
		return "1452"
	case mss <= 1460:
		return "1460"
	case mss <= 8940:
		return "8940"
	default:
		return "inf"
	}
}

func (c *sclient) startStatsLoop(ctx context.Context) {
	// Get the RTT initially to verify it's supported.
	conn := c.tcpConn()
	if conn == nil {
		c.s.tcpRtt.Add("non-tcp", 1)
		return
	}
	if _, err := tcpinfo.RTT(conn); err != nil {
		c.logf("error fetching initial RTT: %v", err)
		c.s.tcpRtt.Add("error", 1)
		return
	}

	const statsInterval = 10 * time.Second

	// Don't launch a goroutine; use a timer instead.
	var gatherStats func()
	gatherStats = func() {
		// Do nothing if the context is finished.
		if ctx.Err() != nil {
			return
		}

		// Reschedule ourselves when this stats gathering is finished.
		defer c.s.clock.AfterFunc(statsInterval, gatherStats)

		// Gather TCP RTT information.
		rtt, err := tcpinfo.RTT(conn)
		if err == nil {
			c.s.tcpRtt.Add(durationToLabel(rtt), 1)
		}

		// TODO(andrew): more metrics?
	}

	// Kick off the initial timer.
	c.s.clock.AfterFunc(statsInterval, gatherStats)
}

// tcpConn attempts to get the underlying *net.TCPConn from this client's
// Conn; if it cannot, then it will return nil.
func (c *sclient) tcpConn() *net.TCPConn {
	nc := c.nc
	for {
		switch v := nc.(type) {
		case *net.TCPConn:
			return v
		case *tls.Conn:
			nc = v.NetConn()
		case interface{ NetConn() net.Conn }:
			// Wrappers such as cmd/derper's connection close hook.
			nc = v.NetConn()
		default:
			return nil
		}
	}
}

func durationToLabel(dur time.Duration) string {
	switch {
	case dur <= 10*time.Millisecond:
		return "10ms"
	case dur <= 20*time.Millisecond:
		return "20ms"
	case dur <= 50*time.Millisecond:
		return "50ms"
	case dur <= 100*time.Millisecond:
		return "100ms"
	case dur <= 150*time.Millisecond:
		return "150ms"
	case dur <= 250*time.Millisecond:
		return "250ms"
	case dur <= 500*time.Millisecond:
		return "500ms"
	default:
		return "inf"
	}
}
