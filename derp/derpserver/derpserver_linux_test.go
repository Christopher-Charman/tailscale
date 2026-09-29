// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package derpserver

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"

	"tailscale.com/types/key"

	"golang.org/x/sys/unix"
)

// ipv4SYNWithMSS builds a raw IPv4+TCP SYN packet of the form returned by
// TCP_SAVED_SYN, with the given TCP options (nil for none).
func ipv4SYNWithMSS(mss uint16) []byte {
	pkt := make([]byte, 20+20+4)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[9] = 6    // protocol: TCP
	// TCP header: data offset 6 (24 bytes, with 4 bytes of options).
	pkt[20+12] = 6 << 4
	// MSS option.
	opts := pkt[40:]
	opts[0] = 2 // kind: MSS
	opts[1] = 4 // length
	binary.BigEndian.PutUint16(opts[2:4], mss)
	return pkt
}

// ipv6SYNWithMSS builds a raw IPv6+TCP SYN packet with an MSS option.
func ipv6SYNWithMSS(mss uint16) []byte {
	pkt := make([]byte, 40+20+4)
	pkt[0] = 6 << 4 // IPv6
	pkt[6] = 6      // next header: TCP
	pkt[40+12] = 6 << 4
	opts := pkt[60:]
	opts[0] = 2
	opts[1] = 4
	binary.BigEndian.PutUint16(opts[2:4], mss)
	return pkt
}

func TestMSSFromSavedSyn(t *testing.T) {
	tests := []struct {
		name    string
		pkt     []byte
		want    uint16
		wantErr bool
	}{
		{
			name: "ipv4",
			pkt:  ipv4SYNWithMSS(1460),
			want: 1460,
		},
		{
			name: "ipv6",
			pkt:  ipv6SYNWithMSS(1440),
			want: 1440,
		},
		{
			name: "ipv4-with-nops-before-mss",
			pkt: func() []byte {
				pkt := make([]byte, 20+20+8)
				pkt[0] = 0x45
				pkt[9] = 6
				pkt[20+12] = 7 << 4 // data offset 7 (28 bytes: 20 + 8 options)
				opts := pkt[40:48]
				opts[0] = 1 // no-op
				opts[1] = 1 // no-op
				opts[2] = 2 // MSS
				opts[3] = 4
				binary.BigEndian.PutUint16(opts[4:6], 1400)
				return pkt
			}(),
			want: 1400,
		},
		{
			name: "ipv4-no-mss-option",
			pkt: func() []byte {
				pkt := make([]byte, 20+20)
				pkt[0] = 0x45
				pkt[9] = 6
				pkt[20+12] = 5 << 4 // no options at all
				return pkt
			}(),
			wantErr: true,
		},
		{
			name:    "truncated",
			pkt:     []byte{0x40, 0x00},
			wantErr: true,
		},
		{
			name: "not-tcp",
			pkt: func() []byte {
				pkt := ipv4SYNWithMSS(1460)
				pkt[9] = 17 // UDP
				return pkt
			}(),
			wantErr: true,
		},
		{
			name:    "bad-ip-version",
			pkt:     make([]byte, 60),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mssFromSavedSyn(tt.pkt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mssFromSavedSyn() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("mssFromSavedSyn() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMSSToLabel(t *testing.T) {
	tests := []struct {
		mss  uint16
		want string
	}{
		{0, "536"},
		{536, "536"},
		{537, "1220"},
		{1220, "1220"},
		{1240, "1240"},
		{1360, "1360"},
		{1400, "1400"},
		{1420, "1420"},
		{1440, "1440"},
		{1452, "1452"},
		{1460, "1460"},
		{1500, "8940"},
		{8940, "8940"},
		{8941, "inf"},
		{65535, "inf"},
	}
	for _, tt := range tests {
		if got := mssToLabel(tt.mss); got != tt.want {
			t.Errorf("mssToLabel(%d) = %q, want %q", tt.mss, got, tt.want)
		}
	}
}

// TestRecordSavedSynDisabled verifies that recordSavedSyn is a no-op when the
// server does not have TCP_SAVE_SYN recording enabled.
func TestRecordSavedSynDisabled(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	s.SetTCPSaveSyn(false)
	c := &sclient{s: s}
	c.recordSavedSyn()
	if got := s.tcpSavedSynStatus.String(); got != "{}" {
		t.Errorf("status map = %q, want empty", got)
	}
	if got := s.tcpSavedSynMSS.String(); got != "{}" {
		t.Errorf("MSS map = %q, want empty", got)
	}
}

func BenchmarkMSSToLabel(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		mssToLabel(uint16(1400 + i%100))
	}
}

// TestRecordSavedSynIntegration verifies the full TCP_SAVE_SYN flow over a
// real kernel TCP connection: TCP_SAVE_SYN set on the listening socket via
// net.ListenConfig.Control (as cmd/derper does), inherited by the accepted
// connection, the client's SYN packet recovered with TCP_SAVED_SYN, and the
// client's advertised MSS recorded to the histogram.
func TestRecordSavedSynIntegration(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	s.SetTCPSaveSyn(true)
	defer s.Close()

	// Listen with TCP_SAVE_SYN set in the socket's Control hook, like
	// cmd/derper does with --tcp-save-syn. Accepted connections inherit
	// the option.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			if e := c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
			}); e != nil {
				return e
			}
			return err
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tc := newWriterTestClient(t, s, ln)
	defer tc.close()

	// Wait for the client's run loop to fetch its saved SYN and record
	// the MSS. The client connected over loopback, where the kernel
	// advertises a very large MSS, so it lands in the "inf" bucket, but
	// don't depend on the kernel's choice of MSS.
	for deadline := time.Now().Add(10 * time.Second); ; {
		if st := s.tcpSavedSynStatus.Get("ok"); st != nil && st.Value() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("saved SYN never recorded; status = %s, MSS = %s", s.tcpSavedSynStatus.String(), s.tcpSavedSynMSS.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.tcpSavedSynMSS.String(); got == "{}" {
		t.Errorf("MSS histogram = %s; want one observation for a loopback client", got)
	}
}
