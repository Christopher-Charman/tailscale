// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
)

const (
	osnetMagicDNSDomain = "tailnet.test"

	osnetSplitDomain = "corp.example"
	osnetSplitHost   = "host." + osnetSplitDomain

	// Outside the block testcontrol assigns, so only quad-100 can answer this.
	osnetSplitIP = "100.99.99.99"
)

// startTUNNode starts a node using the operating system's networking stack.
func startTUNNode(t *testing.T, env *TestEnv) *TestNode {
	t.Helper()
	return startAndUp(t, NewTestNode(t, env, TUNMode(true)))
}

// startPeer starts a userspace peer, since the host has only one TUN slot.
func startPeer(t *testing.T, env *TestEnv, upArgs ...string) *TestNode {
	t.Helper()
	return startAndUp(t, NewTestNode(t, env, TUNMode(false)), upArgs...)
}

func startAndUp(t *testing.T, n *TestNode, upArgs ...string) *TestNode {
	t.Helper()
	d := n.StartDaemon()
	n.AwaitResponding()
	n.MustUp(upArgs...)
	n.AwaitRunning()
	t.Cleanup(func() { d.MustCleanShutdown(t) })
	return n
}

// awaitResolves waits for name to resolve to want through the system resolver.
func awaitResolves(t *testing.T, name, want string) {
	t.Helper()
	if err := tstest.WaitFor(60*time.Second, func() error {
		got, err := net.DefaultResolver.LookupHost(t.Context(), name)
		if err != nil {
			return fmt.Errorf("resolving %s: %w", name, err)
		}
		if !slices.Contains(got, want) {
			return fmt.Errorf("%s resolved to %v, want %s", name, got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// assertNoAnswer fails if name resolves. Call it only after a lookup succeeds.
func assertNoAnswer(t *testing.T, name string) {
	t.Helper()
	if got, err := net.DefaultResolver.LookupHost(t.Context(), name); err == nil {
		t.Errorf("%s resolved to %v, want no answer", name, got)
	}
}

// serveToken answers every connection with token, identifying this listener.
func serveToken(t *testing.T, ln net.Listener, token string) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(token))
			c.Close()
		}
	}()
}

// dialThrough dials addr:port over the tailnet and returns what it read.
func dialThrough(t *testing.T, lc *local.Client, addr string, port uint16) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := lc.DialTCP(ctx, addr, port)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// hostIPv4 returns a non-loopback, non-Tailscale IPv4 address of this host.
func hostIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		p, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(p.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !tsaddr.IsTailscaleIP(ip) {
			return ip
		}
	}
	t.Skip("no routable IPv4 address on this host")
	return netip.Addr{}
}

func TestMagicDNS(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = osnetMagicDNSDomain
		control.DNSConfig = &tailcfg.DNSConfig{Proxied: true}
	}))
	n := startTUNNode(t, env)

	self := strings.TrimSuffix(n.MustStatus().Self.DNSName, ".")
	if self == "" {
		t.Fatal("node has no MagicDNS name")
	}
	awaitResolves(t, self, n.AwaitIP4().String())
	assertNoAnswer(t, "nosuchnode."+osnetMagicDNSDomain)
}

func TestSplitDNS(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = osnetMagicDNSDomain
		control.DNSConfig = &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				osnetSplitDomain: nil, // answer locally, from ExtraRecords
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: osnetSplitHost, Type: "A", Value: osnetSplitIP},
			},
		}
	}))
	startTUNNode(t, env)

	awaitResolves(t, osnetSplitHost, osnetSplitIP)
	assertNoAnswer(t, "nosuchhost."+osnetSplitDomain)
}

func TestIncomingConnections(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t)
	n1 := startTUNNode(t, env)
	n2 := startPeer(t, env)

	// Unspecified address, since the packet arrives on the tailnet IP.
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const token = "reached-the-listener"
	serveToken(t, ln, token)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	lc2 := n2.LocalClient()
	target := n1.AwaitIP4().String()

	// Reaching the listener means the OS network stack delivered the packet.
	if err := tstest.WaitFor(30*time.Second, func() error {
		got, err := dialThrough(t, lc2, target, port)
		if err != nil {
			return err
		}
		if got != token {
			return fmt.Errorf("read %q, want %q", got, token)
		}
		return nil
	}); err != nil {
		t.Fatalf("shields down: %v (health: %q)", err, n1.MustStatus().Health)
	}

	if err := n1.Tailscale("set", "--shields-up=true").Run(); err != nil {
		t.Fatalf("set --shields-up=true: %v", err)
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		if _, err := dialThrough(t, lc2, target, port); err == nil {
			return fmt.Errorf("connection succeeded with shields up")
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

func TestSubnetRoutes(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t)

	dst := hostIPv4(t)
	ln, err := net.Listen("tcp4", net.JoinHostPort(dst.String(), "0"))
	if err != nil {
		t.Fatalf("listening on %v: %v", dst, err)
	}
	defer ln.Close()
	const token = "routed-through-the-subnet-router"
	serveToken(t, ln, token)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	route := netip.PrefixFrom(dst, dst.BitLen())
	n1 := startTUNNode(t, env)
	if err := n1.Tailscale("set", "--advertise-routes="+route.String()).Run(); err != nil {
		t.Fatalf("set --advertise-routes: %v", err)
	}
	env.Control.SetSubnetRoutes(n1.MustStatus().Self.PublicKey, []netip.Prefix{route})

	n2 := startPeer(t, env, "--accept-routes")

	// Arriving means n1 took the packet in and sent it on to the host.
	if err := tstest.WaitFor(60*time.Second, func() error {
		got, err := dialThrough(t, n2.LocalClient(), dst.String(), port)
		if err != nil {
			return err
		}
		if got != token {
			return fmt.Errorf("read %q, want %q", got, token)
		}
		return nil
	}); err != nil {
		t.Fatalf("subnet route %v port %d: %v", route, port, err)
	}
}
