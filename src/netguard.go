package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// blockedNets are refused for every user, including allow_any, on every hop.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
		"::/128",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("bad blocked CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}()

// isBlockedIP reports whether an address is in a range Aegis refuses to reach.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1) to its IPv4 form so a
	// mapped address cannot slip past the IPv4 ranges.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveGuard is the pre-flight check used by the request pipeline. It is a
// variable solely so tests can substitute a stub; production code never
// reassigns it, and the dialer performs the same check again at connect time,
// so nothing depends on this indirection for safety.
var resolveGuard = resolveAndCheck

// resolveAndCheck resolves a host and returns the addresses that are safe to
// dial. If any resolved address is blocked, the whole host is refused - a
// partially private DNS answer is a strong signal of an attack, not something
// to work around.
func resolveAndCheck(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("destination address is in a blocked range")
		}
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve host")
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("host has no addresses")
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			return nil, fmt.Errorf("destination address is in a blocked range")
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// guardedDialer resolves, checks and then dials the checked IP directly, so a
// name cannot resolve to a public address during the check and a private one
// at connect time (DNS rebinding).
func guardedDialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || isBlockedIP(ip) {
				return fmt.Errorf("destination address is in a blocked range")
			}
			return nil
		},
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := resolveAndCheck(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
