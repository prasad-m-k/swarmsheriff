// Package netutil holds network helpers shared by the listeners.
package netutil

import (
	"net"
)

// IsLoopback reports whether host resolves only to loopback, so the endpoint
// is never accidentally exposed to the network.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
