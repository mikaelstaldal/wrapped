package wrapped

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/things-go/go-socks5"
)

// matchHost reports whether host (with optional port) matches any of the allowed hosts.
// Supports exact match ("example.com") and wildcard subdomain ("*.example.com").
func matchHost(host string, allowedHosts []string) bool {
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	for _, pattern := range allowedHosts {
		pattern = strings.ToLower(pattern)
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // e.g. ".example.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// startHTTPProxy starts an HTTP/HTTPS proxy that only allows connections to allowedHosts.
// It returns the listener port, a close function, and any error.
func startHTTPProxy(allowedHosts []string) (int, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("http proxy listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, allowedHosts)
			} else {
				handleHTTP(w, r, allowedHosts)
			}
		}),
	}

	go server.Serve(listener)

	closer := func() {
		server.Close()
	}
	return port, closer, nil
}

func handleConnect(w http.ResponseWriter, r *http.Request, allowedHosts []string) {
	if !matchHost(r.Host, allowedHosts) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	host := r.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	target, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	client, _, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		return
	}

	go func() {
		io.Copy(target, client)
		target.Close()
	}()
	go func() {
		io.Copy(client, target)
		client.Close()
	}()
}

func handleHTTP(w http.ResponseWriter, r *http.Request, allowedHosts []string) {
	if !matchHost(r.URL.Host, allowedHosts) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// hostRuleSet implements socks5.RuleSet to filter connections by allowed hosts.
type hostRuleSet struct {
	allowedHosts []string
}

func (r *hostRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	host := req.DestAddr.FQDN
	if host == "" {
		host = req.DestAddr.IP.String()
	}
	return ctx, matchHost(host, r.allowedHosts)
}

// startSOCKS5Proxy starts a SOCKS5 proxy that only allows connections to allowedHosts.
// Returns the listener port, a close function, and any error.
func startSOCKS5Proxy(allowedHosts []string) (int, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("socks5 proxy listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	server := socks5.NewServer(
		socks5.WithRule(&hostRuleSet{allowedHosts: allowedHosts}),
	)

	go server.Serve(listener)

	closer := func() {
		listener.Close()
	}
	return port, closer, nil
}
