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

// hostFilter is a function that reports whether a given host (with optional port) is allowed.
type hostFilter func(host string) bool

// matchHost reports whether the host matches any of the given patterns.
// Supports exact match ("example.com") and wildcard subdomain ("*.example.com").
func matchHost(host string, patterns []string) bool {
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	for _, pattern := range patterns {
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

// allowListFilter returns a hostFilter that allows only the given hosts.
func allowListFilter(allowedHosts []string) hostFilter {
	return func(host string) bool {
		return matchHost(host, allowedHosts)
	}
}

// denyListFilter returns a hostFilter that allows all hosts except the given ones.
func denyListFilter(deniedHosts []string) hostFilter {
	return func(host string) bool {
		return !matchHost(host, deniedHosts)
	}
}

// startHTTPProxy starts an HTTP/HTTPS proxy that filters connections using the given hostFilter.
// It returns the listener port, a close function, and any error.
func startHTTPProxy(filter hostFilter) (int, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("http proxy listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, filter)
			} else {
				handleHTTP(w, r, filter)
			}
		}),
	}

	go server.Serve(listener)

	closer := func() {
		_ = server.Close()
	}
	return port, closer, nil
}

func handleConnect(w http.ResponseWriter, r *http.Request, filter hostFilter) {
	if !filter(r.Host) {
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
		_ = target.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = target.Close()
		return
	}

	go func() {
		_, _ = io.Copy(target, client)
		_ = target.Close()
	}()
	go func() {
		_, _ = io.Copy(client, target)
		_ = client.Close()
	}()
}

func handleHTTP(w http.ResponseWriter, r *http.Request, filter hostFilter) {
	if !filter(r.URL.Host) {
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
	_, _ = io.Copy(w, resp.Body)
}

// filterRuleSet implements socks5.RuleSet using a hostFilter.
type filterRuleSet struct {
	filter hostFilter
}

func (r *filterRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	host := req.DestAddr.FQDN
	if host == "" {
		host = req.DestAddr.IP.String()
	}
	return ctx, r.filter(host)
}

// startSOCKS5Proxy starts a SOCKS5 proxy that filters connections using the given hostFilter.
// Returns the listener port, a close function, and any error.
func startSOCKS5Proxy(filter hostFilter) (int, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("socks5 proxy listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	server := socks5.NewServer(
		socks5.WithRule(&filterRuleSet{filter: filter}),
	)

	go server.Serve(listener)

	closer := func() {
		_ = listener.Close()
	}
	return port, closer, nil
}
