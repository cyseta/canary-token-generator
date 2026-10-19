// Package netguard protege contra SSRF en las peticiones salientes iniciadas por usuarios
// (webhooks). La validacion se hace en el momento de conectar (DialContext) sobre la IP ya
// resuelta, lo que neutraliza tambien DNS rebinding y redirecciones a redes internas.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrBlockedAddress = errors.New("destination address is not allowed")

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Policy struct {
	AllowPrivate bool          // permite destinos internos (solo para despliegues autoalojados de confianza)
	AllowHTTP    bool          // permite http:// ademas de https://
	Resolver     Resolver      // nil => net.DefaultResolver
	Timeout      time.Duration // 0 => 10s
}

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	"64:ff9b::/96", "2002::/16",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// IsBlockedIP indica si la IP pertenece a un rango no enrutable publicamente.
func IsBlockedIP(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ValidateURL valida sintacticamente una URL de webhook. No sustituye al control en el dial.
func ValidateURL(raw string, p Policy) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return nil, errors.New("url is empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("url is malformed")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return nil, errors.New("only https urls are allowed")
		}
	default:
		return nil, errors.New("only https urls are allowed")
	}
	if u.User != nil {
		return nil, errors.New("credentials in the url are not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("url has no host")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("url has an invalid port")
		}
	}
	if !p.AllowPrivate {
		lh := strings.ToLower(strings.TrimSuffix(host, "."))
		if lh == "localhost" || strings.HasSuffix(lh, ".localhost") || strings.HasSuffix(lh, ".local") ||
			strings.HasSuffix(lh, ".internal") || strings.HasSuffix(lh, ".lan") || !strings.Contains(lh, ".") && net.ParseIP(lh) == nil {
			return nil, errors.New("host is not allowed")
		}
		if a, err := netip.ParseAddr(host); err == nil && IsBlockedIP(a) {
			return nil, errors.New("host is not allowed")
		}
	}
	return u, nil
}

// NewClient devuelve un http.Client que nunca conecta a destinos bloqueados, no sigue
// redirecciones y no usa proxies del entorno.
func NewClient(p Policy) *http.Client {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res := p.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var ips []netip.Addr
			if a, err := netip.ParseAddr(host); err == nil {
				ips = []netip.Addr{a}
			} else if ips, err = res.LookupNetIP(ctx, "ip", host); err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %q: %w", host, errOrEmpty(err))
			}
			if !p.AllowPrivate {
				for _, ip := range ips { // si CUALQUIER respuesta es interna, se rechaza todo
					if IsBlockedIP(ip) {
						return nil, ErrBlockedAddress
					}
				}
			}
			var lastErr error
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func errOrEmpty(err error) error {
	if err == nil {
		return errors.New("no addresses")
	}
	return err
}
