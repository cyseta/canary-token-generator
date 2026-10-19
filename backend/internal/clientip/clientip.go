// Package clientip determina la IP real del cliente de forma resistente a falsificacion.
//
// Regla de oro: las cabeceras de reenvio (X-Forwarded-For, X-Real-IP, CF-Connecting-IP) solo se
// consideran si la conexion TCP directa (RemoteAddr) proviene de un proxy de confianza. En caso
// contrario se usa RemoteAddr y las cabeceras se ignoran por completo.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	HeaderXFF        = "x-forwarded-for"
	HeaderXRealIP    = "x-real-ip"
	HeaderCloudflare = "cf-connecting-ip"
)

// DefaultTrusted cubre loopback y redes privadas: el tipico proxy inverso en Docker/Kubernetes.
var DefaultTrusted = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"fc00::/7", "fe80::/10",
}

type Resolver struct {
	trusted []netip.Prefix
	header  string
}

// New crea un Resolver. trusted vacio => DefaultTrusted. header vacio => x-forwarded-for.
func New(trusted []string, header string) (*Resolver, error) {
	if len(trusted) == 0 {
		trusted = DefaultTrusted
	}
	r := &Resolver{header: strings.ToLower(strings.TrimSpace(header))}
	if r.header == "" {
		r.header = HeaderXFF
	}
	switch r.header {
	case HeaderXFF, HeaderXRealIP, HeaderCloudflare:
	default:
		return nil, fmt.Errorf("clientip: unsupported header %q", header)
	}
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if p, err := netip.ParsePrefix(t); err == nil {
			r.trusted = append(r.trusted, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(t)
		if err != nil {
			return nil, fmt.Errorf("clientip: invalid trusted proxy %q", t)
		}
		r.trusted = append(r.trusted, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return r, nil
}

// Parse normaliza una IP (admite corchetes, puerto, zona IPv6 y IPv4 mapeada en IPv6).
func Parse(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// FromRequest devuelve siempre una IP valida y canonica (o "unknown" si RemoteAddr es ilegible).
func (r *Resolver) FromRequest(req *http.Request) string {
	host := req.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	peer, ok := Parse(host)
	if !ok {
		return "unknown"
	}
	if !r.isTrusted(peer) {
		return peer.String()
	}

	switch r.header {
	case HeaderXRealIP, HeaderCloudflare:
		if a, ok := Parse(req.Header.Get(r.header)); ok {
			return a.String()
		}
	default: // x-forwarded-for: recorrer de derecha a izquierda saltando proxies de confianza
		parts := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.TrimSpace(parts[i]) == "" {
				continue
			}
			a, ok := Parse(parts[i])
			if !ok {
				return peer.String() // entrada corrupta: la cadena no es fiable
			}
			if !r.isTrusted(a) {
				return a.String()
			}
		}
	}
	return peer.String()
}
