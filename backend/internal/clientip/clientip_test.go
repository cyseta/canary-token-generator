package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func req(remote string, hdr map[string][]string) *http.Request {
	r := httptest.NewRequest("GET", "/t/x", nil)
	r.RemoteAddr = remote
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestFromRequest(t *testing.T) {
	std, _ := New(nil, "")
	cf, _ := New(nil, "cf-connecting-ip")
	rip, _ := New(nil, "x-real-ip")
	tests := []struct {
		name string
		res  *Resolver
		r    *http.Request
		want string
	}{
		{"peer publico: XFF falsificado se ignora", std, req("203.0.113.50:4444", map[string][]string{"X-Forwarded-For": {"8.8.8.8"}}), "203.0.113.50"},
		{"peer publico: CF-Connecting-IP falsificado se ignora", cf, req("203.0.113.50:4444", map[string][]string{"Cf-Connecting-Ip": {"8.8.8.8"}}), "203.0.113.50"},
		{"proxy de confianza: usa XFF", std, req("10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}}), "198.51.100.7"},
		{"cadena: el atacante antepone IPs falsas, gana la mas a la derecha no confiable", std, req("10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1, 198.51.100.7, 10.0.0.9"}}), "198.51.100.7"},
		{"varias lineas XFF", std, req("10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1", "198.51.100.7"}}), "198.51.100.7"},
		{"entrada corrupta => peer", std, req("10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"198.51.100.7, " + strings.Repeat("A", 100)}}), "10.0.0.5"},
		{"XFF con puerto y IPv6", std, req("10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"[2001:db8::1]:5000"}}), "2001:db8::1"},
		{"sin cabecera => peer", std, req("10.0.0.5:1", nil), "10.0.0.5"},
		{"peer IPv6 con corchetes", std, req("[2001:db8::9]:80", nil), "2001:db8::9"},
		{"IPv4 mapeada se normaliza", std, req("[::ffff:203.0.113.9]:80", nil), "203.0.113.9"},
		{"cloudflare valido", cf, req("10.0.0.5:1", map[string][]string{"Cf-Connecting-Ip": {"198.51.100.7"}}), "198.51.100.7"},
		{"cloudflare basura => peer", cf, req("10.0.0.5:1", map[string][]string{"Cf-Connecting-Ip": {strings.Repeat("A", 100)}}), "10.0.0.5"},
		{"x-real-ip", rip, req("127.0.0.1:1", map[string][]string{"X-Real-Ip": {"198.51.100.7"}}), "198.51.100.7"},
		{"RemoteAddr ilegible", std, req("garbage", nil), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.FromRequest(tc.r); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New([]string{"not-an-ip"}, ""); err == nil {
		t.Fatal("esperaba error por proxy invalido")
	}
	if _, err := New(nil, "x-evil"); err == nil {
		t.Fatal("esperaba error por cabecera no soportada")
	}
	if r, err := New([]string{"203.0.113.1"}, ""); err != nil || !r.isTrusted(mustAddr("203.0.113.1")) {
		t.Fatal("una IP suelta debe aceptarse como /32")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
