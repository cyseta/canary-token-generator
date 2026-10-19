package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range f[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "224.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1"}
	for _, s := range blocked {
		if !IsBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s deberia estar bloqueada", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if IsBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s deberia estar permitida", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	ok := []string{"https://hooks.example.com/abc", "https://example.com:8443/x?y=1"}
	bad := []string{"", "http://example.com/x", "ftp://example.com", "https://user:pw@example.com/", "https:///nohost",
		"https://localhost/x", "https://127.0.0.1/x", "https://169.254.169.254/latest/meta-data", "https://[::1]/x",
		"https://intranet/x", "https://svc.internal/x", "https://example.com:99999/", "javascript:alert(1)",
		"https://example.com/" + strings.Repeat("a", 3000)}
	for _, s := range ok {
		if _, err := ValidateURL(s, Policy{}); err != nil {
			t.Errorf("%q deberia ser valida: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ValidateURL(s, Policy{}); err == nil {
			t.Errorf("%q deberia ser rechazada", s)
		}
	}
	if _, err := ValidateURL("http://10.0.0.5/hook", Policy{AllowPrivate: true, AllowHTTP: true}); err != nil {
		t.Errorf("con AllowPrivate+AllowHTTP debe aceptarse: %v", err)
	}
}

func TestClientBlocksLoopbackAndRebinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("internal-secret")) }))
	defer srv.Close()

	// 1) destino loopback literal
	_, err := NewClient(Policy{AllowHTTP: true}).Get(srv.URL)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("esperaba ErrBlockedAddress, got %v", err)
	}
	// 2) hostname publico que RESUELVE a metadata cloud (rebinding / DNS malicioso)
	res := fakeResolver{"evil.test": {"169.254.169.254"}, "mixed.test": {"8.8.8.8", "127.0.0.1"}}
	for _, h := range []string{"evil.test", "mixed.test"} {
		_, err = NewClient(Policy{Resolver: res}).Get("https://" + h + "/")
		if !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("%s: esperaba ErrBlockedAddress, got %v", h, err)
		}
	}
	// 3) con AllowPrivate (autoalojado) si conecta
	resp, err := NewClient(Policy{AllowPrivate: true, AllowHTTP: true}).Get(srv.URL)
	if err != nil {
		t.Fatalf("con AllowPrivate deberia conectar: %v", err)
	}
	resp.Body.Close()
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("la redireccion NO debe seguirse") }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redir.Close()
	resp, err := NewClient(Policy{AllowPrivate: true, AllowHTTP: true}).Get(redir.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("esperaba 302 sin seguir, got %d", resp.StatusCode)
	}
}
