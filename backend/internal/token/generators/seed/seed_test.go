package seed

import (
	"hash/crc32"
	"regexp"
	"strings"
	"testing"
)

func TestDeterministicAndIndependent(t *testing.T) {
	a1 := New("abc", "aws").Pick(Base62, 40)
	a2 := New("abc", "aws").Pick(Base62, 40)
	b := New("abc", "db").Pick(Base62, 40)
	c := New("abd", "aws").Pick(Base62, 40)
	if a1 != a2 {
		t.Fatal("misma semilla+proposito debe dar mismos bytes")
	}
	if a1 == b || a1 == c {
		t.Fatal("proposito/semilla distintos deben dar salidas distintas")
	}
	if New("", "x").Pick(Base62, 20) == New("", "x").Pick(Base62, 20) {
		t.Fatal("sin semilla debe ser aleatorio")
	}
}

func TestPickAlphabetAndUniformity(t *testing.T) {
	s := New("u", "p")
	out := s.Pick(Base32, 20000)
	counts := map[rune]int{}
	for _, r := range out {
		if !strings.ContainsRune(Base32, r) {
			t.Fatalf("caracter fuera de alfabeto: %q", r)
		}
		counts[r]++
	}
	for _, r := range Base32 { // esperado 625 +-; tolerancia amplia
		if counts[r] < 450 || counts[r] > 800 {
			t.Fatalf("sesgo sospechoso para %q: %d", r, counts[r])
		}
	}
}

func TestGitHubTokenFormatAndChecksum(t *testing.T) {
	tok := New("s", "gh").GitHubToken()
	if !regexp.MustCompile(`^ghp_[0-9A-Za-z]{36}$`).MatchString(tok) {
		t.Fatalf("formato invalido: %s", tok)
	}
	body, chk := tok[4:34], tok[34:]
	sum := crc32.ChecksumIEEE([]byte(body))
	var want [6]byte
	for i := 5; i >= 0; i-- {
		want[i] = Base62[sum%62]
		sum /= 62
	}
	if chk != string(want[:]) {
		t.Fatalf("checksum incorrecto %s != %s", chk, want)
	}
}

func TestMySQLUserRoundTrip(t *testing.T) {
	id := "c" + strings.Repeat("ab12", 6)
	u := MySQLUser(id)
	if len(u) > 32 || strings.Contains(strings.ToLower(u), "canary") {
		t.Fatalf("usuario invalido: %s", u)
	}
	got, ok := TokenIDFromMySQLUser(u)
	if !ok || got != id {
		t.Fatalf("round trip fallo: %q %v", got, ok)
	}
	for _, bad := range []string{"root", "svc_", "svc_short", "svc_" + strings.Repeat("Z", 24), "canary_" + id[:12], "xsvc_" + id[1:]} {
		if _, ok := TokenIDFromMySQLUser(bad); ok {
			t.Fatalf("no deberia aceptar %q", bad)
		}
	}
	if MySQLPassword("s", id) != MySQLPassword("s", id) || MySQLPassword("s", id) == MySQLPassword("t", id) {
		t.Fatal("password debe ser estable y depender de la semilla")
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	s := NewSeed()
	if FromMetadata(Metadata(s)) != s || len(s) != 32 {
		t.Fatal("metadata roundtrip")
	}
	if FromMetadata("{}") != "" || FromMetadata("garbage") != "" {
		t.Fatal("debe tolerar metadata sin semilla")
	}
}
