// Package seed ofrece aleatoriedad DETERMINISTA por token para los artefactos senuelo.
//
// Cada token guarda una semilla aleatoria (crypto/rand) en su columna metadata. Los artefactos se
// derivan de ella con HMAC-SHA256, de modo que descargar el artefacto varias veces produce
// siempre exactamente los mismos bytes (antes cambiaban en cada descarga) sin que sean
// predecibles para un tercero.
package seed

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"strings"
)

const (
	Base62    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	Base32    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // formato real de los AWS Access Key ID
	Base64    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	Base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	LowerHex  = "0123456789abcdef"
)

// NewSeed genera una semilla nueva (16 bytes aleatorios, hex).
func NewSeed() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // Go >= 1.24: nunca devuelve error; en versiones previas el fallo es catastrofico igualmente
	return hex.EncodeToString(b)
}

// Meta es lo que se persiste en tokens.metadata: la semilla y las opciones ya validadas con las que
// se creo el token (antes las opciones se perdian y la descarga volvia a la receta por defecto).
type Meta struct {
	Seed    string         `json:"seed"`
	Options map[string]any `json:"options,omitempty"`
}

// EncodeMeta serializa semilla y opciones para la columna tokens.metadata.
func EncodeMeta(seedHex string, options map[string]any) string {
	b, _ := json.Marshal(Meta{Seed: seedHex, Options: options})
	return string(b)
}

// DecodeMeta extrae semilla y opciones de tokens.metadata (vacios si no existen).
func DecodeMeta(meta string) (string, map[string]any) {
	var m Meta
	_ = json.Unmarshal([]byte(meta), &m)
	return m.Seed, m.Options
}

// Metadata serializa solo la semilla.
func Metadata(seedHex string) string { return EncodeMeta(seedHex, nil) }

// FromMetadata extrae la semilla de tokens.metadata ("" si no existe).
func FromMetadata(meta string) string { s, _ := DecodeMeta(meta); return s }

type Stream struct {
	key []byte
	ctr uint64
	buf []byte
}

// New crea un flujo determinista para un proposito concreto. Si seedHex esta vacio (tokens
// antiguos o tests) se usa una semilla aleatoria efimera.
func New(seedHex, purpose string) *Stream {
	if seedHex == "" {
		seedHex = NewSeed()
	}
	m := hmac.New(sha256.New, []byte(seedHex))
	m.Write([]byte("canary/seed/v1:" + purpose))
	return &Stream{key: m.Sum(nil)}
}

func (s *Stream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(s.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], s.ctr)
			s.ctr++
			m := hmac.New(sha256.New, s.key)
			m.Write(c[:])
			s.buf = m.Sum(nil)
		}
		k := copy(p[n:], s.buf)
		s.buf = s.buf[k:]
		n += k
	}
	return n, nil
}

// Pick devuelve n caracteres uniformes del alfabeto (muestreo por rechazo, sin sesgo de modulo).
func (s *Stream) Pick(alphabet string, n int) string {
	limit := 256 - (256 % len(alphabet))
	out := make([]byte, 0, n)
	var b [1]byte
	for len(out) < n {
		_, _ = s.Read(b[:])
		if int(b[0]) >= limit {
			continue
		}
		out = append(out, alphabet[int(b[0])%len(alphabet)])
	}
	return string(out)
}

func (s *Stream) Bytes(n int) []byte { b := make([]byte, n); _, _ = s.Read(b); return b }

// GitHubToken genera un token con el formato moderno ghp_ + 30 aleatorios + 6 de checksum CRC32
// (base62), por lo que supera las comprobaciones de formato de los escaneres de secretos.
func (s *Stream) GitHubToken() string {
	body := s.Pick(Base62, 30)
	sum := crc32.ChecksumIEEE([]byte(body))
	enc := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		enc[i] = Base62[sum%62]
		sum /= 62
	}
	return "ghp_" + body + string(enc)
}

// ---- credenciales del honeypot MySQL -------------------------------------------------------

const userPrefix = "svc_"

// MySQLUser deriva un nombre de usuario creible que codifica el ID COMPLETO del token
// (max 28 chars, por debajo del limite de 32 de MySQL).
func MySQLUser(tokenID string) string { return userPrefix + strings.TrimPrefix(tokenID, "c") }

// TokenIDFromMySQLUser invierte MySQLUser. Solo acepta el formato exacto c+24 hex.
func TokenIDFromMySQLUser(user string) (string, bool) {
	if !strings.HasPrefix(user, userPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(user, userPrefix)
	if len(rest) != 24 {
		return "", false
	}
	for _, r := range rest {
		if !strings.ContainsRune(LowerHex, r) {
			return "", false
		}
	}
	return "c" + rest, true
}

// MySQLPassword deriva la contrasena senuelo del token (estable entre descargas) y permite al
// honeypot comprobar si el atacante uso EXACTAMENTE la credencial plantada.
func MySQLPassword(seedHex, tokenID string) string {
	return New(seedHex, "mysql-password:"+tokenID).Pick(Base62, 20)
}
