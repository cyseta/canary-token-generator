package mysql

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // exigido por el protocolo mysql_native_password
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxPacketSize limita el tamano de paquete aceptado ANTES de reservar memoria. Antes se hacia
// make([]byte, longitud) con la longitud declarada por un cliente SIN autenticar (hasta 16 MiB) para
// cada conexion: sin limite de conexiones, un DoS trivial de todo el proceso (incluida la API HTTP).
const MaxPacketSize = 64 * 1024

var (
	ErrPacketTooLarge = errors.New("mysql: packet too large")
	errShort          = errors.New("mysql: packet too short")
)

// Banderas de capacidad (protocolo MySQL).
const (
	capConnectWithDB       = 0x00000008
	capProtocol41          = 0x00000200
	capSSL                 = 0x00000800
	capSecureConnection    = 0x00008000
	capPluginAuth          = 0x00080000
	capConnectAttrs        = 0x00100000
	capPluginAuthLenencCli = 0x00200000
)

func WritePacket(w io.Writer, seq uint8, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return ErrPacketTooLarge
	}
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	_, err := w.Write(append(hdr, payload...))
	return err
}

func ReadPacket(r io.Reader) (uint8, []byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length > MaxPacketSize {
		return hdr[3], nil, ErrPacketTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

// newSalt genera 20 bytes sin NUL y de 7 bits, como un servidor MySQL real. Con bytes uniformes habia un
// 7,5% de conexiones con un 0x00 en el scramble, que algunos clientes interpretan como fin de cadena.
func newSalt() []byte {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = 1 + b[i]%127
	}
	return b
}

// BuildHandshake construye el saludo inicial (protocolo 10) y devuelve tambien el salt para poder
// verificar despues la respuesta del cliente.
func BuildHandshake(connectionID uint32, serverVersion string) (payload, salt []byte) {
	salt = newSalt()
	var b bytes.Buffer
	b.WriteByte(0x0a)
	b.WriteString(serverVersion)
	b.WriteByte(0x00)
	_ = binary.Write(&b, binary.LittleEndian, connectionID)
	b.Write(salt[:8])
	b.WriteByte(0x00)
	// Capacidades: sin SSL ni compresion; CON PLUGIN_AUTH y CONNECT_ATTRS para que el cliente envie sus atributos.
	const lower, upper = 0xf7df, 0x001f
	_ = binary.Write(&b, binary.LittleEndian, uint16(lower))
	b.WriteByte(0xff)                                         // utf8mb4_0900_ai_ci
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x0002)) // SERVER_STATUS_AUTOCOMMIT
	_ = binary.Write(&b, binary.LittleEndian, uint16(upper))
	b.WriteByte(21) // longitud de auth-plugin-data
	b.Write(make([]byte, 10))
	b.Write(salt[8:])
	b.WriteByte(0x00)
	b.WriteString("mysql_native_password")
	b.WriteByte(0x00)
	return b.Bytes(), salt
}

// BuildHandshakeV10 se mantiene por compatibilidad.
func BuildHandshakeV10(connectionID uint32, serverVersion string) []byte {
	p, _ := BuildHandshake(connectionID, serverVersion)
	return p
}

type ClientAuth struct {
	Username     string
	Database     string
	AuthPlugin   string
	AuthResponse []byte
	Capabilities uint32
	Attributes   map[string]string // _client_name, _client_version, _os, program_name...
}

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || r.pos+n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) cstr() string {
	if r.err != nil {
		return ""
	}
	i := bytes.IndexByte(r.b[r.pos:], 0)
	if i < 0 {
		r.err = errShort
		return ""
	}
	s := string(r.b[r.pos : r.pos+i])
	r.pos += i + 1
	return s
}

func (r *reader) lenenc() uint64 {
	f := r.take(1)
	if f == nil {
		return 0
	}
	switch {
	case f[0] < 0xfb:
		return uint64(f[0])
	case f[0] == 0xfc:
		if v := r.take(2); v != nil {
			return uint64(binary.LittleEndian.Uint16(v))
		}
	case f[0] == 0xfd:
		if v := r.take(3); v != nil {
			return uint64(v[0]) | uint64(v[1])<<8 | uint64(v[2])<<16
		}
	default:
		r.err = errShort // 0xfe (8 bytes) o 0xfb/0xff: no validos aqui
	}
	return 0
}

func (r *reader) lenencBytes(max int) []byte {
	n := r.lenenc()
	if r.err != nil || n > uint64(max) {
		r.err = errShort
		return nil
	}
	return r.take(int(n))
}

// ParseHandshakeResponse41 analiza la respuesta del cliente con comprobacion de limites en cada lectura.
func ParseHandshakeResponse41(payload []byte) (*ClientAuth, error) {
	if len(payload) < 32 {
		return nil, errShort
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	if caps&capProtocol41 == 0 {
		return nil, fmt.Errorf("mysql: unsupported client protocol")
	}
	if caps&capSSL != 0 && len(payload) == 32 {
		return nil, errors.New("mysql: client requested SSL, which is not offered")
	}
	r := &reader{b: payload, pos: 32}
	a := &ClientAuth{Capabilities: caps, Attributes: map[string]string{}}
	a.Username = r.cstr()

	switch {
	case caps&capPluginAuthLenencCli != 0:
		a.AuthResponse = r.lenencBytes(256)
	case caps&capSecureConnection != 0:
		if l := r.take(1); l != nil {
			a.AuthResponse = r.take(int(l[0]))
		}
	default:
		_ = r.cstr()
	}
	if caps&capConnectWithDB != 0 {
		a.Database = r.cstr()
	}
	if caps&capPluginAuth != 0 {
		a.AuthPlugin = r.cstr()
	}
	if caps&capConnectAttrs != 0 && r.err == nil {
		total := r.lenenc()
		if r.err == nil && total <= 4096 {
			ar := &reader{b: r.take(int(total))}
			for n := 0; ar.err == nil && ar.pos < len(ar.b) && n < 32; n++ {
				k, v := ar.lenencBytes(128), ar.lenencBytes(256)
				if ar.err == nil {
					a.Attributes[string(k)] = string(v)
				}
			}
		}
	}
	if r.err != nil && a.Username == "" {
		return nil, r.err
	}
	// Los campos opcionales truncados no invalidan la deteccion: lo importante es el usuario.
	return a, nil
}

// VerifyNativePassword comprueba la respuesta mysql_native_password:
//
//	token = SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))
func VerifyNativePassword(salt, authResponse []byte, password string) bool {
	if len(authResponse) != sha1.Size || len(salt) == 0 {
		return false
	}
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	mix := h.Sum(nil)
	expected := make([]byte, sha1.Size)
	for i := range expected {
		expected[i] = s1[i] ^ mix[i]
	}
	return subtle.ConstantTimeCompare(expected, authResponse) == 1
}

func BuildERRPacket(errorCode uint16, sqlState, message string) []byte {
	var b bytes.Buffer
	b.WriteByte(0xff)
	_ = binary.Write(&b, binary.LittleEndian, errorCode)
	b.WriteByte('#')
	b.WriteString(sqlState)
	b.WriteString(message)
	return b.Bytes()
}
