package mysql

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"canary-token-generator/backend/internal/clientip"
	"canary-token-generator/backend/internal/core"
	"canary-token-generator/backend/internal/event"
	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/seed"
)

// Banner creible (build de Ubuntu). La anterior "8.0.35-canary-audit" delataba el honeypot a cualquier
// escaner (nmap, Shodan) con solo leer el saludo.
const DefaultServerVersion = "8.0.39-0ubuntu0.22.04.1"

var globalConnID uint32

type ConnectionHandler struct {
	tokenRepo     token.Repository
	eventService  event.Service
	serverVersion string
}

func NewConnectionHandler(tokenRepo token.Repository, eventService event.Service) *ConnectionHandler {
	return &ConnectionHandler{tokenRepo: tokenRepo, eventService: eventService, serverVersion: DefaultServerVersion}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (h *ConnectionHandler) HandleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	// Una goroutine por conexion: un panic aqui tumbaria TODO el proceso (no hay Recovery HTTP que lo atrape).
	defer func() {
		if r := recover(); r != nil {
			core.IncErrors()
			slog.Error("panic in mysql honeypot handler", "error", r)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second)) // limite total por conexion

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	addr, ok := clientip.Parse(host)
	if !ok {
		return
	}
	clientIP := addr.String()

	connID := atomic.AddUint32(&globalConnID, 1)
	hello, salt := BuildHandshake(connID, h.serverVersion)
	if err := WritePacket(conn, 0, hello); err != nil {
		return
	}
	seq, payload, err := ReadPacket(conn)
	if err != nil {
		return // el cliente cerro (p.ej. un simple escaneo de puerto) o envio un paquete excesivo
	}
	auth, err := ParseHandshakeResponse41(payload)
	if err != nil {
		slog.Debug("mysql honeypot: unparsable handshake response", "ip", clientIP, "error", err)
		return
	}

	tok, matched := h.resolveToken(ctx, auth, salt)
	if tok == nil {
		// Trafico de fondo de internet (botnets que prueban root/admin en el 3306): NO es una deteccion.
		// Antes se atribuia al azar al primer token mysql reciente de cualquier usuario, generando
		// alertas falsas a terceros y revelando los datos del atacante a otro propietario.
		core.IncMySQLUnattributed()
		slog.Info("mysql honeypot: unattributed connection (no canary credentials)", "ip", clientIP, "username", clip(auth.Username, 64))
	} else {
		h.record(ctx, tok, auth, clientIP, matched)
	}

	using := "NO"
	if len(auth.AuthResponse) > 0 {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", clip(auth.Username, 64), clientIP, using)
	_ = WritePacket(conn, seq+1, BuildERRPacket(1045, "28000", msg))
}

// resolveToken atribuye la conexion SOLO por coincidencia exacta del ID codificado en el usuario.
func (h *ConnectionHandler) resolveToken(ctx context.Context, auth *ClientAuth, salt []byte) (*token.Token, string) {
	id, ok := seed.TokenIDFromMySQLUser(auth.Username)
	if !ok {
		return nil, ""
	}
	tok, err := h.tokenRepo.GetByID(ctx, id)
	if err != nil || !tok.IsActive || (tok.Type != "mysql" && tok.Type != "envfile") {
		return nil, ""
	}
	// Distingue "uso la credencial plantada" de "solo conocia el usuario".
	matched := "unknown"
	if seedHex := seed.FromMetadata(tok.Metadata); seedHex != "" && (auth.AuthPlugin == "" || auth.AuthPlugin == "mysql_native_password") {
		if VerifyNativePassword(salt, auth.AuthResponse, seed.MySQLPassword(seedHex, tok.ID)) {
			matched = "yes"
		} else {
			matched = "no"
		}
	}
	return tok, matched
}

func (h *ConnectionHandler) record(ctx context.Context, tok *token.Token, auth *ClientAuth, ip, matched string) {
	prog := auth.Attributes["program_name"]
	if prog == "" {
		prog = auth.Attributes["_client_name"]
	}
	ua := "MySQL-Client"
	if prog != "" {
		ua = clip(prog+" "+auth.Attributes["_client_version"], 200)
	}
	fp := map[string]any{"mysql_username": clip(auth.Username, 64), "mysql_database": clip(auth.Database, 64), "password_match": matched}
	if len(auth.Attributes) > 0 {
		fp["client_attributes"] = auth.Attributes
	}
	tc := event.TriggerContext{
		SourceIP: ip, UserAgent: ua, Protocol: "MYSQL",
		Headers:     map[string]string{"mysql_username": clip(auth.Username, 64), "mysql_database": clip(auth.Database, 64), "mysql_auth_plugin": clip(auth.AuthPlugin, 64)},
		Fingerprint: fp,
	}
	if _, err := h.eventService.RecordTrigger(ctx, tok.ToTarget(), tc); err != nil {
		slog.Error("FAILED TO RECORD MYSQL TRIGGER", "token_id", tok.ID, "error", err)
	}
}
