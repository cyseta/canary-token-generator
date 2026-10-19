package mysql

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

type Server struct {
	port    int
	handler *ConnectionHandler

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	maxConns int
	maxPerIP int
	mu       sync.Mutex
	active   int
	perIP    map[string]int
}

func NewServer(port int, handler *ConnectionHandler) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{port: port, handler: handler, ctx: ctx, cancel: cancel, maxConns: 256, maxPerIP: 8, perIP: map[string]int{}}
}

// SetLimits fija el maximo de conexiones simultaneas totales y por IP. Antes no existia ningun limite.
func (s *Server) SetLimits(maxConns, maxPerIP int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxConns > 0 {
		s.maxConns = maxConns
	}
	if maxPerIP > 0 {
		s.maxPerIP = maxPerIP
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.listener = ln
	slog.Info("mysql honeypot listening", "port", s.port, "max_conns", s.maxConns, "max_per_ip", s.maxPerIP)
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Addr devuelve la direccion de escucha (util en tests con puerto 0).
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

func (s *Server) admit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= s.maxConns || s.perIP[ip] >= s.maxPerIP {
		return false
	}
	s.active++
	s.perIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// El error de un listener cerrado llega ENVUELTO en *net.OpError: hay que usar errors.Is
			// (una comparacion directa con == nunca coincide y el bucle giraba sin fin).
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			slog.Error("mysql accept error", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.admit(ip) {
			conn.Close() // saturado: se descarta sin gastar memoria ni goroutines
			continue
		}
		s.wg.Add(1) // los manejadores tambien se esperan en el apagado
		go func() {
			defer s.wg.Done()
			defer s.release(ip)
			s.handler.HandleConnection(s.ctx, conn)
		}()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel() // primero: el bucle de accept y los manejadores ven la cancelacion
	if s.listener != nil {
		_ = s.listener.Close()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}
