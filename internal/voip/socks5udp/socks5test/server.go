// Package socks5test tem um servidor SOCKS5 mínimo (só UDP ASSOCIATE) para testes
// do patch leadmi (mídia das chamadas pelo proxy). Não é usado em produção.
package socks5test

import (
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
)

// Server é um SOCKS5 com usuário/senha opcional que só implementa UDP ASSOCIATE.
type Server struct {
	ln        net.Listener
	user      string
	pass      string
	RejectUDP bool // responde 7 (command not supported) ao UDP ASSOCIATE

	mu      sync.Mutex
	relays  []*net.UDPConn
	ctrls   []net.Conn
	relayed int
}

// New inicia o servidor em 127.0.0.1 e o encerra no fim do teste.
func New(t testing.TB, user, pass string) *Server {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ln: ln, user: user, pass: pass}
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// URL do proxy (socks5://[user:pass@]host:port).
func (s *Server) URL() string {
	u := url.URL{Scheme: "socks5", Host: s.ln.Addr().String()}
	if s.user != "" {
		u.User = url.UserPassword(s.user, s.pass)
	}
	return u.String()
}

// Addr do listener TCP.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Relayed: quantos datagramas do cliente o servidor encaminhou.
func (s *Server) Relayed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relayed
}

// RelayAddrs: endereços UDP dos relays abertos (o que o destino vê como origem).
func (s *Server) RelayAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.relays))
	for _, r := range s.relays {
		out = append(out, r.LocalAddr().String())
	}
	return out
}

// Associations: quantas associações UDP foram abertas.
func (s *Server) Associations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.relays)
}

// Close encerra tudo.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.relays {
		_ = r.Close()
	}
	for _, c := range s.ctrls {
		_ = c.Close()
	}
}

// DropControls derruba as conexões TCP de controle (encerra as associações).
func (s *Server) DropControls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.ctrls {
		_ = c.Close()
	}
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	s.mu.Lock()
	s.ctrls = append(s.ctrls, c)
	s.mu.Unlock()
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	_, _ = io.ReadFull(c, methods)
	if s.user != "" {
		_, _ = c.Write([]byte{5, 2})
		var v [2]byte
		_, _ = io.ReadFull(c, v[:])
		u := make([]byte, v[1])
		_, _ = io.ReadFull(c, u)
		var pl [1]byte
		_, _ = io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		_, _ = io.ReadFull(c, p)
		if string(u) != s.user || string(p) != s.pass {
			_, _ = c.Write([]byte{1, 1})
			_ = c.Close()
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0})
	}
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if s.RejectUDP || req[1] != 3 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		_ = c.Close()
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	s.mu.Lock()
	s.relays = append(s.relays, relay)
	s.mu.Unlock()
	// BND.ADDR = 0.0.0.0 de propósito: o cliente deve usar o IP do proxy.
	rep := []byte{5, 0, 0, 1, 0, 0, 0, 0}
	rep = binary.BigEndian.AppendUint16(rep, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
	_, _ = c.Write(rep)

	var client *net.UDPAddr
	buf := make([]byte, 4096)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil || from.String() == client.String() {
			client = from
			payload, dst, ok := decode(buf[:n])
			if !ok {
				continue
			}
			s.mu.Lock()
			s.relayed++
			s.mu.Unlock()
			_, _ = relay.WriteToUDP(payload, dst)
			continue
		}
		h := []byte{0, 0, 0, 1}
		h = append(h, from.IP.To4()...)
		h = binary.BigEndian.AppendUint16(h, uint16(from.Port))
		_, _ = relay.WriteToUDP(append(h, buf[:n]...), client)
	}
}

func decode(b []byte) ([]byte, *net.UDPAddr, bool) {
	if len(b) < 10 || b[2] != 0 || b[3] != 1 {
		return nil, nil, false
	}
	ip := net.IP(append([]byte(nil), b[4:8]...))
	port := int(binary.BigEndian.Uint16(b[8:10]))
	return b[10:], &net.UDPAddr{IP: ip, Port: port}, true
}
