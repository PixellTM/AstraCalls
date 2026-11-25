package socks5udp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

// fakeSocks é um servidor SOCKS5 mínimo (só UDP ASSOCIATE) para os testes.
type fakeSocks struct {
	t        *testing.T
	ln       net.Listener
	user     string
	pass     string
	rejectUD bool // responde 7 (command not supported) ao UDP ASSOCIATE

	mu      sync.Mutex
	relays  []*net.UDPConn
	ctrls   []net.Conn
	relayed int
}

func newFakeSocks(t *testing.T, user, pass string) *fakeSocks {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks{t: t, ln: ln, user: user, pass: pass}
	go s.serve()
	t.Cleanup(s.close)
	return s
}

func (s *fakeSocks) url() string {
	if s.user == "" {
		return "socks5://" + s.ln.Addr().String()
	}
	u := url.URL{Scheme: "socks5", User: url.UserPassword(s.user, s.pass), Host: s.ln.Addr().String()}
	return u.String()
}

func (s *fakeSocks) close() {
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

func (s *fakeSocks) dropControls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.ctrls {
		_ = c.Close()
	}
}

func (s *fakeSocks) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeSocks) handle(c net.Conn) {
	s.mu.Lock()
	s.ctrls = append(s.ctrls, c)
	s.mu.Unlock()
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	io.ReadFull(c, methods)
	if s.user != "" {
		c.Write([]byte{5, 2})
		var v [2]byte
		io.ReadFull(c, v[:])
		u := make([]byte, v[1])
		io.ReadFull(c, u)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		io.ReadFull(c, p)
		if string(u) != s.user || string(p) != s.pass {
			c.Write([]byte{1, 1})
			c.Close()
			return
		}
		c.Write([]byte{1, 0})
	} else {
		c.Write([]byte{5, 0})
	}
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if s.rejectUD || req[1] != 3 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	s.mu.Lock()
	s.relays = append(s.relays, relay)
	s.mu.Unlock()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	// BND.ADDR = 0.0.0.0 de propósito: o cliente deve usar o IP do proxy.
	rep := []byte{5, 0, 0, 1, 0, 0, 0, 0}
	rep = binary.BigEndian.AppendUint16(rep, uint16(port))
	c.Write(rep)

	var client *net.UDPAddr
	buf := make([]byte, 2048)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil || from.String() == client.String() {
			// datagrama do cliente: desencapsula e encaminha
			client = from
			payload, dst, err := decodeHeader(buf[:n])
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.relayed++
			s.mu.Unlock()
			relay.WriteToUDP(payload, dst)
			continue
		}
		// resposta de fora: encapsula com a origem e devolve ao cliente
		h, _ := encodeHeader(from)
		relay.WriteToUDP(append(h, buf[:n]...), client)
	}
}

// udpEcho devolve cada datagrama prefixado com o endereço de origem visto.
func udpEcho(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP([]byte(from.String()+"|"+string(buf[:n])), from)
		}
	}()
	return c
}

func TestRoundTripGoesThroughProxy(t *testing.T) {
	s := newFakeSocks(t, "u-ser", "p@ss:w/rd")
	echo := udpEcho(t)

	conn, err := Dial(context.Background(), s.url(), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	dst := echo.LocalAddr().(*net.UDPAddr)
	if _, err := conn.WriteTo([]byte("ola"), dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if from.String() != dst.String() {
		t.Fatalf("origem = %s, quero %s (o endereço real do destino)", from, dst)
	}
	got := string(buf[:n])
	// o eco viu o socket do PROXY, não o socket local do cliente
	seen := got[:len(got)-len("|ola")]
	if seen == conn.LocalAddr().String() {
		t.Fatalf("o destino viu o socket local do cliente (%s): não passou pelo proxy", seen)
	}
	if seen != conn.RelayAddr().String() {
		t.Fatalf("o destino viu %s, quero o relay do proxy %s", seen, conn.RelayAddr())
	}
	if got[len(got)-3:] != "ola" {
		t.Fatalf("payload = %q", got)
	}
}

func TestUDPNotSupported(t *testing.T) {
	s := newFakeSocks(t, "", "")
	s.rejectUD = true
	_, err := Dial(context.Background(), s.url(), 5*time.Second)
	if !errors.Is(err, ErrUDPNotSupported) {
		t.Fatalf("err = %v, quero ErrUDPNotSupported", err)
	}
}

func TestWrongPassword(t *testing.T) {
	s := newFakeSocks(t, "u", "certa")
	_, err := Dial(context.Background(), "socks5://u:errada@"+s.ln.Addr().String(), 5*time.Second)
	if err == nil {
		t.Fatal("esperava erro de autenticação")
	}
}

func TestHTTPProxyRejected(t *testing.T) {
	_, err := Dial(context.Background(), "http://u:p@127.0.0.1:1", time.Second)
	if !errors.Is(err, ErrNotSocks5) {
		t.Fatalf("err = %v, quero ErrNotSocks5", err)
	}
	if IsSocks5("http://x:1") || !IsSocks5("SOCKS5://x:1") || !IsSocks5("socks5h://x:1") {
		t.Fatal("IsSocks5 errado")
	}
	if r := Redact("socks5://user:senha@h:22228"); r != "socks5://h:22228" {
		t.Fatalf("Redact = %q", r)
	}
}

func TestControlDropEndsAssociation(t *testing.T) {
	s := newFakeSocks(t, "", "")
	conn, err := Dial(context.Background(), s.url(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.dropControls()
	select {
	case <-conn.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a associação não terminou quando o TCP de controle caiu")
	}
	if _, _, err := conn.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatal("ReadFrom deveria falhar com a associação encerrada")
	}
}

func TestIgnoresDatagramsNotFromProxy(t *testing.T) {
	s := newFakeSocks(t, "", "")
	conn, err := Dial(context.Background(), s.url(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// um terceiro manda direto para o socket local do cliente (fora do proxy)
	intruder, _ := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	defer intruder.Close()
	// ...com IP igual ao do proxy (127.0.0.1) mas cabeçalho inválido: deve ser descartado
	intruder.Write([]byte{1, 2})
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := conn.ReadFrom(make([]byte, 100)); err == nil {
		t.Fatalf("leu %d bytes de um datagrama inválido", n)
	}
}

func TestProbeWithFakeStun(t *testing.T) {
	s := newFakeSocks(t, "", "")
	stun, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stun.Close()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := stun.ReadFromUDP(buf)
		if err != nil || n < 20 {
			return
		}
		// Binding Success com XOR-MAPPED-ADDRESS = origem vista
		resp := make([]byte, 20, 32)
		binary.BigEndian.PutUint16(resp[0:], 0x0101)
		binary.BigEndian.PutUint16(resp[2:], 12)
		copy(resp[4:20], buf[4:20])
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:], 0x0020)
		binary.BigEndian.PutUint16(attr[2:], 8)
		attr[5] = 0x01
		binary.BigEndian.PutUint16(attr[6:], uint16(from.Port)^uint16(stunMagic>>16))
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], stunMagic)
		ip := from.IP.To4()
		for k := 0; k < 4; k++ {
			attr[8+k] = ip[k] ^ m[k]
		}
		stun.WriteToUDP(append(resp, attr...), from)
	}()
	res := Probe(context.Background(), s.url(), []string{stun.LocalAddr().String()})
	if !res.UDP {
		t.Fatalf("probe falhou: %+v", res)
	}
	if res.PublicAddr != res.ProxyRelay {
		t.Fatalf("STUN viu %s, quero o relay do proxy %s", res.PublicAddr, res.ProxyRelay)
	}
}
