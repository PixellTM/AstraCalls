package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	pt "github.com/pion/transport/v4"

	"wacalls/internal/voip/socks5udp"
	"wacalls/internal/voip/socks5udp/socks5test"
)

// fakeRelay registra a ORIGEM de cada datagrama recebido (é o que o WhatsApp veria).
type fakeRelay struct {
	conn *net.UDPConn
	mu   sync.Mutex
	srcs []string
}

func newFakeRelay(t *testing.T) *fakeRelay {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{conn: c}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			_, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.srcs = append(r.srcs, from.String())
			r.mu.Unlock()
		}
	}()
	return r
}

func (r *fakeRelay) port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *fakeRelay) sources() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.srcs...)
}

func (r *fakeRelay) waitPackets(t *testing.T, d time.Duration) []string {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s := r.sources(); len(s) > 0 {
			time.Sleep(200 * time.Millisecond) // junta mais alguns
			return r.sources()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func proxyNet(proxyURL string) *RelayNet {
	return &RelayNet{
		Label: socks5udp.Redact(proxyURL),
		Listen: func(network string, laddr *net.UDPAddr) (pt.UDPConn, error) {
			return socks5udp.Dial(context.Background(), proxyURL, 5*time.Second)
		},
	}
}

func testRelayConfig(port int) RelayConfig {
	return RelayConfig{IP: "127.0.0.1", Port: port, Token: "tok", AuthToken: "authtok", Key: "chave-do-relay", Name: "teste"}
}

// Com RelayNet, TODO pacote que chega ao relay vem do relay UDP do proxy.
func TestSctpRelayMediaGoesThroughProxy(t *testing.T) {
	socks := socks5test.New(t, "usuario", "s3nh@")
	relay := newFakeRelay(t)

	m := NewSctpRelayManager(nil)
	m.SetRelayNet(proxyNet(socks.URL()))
	m.connectToRelay(testRelayConfig(relay.port())) // retorna após montar a conexão (o ICE segue em background)
	t.Cleanup(m.Cleanup)

	srcs := relay.waitPackets(t, 8*time.Second)
	if len(srcs) == 0 {
		t.Fatal("o relay não recebeu nada (ICE não enviou pelo proxy)")
	}
	allowed := map[string]bool{}
	for _, a := range socks.RelayAddrs() {
		allowed[a] = true
	}
	for _, s := range srcs {
		if !allowed[s] {
			t.Fatalf("pacote chegou de %s, fora do proxy (relays do proxy: %v)", s, socks.RelayAddrs())
		}
	}
	if socks.Relayed() == 0 {
		t.Fatal("o proxy não encaminhou nenhum datagrama")
	}
	if n := socks.Associations(); n != 1 {
		t.Fatalf("associações abertas = %d, quero 1 (um candidato host só)", n)
	}
}

// Sem RelayNet (original): os pacotes NÃO passam pelo proxy. Garante que o teste
// acima distingue os dois caminhos.
func TestSctpRelayDirectWithoutRelayNet(t *testing.T) {
	socks := socks5test.New(t, "", "")
	relay := newFakeRelay(t)

	m := NewSctpRelayManager(nil)
	m.connectToRelay(testRelayConfig(relay.port())) // retorna após montar a conexão (o ICE segue em background)
	t.Cleanup(m.Cleanup)

	srcs := relay.waitPackets(t, 8*time.Second)
	if len(srcs) == 0 {
		t.Skip("ICE direto não alcançou 127.0.0.1 neste ambiente")
	}
	if socks.Associations() != 0 {
		t.Fatal("sem RelayNet não deveria abrir associação")
	}
}

// Block: a conexão falha na hora e nenhum pacote sai.
func TestSctpRelayBlocked(t *testing.T) {
	relay := newFakeRelay(t)
	m := NewSctpRelayManager(nil)
	m.SetRelayNet(&RelayNet{Label: "http://x:1", Block: errors.New("proxy http não transporta UDP")})
	done := make(chan struct{})
	go func() { m.connectToRelay(testRelayConfig(relay.port())); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connectToRelay deveria retornar na hora com Block")
	}
	if srcs := relay.waitPackets(t, time.Second); len(srcs) != 0 {
		t.Fatalf("com Block nenhum pacote deveria sair, chegaram %d", len(srcs))
	}
}

// Relay de grupo (DTLS direto): o ClientHello chega pelo proxy.
func TestGroupRelayGoesThroughProxy(t *testing.T) {
	socks := socks5test.New(t, "", "")
	relay := newFakeRelay(t)
	go func() { _, _ = ConnectGroupRelay("127.0.0.1", relay.port(), proxyNet(socks.URL())) }()

	srcs := relay.waitPackets(t, 5*time.Second)
	if len(srcs) == 0 {
		t.Fatal("o relay de grupo não recebeu o handshake")
	}
	allowed := map[string]bool{}
	for _, a := range socks.RelayAddrs() {
		allowed[a] = true
	}
	for _, s := range srcs {
		if !allowed[s] {
			t.Fatalf("handshake de grupo chegou de %s, fora do proxy", s)
		}
	}
}
