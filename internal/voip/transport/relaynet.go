package transport

// Patch leadmi: rede da MÍDIA das chamadas por sessão.
//
// Sem isto, a mídia (UDP até o relay do WhatsApp na 3478) sempre saía direto pelo IP
// do servidor, mesmo com proxy na sessão. O RelayNet permite que a sessão diga por
// onde cada conexão de relay abre o seu "socket UDP" (ex.: UDP ASSOCIATE no proxy
// SOCKS5 da sessão). nil = comportamento original (UDP direto).

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/pion/ice/v4"
	pt "github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/webrtc/v4"
)

// ListenFunc abre o socket UDP de UMA conexão de mídia com o relay. laddr é o endereço
// local que o ICE pediria (interface do container, porta 0).
type ListenFunc func(network string, laddr *net.UDPAddr) (pt.UDPConn, error)

// RelayNet descreve por onde sai a mídia das chamadas de uma sessão.
type RelayNet struct {
	// Listen abre o socket de cada conexão de relay. Obrigatório (exceto com Block).
	Listen ListenFunc
	// Label descreve o caminho para logs, SEM credenciais (ex.: "socks5://host:22228").
	Label string
	// Block, se != nil, impede a mídia de sair (modo strict sem proxy utilizável):
	// a conexão com o relay falha na hora, com este erro no log.
	Block error
}

// listenPacket abre um socket para o relay de grupo (DTLS direto, sem ICE).
func (r *RelayNet) listenPacket() (net.PacketConn, error) {
	if r.Block != nil {
		return nil, r.Block
	}
	return r.Listen("udp4", &net.UDPAddr{IP: net.IPv4zero})
}

// relayPionNet é a rede do pion com o ListenUDP trocado pelo do RelayNet. O resto
// (Interfaces, Resolve*, TCP) segue o stdnet. O ICE do relay só usa candidatos host
// UDP (sem STUN/TURN e com mDNS desligado), então só o ListenUDP importa.
type relayPionNet struct {
	*stdnet.Net
	listen ListenFunc
}

func (n *relayPionNet) ListenUDP(network string, laddr *net.UDPAddr) (pt.UDPConn, error) {
	return n.listen(network, laddr)
}

func (n *relayPionNet) ListenPacket(network, address string) (net.PacketConn, error) {
	if strings.HasPrefix(network, "udp") {
		laddr, err := n.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return n.listen(network, laddr)
	}
	return n.Net.ListenPacket(network, address)
}

// webrtcAPI monta uma API do pion que abre os sockets pelo RelayNet. Uma por conexão
// de relay (é barata) para que cada uma use o proxy vigente da sessão.
func (r *RelayNet) webrtcAPI() (*webrtc.API, error) {
	std, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("relay net: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	s.SetNet(&relayPionNet{Net: std, listen: r.Listen})
	// Só IPv4/UDP (o relay é IPv4) e um único IP local: cada IP local vira um
	// candidato host e cada candidato abriria uma associação no proxy.
	s.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	var (
		mu     sync.Mutex
		chosen net.IP
	)
	s.SetIPFilter(func(ip net.IP) bool {
		if ip.To4() == nil {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if chosen == nil {
			chosen = append(net.IP(nil), ip...)
		}
		return ip.Equal(chosen)
	})
	return webrtc.NewAPI(webrtc.WithSettingEngine(s)), nil
}
