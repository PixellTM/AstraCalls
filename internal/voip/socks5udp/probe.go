package socks5udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DefaultProbeServers: servidores STUN públicos usados no teste de UDP do proxy.
var DefaultProbeServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

// ProbeResult é o resultado do teste de UDP por um proxy.
type ProbeResult struct {
	UDP        bool   `json:"udp"`                  // o proxy aceitou o UDP ASSOCIATE e o STUN respondeu
	PublicAddr string `json:"publicAddr,omitempty"` // IP:porta que o servidor STUN viu (deve ser o IP do proxy)
	ProxyRelay string `json:"proxyRelay,omitempty"` // endereço UDP do relay do proxy
	Server     string `json:"server,omitempty"`     // servidor STUN que respondeu
	RTTMs      int64  `json:"rttMs,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Probe abre um UDP ASSOCIATE no proxy e manda um STUN Binding Request para um
// servidor público. Se responder, o UDP passa pelo proxy e PublicAddr é o IP de saída.
func Probe(ctx context.Context, proxyURL string, servers []string) ProbeResult {
	if len(servers) == 0 {
		servers = DefaultProbeServers
	}
	conn, err := Dial(ctx, proxyURL, 15*time.Second)
	if err != nil {
		return ProbeResult{Error: err.Error()}
	}
	defer conn.Close()
	res := ProbeResult{ProxyRelay: conn.RelayAddr().String()}

	var lastErr error
	for _, s := range servers {
		dst, err := net.ResolveUDPAddr("udp4", s)
		if err != nil {
			lastErr = err
			continue
		}
		mapped, rtt, err := stunBinding(conn, dst, 4*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", s, err)
			continue
		}
		res.UDP, res.PublicAddr, res.Server, res.RTTMs = true, mapped, s, rtt.Milliseconds()
		return res
	}
	if lastErr != nil {
		res.Error = "UDP ASSOCIATE aceito, mas nenhum STUN respondeu: " + lastErr.Error()
	}
	return res
}

const stunMagic = 0x2112A442

func stunBinding(c *Conn, dst *net.UDPAddr, timeout time.Duration) (string, time.Duration, error) {
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], stunMagic)
	if _, err := rand.Read(req[8:20]); err != nil {
		return "", 0, err
	}
	start := time.Now()
	if _, err := c.WriteToUDP(req, dst); err != nil {
		return "", 0, err
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return "", 0, fmt.Errorf("sem resposta: %w", err)
		}
		if !from.IP.Equal(dst.IP) || n < 20 || string(buf[8:20]) != string(req[8:20]) {
			continue
		}
		if a := parseMapped(buf[:n]); a != "" {
			return a, time.Since(start), nil
		}
		return "", 0, fmt.Errorf("resposta STUN sem endereço mapeado")
	}
}

func parseMapped(b []byte) string {
	i := 20
	for i+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[i:])
		l := int(binary.BigEndian.Uint16(b[i+2:]))
		if i+4+l > len(b) {
			return ""
		}
		v := b[i+4 : i+4+l]
		if (t == 0x0020 || t == 0x0001) && l >= 8 && v[1] == 0x01 {
			port := binary.BigEndian.Uint16(v[2:])
			ip := append([]byte(nil), v[4:8]...)
			if t == 0x0020 {
				port ^= uint16(stunMagic >> 16)
				var m [4]byte
				binary.BigEndian.PutUint32(m[:], stunMagic)
				for k := range ip {
					ip[k] ^= m[k]
				}
			}
			return net.JoinHostPort(net.IP(ip).String(), fmt.Sprint(port))
		}
		i += 4 + l + (4-l%4)%4
	}
	return ""
}
