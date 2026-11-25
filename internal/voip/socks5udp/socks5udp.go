// Package socks5udp implementa o lado cliente do UDP ASSOCIATE do SOCKS5 (RFC 1928,
// seção 7) com autenticação usuário/senha (RFC 1929).
//
// Uso no AstraCalls (patch leadmi): a mídia das chamadas (DTLS/SCTP/SRTP até o relay
// do WhatsApp na porta 3478) é UDP. Sem isto ela sai direto pelo IP do servidor,
// mesmo quando a sessão tem proxy (o proxy só cobria o websocket do whatsmeow).
// Com um proxy SOCKS5 que aceite UDP, cada conexão de relay passa a sair pelo IP
// do proxy, igual à sinalização.
//
// O Conn devolvido se comporta como um socket UDP não conectado: WriteTo(dst)
// encapsula o datagrama no cabeçalho SOCKS e manda para o relay UDP do proxy;
// ReadFrom devolve o datagrama já sem cabeçalho e com o endereço de ORIGEM real
// (o relay do WhatsApp), que é o que o ICE do pion compara com o candidato remoto.
package socks5udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUDPNotSupported: o proxy recusou o UDP ASSOCIATE (ex.: Bright Data responde 7,
// "command not supported"). Proxy HTTP também cai aqui (não existe UDP em HTTP).
var ErrUDPNotSupported = errors.New("proxy não aceita UDP (SOCKS5 UDP ASSOCIATE)")

// ErrNotSocks5: o proxy configurado não é socks5 (ex.: http/https).
var ErrNotSocks5 = errors.New("proxy não é socks5")

const (
	socksVersion   = 0x05
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xff
	cmdUDPAssoc    = 0x03
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	maxHeader      = 4 + 1 + 255 + 2 // RSV(2)+FRAG+ATYP + domínio máx + porta
)

var replyText = map[byte]string{
	0x01: "falha geral do servidor SOCKS",
	0x02: "conexão não permitida pelas regras",
	0x03: "rede inalcançável",
	0x04: "host inalcançável",
	0x05: "conexão recusada",
	0x06: "TTL expirou",
	0x07: "comando não suportado",
	0x08: "tipo de endereço não suportado",
}

// IsSocks5 diz se a URL de proxy é socks5/socks5h.
func IsSocks5(proxyURL string) bool {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return true
	}
	return false
}

// Redact devolve "esquema://host:porta" sem credenciais (para logs).
func Redact(proxyURL string) string {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || u.Host == "" {
		return "(proxy inválido)"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// Conn é a associação UDP aberta no proxy. Implementa net.PacketConn e a interface
// transport.UDPConn do pion (usada pelo ICE para os candidatos host).
type Conn struct {
	ctrl  net.Conn     // conexão TCP de controle: a associação vive enquanto ela estiver aberta
	udp   *net.UDPConn // socket local que fala com o relay UDP do proxy
	relay *net.UDPAddr // BND.ADDR/BND.PORT devolvido pelo proxy

	closeOnce sync.Once
	closed    chan struct{}
	ctrlErr   error
	mu        sync.Mutex
}

// Dial abre a conexão de controle, autentica, pede o UDP ASSOCIATE e devolve o Conn.
// O timeout cobre a negociação inteira.
func Dial(ctx context.Context, proxyURL string, timeout time.Duration) (*Conn, error) {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("URL de proxy inválida: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("%w (%s)", ErrNotSocks5, strings.ToLower(u.Scheme))
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "1080")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	ctrl, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("conexão TCP com o proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = ctrl.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		_ = ctrl.SetDeadline(dl)
	}

	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if err := handshake(ctrl, user, pass); err != nil {
		return nil, err
	}

	// UDP ASSOCIATE com DST zerado: ainda não sabemos de que IP:porta vamos mandar
	// (RFC 1928: o cliente pode mandar zeros quando não sabe).
	if _, err := ctrl.Write([]byte{socksVersion, cmdUDPAssoc, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("pedido UDP ASSOCIATE: %w", err)
	}
	rep, bnd, err := readReply(ctrl)
	if err != nil {
		return nil, fmt.Errorf("resposta do UDP ASSOCIATE: %w", err)
	}
	if rep != 0x00 {
		txt := replyText[rep]
		if txt == "" {
			txt = "código desconhecido"
		}
		if rep == 0x07 || rep == 0x02 {
			return nil, fmt.Errorf("%w: código %d (%s)", ErrUDPNotSupported, rep, txt)
		}
		return nil, fmt.Errorf("UDP ASSOCIATE recusado: código %d (%s)", rep, txt)
	}
	// BND.ADDR 0.0.0.0/:: = "o mesmo host do proxy" (comum em servidores atrás de NAT).
	if bnd.IP == nil || bnd.IP.IsUnspecified() {
		if ta, ok := ctrl.RemoteAddr().(*net.TCPAddr); ok {
			bnd.IP = ta.IP
		}
	}
	if bnd.Port == 0 {
		return nil, fmt.Errorf("UDP ASSOCIATE sem porta de relay")
	}

	network := "udp4"
	if bnd.IP.To4() == nil {
		network = "udp6"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, fmt.Errorf("socket UDP local: %w", err)
	}
	_ = ctrl.SetDeadline(time.Time{})

	c := &Conn{ctrl: ctrl, udp: udp, relay: bnd, closed: make(chan struct{})}
	go c.watchControl()
	ok = true
	return c, nil
}

func handshake(ctrl net.Conn, user, pass string) error {
	methods := []byte{methodNoAuth}
	if user != "" {
		methods = []byte{methodUserPass, methodNoAuth}
	}
	greet := append([]byte{socksVersion, byte(len(methods))}, methods...)
	if _, err := ctrl.Write(greet); err != nil {
		return fmt.Errorf("saudação SOCKS5: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(ctrl, sel[:]); err != nil {
		return fmt.Errorf("resposta da saudação SOCKS5: %w", err)
	}
	if sel[0] != socksVersion {
		return fmt.Errorf("o servidor não fala SOCKS5 (versão %d)", sel[0])
	}
	switch sel[1] {
	case methodNoAuth:
		return nil
	case methodUserPass:
		if user == "" {
			return fmt.Errorf("o proxy exige usuário e senha")
		}
		if len(user) > 255 || len(pass) > 255 {
			return fmt.Errorf("usuário/senha do proxy maiores que 255 bytes")
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := ctrl.Write(req); err != nil {
			return fmt.Errorf("autenticação SOCKS5: %w", err)
		}
		var st [2]byte
		if _, err := io.ReadFull(ctrl, st[:]); err != nil {
			return fmt.Errorf("resposta da autenticação SOCKS5: %w", err)
		}
		if st[1] != 0x00 {
			return fmt.Errorf("autenticação no proxy recusada")
		}
		return nil
	case methodNone:
		return fmt.Errorf("o proxy não aceitou nenhum método de autenticação")
	default:
		return fmt.Errorf("método de autenticação inesperado: %d", sel[1])
	}
}

// readReply lê VER REP RSV ATYP BND.ADDR BND.PORT.
func readReply(r io.Reader) (byte, *net.UDPAddr, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] != socksVersion {
		return 0, nil, fmt.Errorf("versão inválida na resposta: %d", h[0])
	}
	addr, err := readAddr(r, h[3])
	if err != nil {
		return h[1], nil, err
	}
	return h[1], addr, nil
}

func readAddr(r io.Reader, atyp byte) (*net.UDPAddr, error) {
	var ip net.IP
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(string(name))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("não foi possível resolver BND.ADDR %q", name)
		}
		ip = ips[0]
	default:
		return nil, fmt.Errorf("ATYP desconhecido: %d", atyp)
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(p[:]))}, nil
}

// watchControl: a associação morre quando a conexão TCP de controle cai (RFC 1928).
// Nesse caso fechamos o socket UDP para destravar quem estiver lendo.
func (c *Conn) watchControl() {
	buf := make([]byte, 64)
	for {
		if _, err := c.ctrl.Read(buf); err != nil {
			c.mu.Lock()
			if c.ctrlErr == nil {
				c.ctrlErr = fmt.Errorf("conexão de controle do proxy encerrada: %w", err)
			}
			c.mu.Unlock()
			_ = c.Close()
			return
		}
	}
}

// RelayAddr é o endereço UDP do relay do proxy (para logs).
func (c *Conn) RelayAddr() *net.UDPAddr { return c.relay }

func encodeHeader(dst *net.UDPAddr) ([]byte, error) {
	if dst == nil || dst.IP == nil {
		return nil, fmt.Errorf("destino UDP inválido")
	}
	var h []byte
	if ip4 := dst.IP.To4(); ip4 != nil {
		h = make([]byte, 0, 10)
		h = append(h, 0, 0, 0, atypIPv4)
		h = append(h, ip4...)
	} else {
		h = make([]byte, 0, 22)
		h = append(h, 0, 0, 0, atypIPv6)
		h = append(h, dst.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(h, uint16(dst.Port)), nil
}

// decodeHeader devolve (payload, origem). Datagramas fragmentados (FRAG != 0) não são
// suportados e são descartados (nenhum servidor comum fragmenta).
func decodeHeader(b []byte) ([]byte, *net.UDPAddr, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("datagrama SOCKS curto")
	}
	if b[2] != 0 {
		return nil, nil, fmt.Errorf("datagrama SOCKS fragmentado")
	}
	var ip net.IP
	off := 4
	switch b[3] {
	case atypIPv4:
		if len(b) < off+4+2 {
			return nil, nil, fmt.Errorf("datagrama SOCKS curto")
		}
		ip = net.IP(append([]byte(nil), b[off:off+4]...))
		off += 4
	case atypIPv6:
		if len(b) < off+16+2 {
			return nil, nil, fmt.Errorf("datagrama SOCKS curto")
		}
		ip = net.IP(append([]byte(nil), b[off:off+16]...))
		off += 16
	case atypDomain:
		if len(b) < off+1 {
			return nil, nil, fmt.Errorf("datagrama SOCKS curto")
		}
		l := int(b[off])
		if len(b) < off+1+l+2 {
			return nil, nil, fmt.Errorf("datagrama SOCKS curto")
		}
		ips, err := net.LookupIP(string(b[off+1 : off+1+l]))
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("origem com domínio não resolvido")
		}
		ip = ips[0]
		off += 1 + l
	default:
		return nil, nil, fmt.Errorf("ATYP desconhecido no datagrama: %d", b[3])
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	return b[off:], &net.UDPAddr{IP: ip, Port: port}, nil
}

// WriteTo encapsula p e manda ao relay UDP do proxy, endereçado a addr.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		r, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, err
		}
		ua = r
	}
	return c.WriteToUDP(p, ua)
}

// WriteToUDP: ver WriteTo.
func (c *Conn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	h, err := encodeHeader(addr)
	if err != nil {
		return 0, err
	}
	pkt := make([]byte, 0, len(h)+len(p))
	pkt = append(pkt, h...)
	pkt = append(pkt, p...)
	if _, err := c.udp.WriteToUDP(pkt, c.relay); err != nil {
		return 0, c.wrapErr(err)
	}
	return len(p), nil
}

// ReadFrom lê o próximo datagrama vindo do relay do proxy. Pacotes de qualquer outra
// origem (que não o proxy) são ignorados.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.ReadFromUDP(p)
	if a == nil {
		return n, nil, err
	}
	return n, a, err
}

// ReadFromUDP: ver ReadFrom.
func (c *Conn) ReadFromUDP(p []byte) (int, *net.UDPAddr, error) {
	buf := make([]byte, len(p)+maxHeader)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, c.wrapErr(err)
		}
		if !from.IP.Equal(c.relay.IP) {
			continue // não veio do proxy: descarta
		}
		payload, src, derr := decodeHeader(buf[:n])
		if derr != nil {
			continue
		}
		return copy(p, payload), src, nil
	}
}

// ReadMsgUDP existe só para satisfazer a interface do pion (não há OOB pelo proxy).
func (c *Conn) ReadMsgUDP(b, _ []byte) (int, int, int, *net.UDPAddr, error) {
	n, a, err := c.ReadFromUDP(b)
	return n, 0, 0, a, err
}

// WriteMsgUDP existe só para satisfazer a interface do pion.
func (c *Conn) WriteMsgUDP(b, _ []byte, addr *net.UDPAddr) (int, int, error) {
	n, err := c.WriteToUDP(b, addr)
	return n, 0, err
}

// Read/Write: o Conn não é "conectado"; só ReadFrom/WriteTo fazem sentido.
func (c *Conn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFromUDP(b)
	return n, err
}

func (c *Conn) Write([]byte) (int, error) {
	return 0, fmt.Errorf("socks5udp: Write sem destino; use WriteTo")
}

func (c *Conn) wrapErr(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctrlErr != nil {
		return c.ctrlErr
	}
	return err
}

// Close encerra a associação (TCP de controle) e o socket UDP.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.ctrl.Close()
		_ = c.udp.Close()
	})
	return nil
}

// Done fecha quando a associação termina.
func (c *Conn) Done() <-chan struct{} { return c.closed }

func (c *Conn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return nil }
func (c *Conn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }
func (c *Conn) SetReadBuffer(n int) error          { return c.udp.SetReadBuffer(n) }
func (c *Conn) SetWriteBuffer(n int) error         { return c.udp.SetWriteBuffer(n) }

// String: "socks5 udp via <relay>" para logs.
func (c *Conn) String() string {
	return "socks5 udp via " + net.JoinHostPort(c.relay.IP.String(), strconv.Itoa(c.relay.Port))
}
