package main

// Patch leadmi: mídia das chamadas pelo proxy da sessão.
//
// Original: o proxy da sessão (PUT /api/sessions/{sid}/proxy) só valia para o websocket
// e a mídia do whatsmeow. O áudio/vídeo das chamadas (UDP até o relay do WhatsApp na
// 3478) saía DIRETO pelo IP do servidor, então o WhatsApp via a conta em dois IPs ao
// mesmo tempo (o do proxy e o do servidor).
//
// Agora, com proxy socks5 que aceite UDP ASSOCIATE, a mídia sai pelo mesmo proxy.
//
// WACALLS_RELAY_PROXY:
//   auto   (padrão) socks5 com UDP → mídia pelo proxy; proxy http/https ou socks5 sem
//          UDP → mídia direta (comportamento original), com WARN no log.
//   strict mídia só pelo proxy: se a sessão tem proxy e ele não transporta UDP, a
//          chamada fica sem mídia (falha) em vez de expor o IP do servidor.
//   off    comportamento original (mídia sempre direta).
// Sessões SEM proxy não mudam em nenhum modo.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	pt "github.com/pion/transport/v4"

	"wacalls/internal/voip/socks5udp"
	"wacalls/internal/voip/transport"
)

type relayProxyMode string

const (
	relayProxyOff    relayProxyMode = "off"
	relayProxyAuto   relayProxyMode = "auto"
	relayProxyStrict relayProxyMode = "strict"

	// relayProxyDialTimeout: negociação SOCKS5 por conexão de relay (o relay dá 20s).
	relayProxyDialTimeout = 8 * time.Second
	// noUDPCacheTTL: depois que um proxy recusa UDP, o modo auto não tenta de novo
	// por este tempo (evita atrasar cada chamada com 3 negociações que vão falhar).
	noUDPCacheTTL = 10 * time.Minute
)

var (
	relayModeOnce sync.Once
	relayModeVal  relayProxyMode

	noUDPMu    sync.Mutex
	noUDPUntil = map[string]time.Time{} // chave: URL do proxy
)

func currentRelayProxyMode() relayProxyMode {
	relayModeOnce.Do(func() {
		raw := strings.ToLower(strings.TrimSpace(envStr("WACALLS_RELAY_PROXY", "auto")))
		switch relayProxyMode(raw) {
		case relayProxyOff, relayProxyAuto, relayProxyStrict:
			relayModeVal = relayProxyMode(raw)
		default:
			relayModeVal = relayProxyAuto
		}
	})
	return relayModeVal
}

func proxyKnownWithoutUDP(proxy string) bool {
	noUDPMu.Lock()
	defer noUDPMu.Unlock()
	until, ok := noUDPUntil[proxy]
	if ok && time.Now().Before(until) {
		return true
	}
	delete(noUDPUntil, proxy)
	return false
}

func markProxyWithoutUDP(proxy string) {
	noUDPMu.Lock()
	noUDPUntil[proxy] = time.Now().Add(noUDPCacheTTL)
	noUDPMu.Unlock()
}

// mediaPath descreve por onde a mídia de uma sessão com este proxy vai sair.
func mediaPath(mode relayProxyMode, proxy string) string {
	switch {
	case proxy == "" || mode == relayProxyOff:
		return "direct"
	case socks5udp.IsSocks5(proxy) && mode == relayProxyStrict:
		return "proxy-only"
	case socks5udp.IsSocks5(proxy):
		return "proxy-if-udp"
	case mode == relayProxyStrict:
		return "blocked"
	default:
		return "direct-fallback"
	}
}

// relayNetForCall decide, com o proxy VIGENTE da sessão, por onde a mídia de uma nova
// conexão com o relay sai. nil = UDP direto (original).
func (s *Session) relayNetForCall() *transport.RelayNet {
	mode := currentRelayProxyMode()
	proxy := s.getProxy()
	if mode == relayProxyOff || proxy == "" {
		return nil
	}
	label := socks5udp.Redact(proxy)
	if !socks5udp.IsSocks5(proxy) {
		if mode == relayProxyStrict {
			return &transport.RelayNet{
				Label: label,
				Block: fmt.Errorf("proxy %s não transporta UDP; use socks5 com UDP ou WACALLS_RELAY_PROXY=auto", label),
			}
		}
		s.log.Warn("mídia da chamada DIRETA pelo IP do servidor: proxy da sessão não é socks5", "proxy", label)
		return nil
	}
	return &transport.RelayNet{Label: label, Listen: s.relayListen(proxy, label, mode)}
}

func (s *Session) relayListen(proxy, label string, mode relayProxyMode) transport.ListenFunc {
	return func(network string, laddr *net.UDPAddr) (pt.UDPConn, error) {
		if mode == relayProxyAuto && proxyKnownWithoutUDP(proxy) {
			s.log.Warn("mídia da chamada DIRETA pelo IP do servidor: proxy sem UDP (cache)", "proxy", label)
			return net.ListenUDP(network, laddr)
		}
		c, err := socks5udp.Dial(context.Background(), proxy, relayProxyDialTimeout)
		if err == nil {
			s.log.Info("mídia: associação UDP aberta no proxy", "proxy", label, "relay_udp", c.RelayAddr().String())
			return c, nil
		}
		if errors.Is(err, socks5udp.ErrUDPNotSupported) {
			markProxyWithoutUDP(proxy)
		}
		if mode == relayProxyStrict {
			s.log.Warn("mídia BLOQUEADA: não foi possível abrir UDP no proxy", "proxy", label, "err", err)
			return nil, err
		}
		s.log.Warn("mídia da chamada DIRETA pelo IP do servidor: o proxy não abriu UDP", "proxy", label, "err", err)
		return net.ListenUDP(network, laddr)
	}
}

// POST /api/sessions/{sid}/proxy/udp-test   { "proxy": "socks5://..." }  (opcional)
// Testa se o proxy (o do corpo, ou o da sessão) transporta UDP: abre UDP ASSOCIATE e
// faz um STUN; publicAddr deve ser o IP do proxy.
func (s *server) handleProxyUDPTest(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionByID(w, r.PathValue("sid"))
	if sess == nil {
		return
	}
	proxy, ok := proxyFromBody(w, r)
	if !ok {
		return
	}
	if proxy == "" {
		proxy = sess.getProxy()
	}
	writeProxyUDPTest(w, r, proxy)
}

// POST /api/proxy/udp-test { "proxy": "socks5://..." } — mesmo teste, sem sessão
// (para validar um proxy antes de usar).
func (s *server) handleProxyUDPTestGlobal(w http.ResponseWriter, r *http.Request) {
	proxy, ok := proxyFromBody(w, r)
	if !ok {
		return
	}
	writeProxyUDPTest(w, r, proxy)
}

func proxyFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b struct {
		Proxy string `json:"proxy"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload inválido"})
			return "", false
		}
	}
	p := strings.TrimSpace(b.Proxy)
	if p != "" {
		if err := validateProxy(p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return "", false
		}
	}
	return p, true
}

func writeProxyUDPTest(w http.ResponseWriter, r *http.Request, proxy string) {
	if proxy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sem proxy para testar"})
		return
	}
	mode := currentRelayProxyMode()
	out := map[string]any{
		"proxy":          socks5udp.Redact(proxy),
		"relayProxyMode": string(mode),
		"media":          mediaPath(mode, proxy),
	}
	if !socks5udp.IsSocks5(proxy) {
		out["udp"] = false
		out["error"] = "proxy http/https não transporta UDP; use socks5"
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := socks5udp.Probe(ctx, proxy, nil)
	if res.UDP {
		noUDPMu.Lock()
		delete(noUDPUntil, proxy)
		noUDPMu.Unlock()
	}
	out["udp"] = res.UDP
	if res.PublicAddr != "" {
		out["publicAddr"] = res.PublicAddr
	}
	if res.ProxyRelay != "" {
		out["proxyRelay"] = res.ProxyRelay
	}
	if res.Server != "" {
		out["stunServer"] = res.Server
		out["rttMs"] = res.RTTMs
	}
	if res.Error != "" {
		out["error"] = res.Error
	}
	writeJSON(w, http.StatusOK, out)
}
