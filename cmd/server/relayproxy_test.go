package main

import (
	"log/slog"
	"net"
	"testing"

	"wacalls/internal/voip/socks5udp"
	"wacalls/internal/voip/socks5udp/socks5test"
)

func setRelayModeForTest(t *testing.T, m relayProxyMode) {
	relayModeOnce.Do(func() {})
	old := relayModeVal
	relayModeVal = m
	t.Cleanup(func() { relayModeVal = old })
}

func TestMediaPath(t *testing.T) {
	cases := []struct {
		mode  relayProxyMode
		proxy string
		want  string
	}{
		{relayProxyAuto, "", "direct"},
		{relayProxyStrict, "", "direct"},
		{relayProxyOff, "socks5://h:1", "direct"},
		{relayProxyAuto, "socks5://h:1", "proxy-if-udp"},
		{relayProxyStrict, "socks5://h:1", "proxy-only"},
		{relayProxyAuto, "http://h:1", "direct-fallback"},
		{relayProxyStrict, "http://h:1", "blocked"},
	}
	for _, c := range cases {
		if got := mediaPath(c.mode, c.proxy); got != c.want {
			t.Errorf("mediaPath(%s, %q) = %s, quero %s", c.mode, c.proxy, got, c.want)
		}
	}
}

func TestRelayNetForCallDecisions(t *testing.T) {
	s := &Session{log: slog.Default()}

	setRelayModeForTest(t, relayProxyAuto)
	if rn := s.relayNetForCall(); rn != nil {
		t.Fatal("sem proxy: mídia deve ser direta (nil)")
	}
	s.setProxy("http://u:p@h:1")
	if rn := s.relayNetForCall(); rn != nil {
		t.Fatal("auto + http: mídia direta (nil)")
	}
	s.setProxy("socks5://u:p@h:1")
	rn := s.relayNetForCall()
	if rn == nil || rn.Listen == nil || rn.Block != nil {
		t.Fatalf("auto + socks5: quero RelayNet com Listen, veio %+v", rn)
	}
	if rn.Label != "socks5://h:1" {
		t.Fatalf("Label com credenciais ou errado: %q", rn.Label)
	}

	setRelayModeForTest(t, relayProxyStrict)
	s.setProxy("http://u:p@h:1")
	if rn := s.relayNetForCall(); rn == nil || rn.Block == nil {
		t.Fatal("strict + http: quero Block")
	}

	setRelayModeForTest(t, relayProxyOff)
	s.setProxy("socks5://u:p@h:1")
	if rn := s.relayNetForCall(); rn != nil {
		t.Fatal("off: mídia direta (nil)")
	}
}

// auto: proxy socks5 SEM UDP → cai para UDP direto (e memoriza); strict → erro.
func TestRelayListenFallback(t *testing.T) {
	socks := socks5test.New(t, "", "")
	socks.RejectUDP = true
	s := &Session{log: slog.Default()}
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}

	listen := s.relayListen(socks.URL(), socks5udp.Redact(socks.URL()), relayProxyAuto)
	c, err := listen("udp4", laddr)
	if err != nil {
		t.Fatalf("auto deveria cair para UDP direto: %v", err)
	}
	if _, isProxy := c.(*socks5udp.Conn); isProxy {
		t.Fatal("auto sem UDP no proxy não deveria devolver conexão do proxy")
	}
	c.Close()
	if !proxyKnownWithoutUDP(socks.URL()) {
		t.Fatal("o proxy sem UDP deveria ficar em cache")
	}

	strict := s.relayListen(socks.URL(), "x", relayProxyStrict)
	if _, err := strict("udp4", laddr); err == nil {
		t.Fatal("strict deveria falhar quando o proxy não abre UDP")
	}

	ok := socks5test.New(t, "", "")
	c2, err := s.relayListen(ok.URL(), "y", relayProxyAuto)("udp4", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, isProxy := c2.(*socks5udp.Conn); !isProxy {
		t.Fatal("socks5 com UDP deveria devolver a conexão do proxy")
	}
}
