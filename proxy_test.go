package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDialer подменяет ядро Xray: цепочки ведут в локальные echo-серверы,
// поэтому проверяется именно протокол прокси и раскладка по цепочкам.
type fakeDialer struct {
	mu      sync.Mutex
	circ    *Circuits
	echo    net.Listener
	seen    map[int][]string // слот -> обслуженные цели
	failing map[int]bool     // слоты, которые «не дозваниваются»
}

func newFakeDialer(t *testing.T, count int, reject map[int][]string) *fakeDialer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return &fakeDialer{
		circ: fakeCircuits(count, reject), echo: l,
		seen: map[int][]string{}, failing: map[int]bool{},
	}
}

func (f *fakeDialer) Pick(host string, port int) *Slot { return f.circ.Pick(host, port) }
func (f *fakeDialer) Report(s *Slot, ok bool)          { f.circ.Report(s, ok) }

func (f *fakeDialer) Dial(ctx context.Context, s *Slot, host string, port int) (net.Conn, error) {
	f.mu.Lock()
	broken := f.failing[s.Idx]
	if !broken {
		f.seen[s.Idx] = append(f.seen[s.Idx], fmt.Sprintf("%s:%d", host, port))
	}
	f.mu.Unlock()
	if broken {
		return nil, fmt.Errorf("цепочка недоступна")
	}
	return net.Dial("tcp", f.echo.Addr().String())
}

func (f *fakeDialer) served() map[int][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int][]string{}
	for k, v := range f.seen {
		out[k] = append([]string{}, v...)
	}
	return out
}

func (f *fakeDialer) usedSlots() []int {
	var out []int
	for idx, v := range f.served() {
		if len(v) > 0 {
			out = append(out, idx)
		}
	}
	return out
}

func startProxy(t *testing.T, d Dialer) (socksAddr, httpAddr string) {
	t.Helper()
	p := &Proxy{D: d, Logf: func(string, ...any) {}}
	sl, err := p.ServeSOCKS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hl, err := p.ServeHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return sl.Addr().String(), hl.Addr().String()
}

// ── SOCKS5 ───────────────────────────────────────────────────────────────

func socksDial(t *testing.T, proxy, host string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != repOK {
		c.Close()
		return nil, rep[1]
	}
	return c, repOK
}

func TestSOCKSConnectAndEcho(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	socks, _ := startProxy(t, d)

	c, code := socksDial(t, socks, "example.com", 443)
	if code != repOK {
		t.Fatalf("SOCKS5 отказ %d", code)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("эхо вернуло %q", buf)
	}
	if used := d.usedSlots(); len(used) != 1 {
		t.Fatalf("задействовано слотов: %v", used)
	}
}

func TestSOCKSKeepsOneHostOnOneCircuit(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	socks, _ := startProxy(t, d)
	for i := 0; i < 6; i++ {
		c, code := socksDial(t, socks, "sticky.example", 443)
		if code != repOK {
			t.Fatalf("отказ %d", code)
		}
		c.Close()
	}
	used := d.usedSlots()
	if len(used) != 1 {
		t.Fatalf("один хост размазался по слотам %v", used)
	}
	if got := len(d.served()[used[0]]); got != 6 {
		t.Fatalf("слот обслужил %d соединений из 6", got)
	}
}

func TestSOCKSSpreadsDifferentHosts(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	socks, _ := startProxy(t, d)
	for i := 0; i < 40; i++ {
		c, code := socksDial(t, socks, fmt.Sprintf("h%d.example", i), 443)
		if code == repOK {
			c.Close()
		}
	}
	if used := d.usedSlots(); len(used) < 2 {
		t.Fatalf("все хосты ушли в один слот: %v", used)
	}
}

func TestSOCKSRefusesPortBlockedByEveryExit(t *testing.T) {
	d := newFakeDialer(t, 2, map[int][]string{0: {"25"}, 1: {"1-100"}})
	socks, _ := startProxy(t, d)
	if _, code := socksDial(t, socks, "mail.example", 25); code != repNotAllowed {
		t.Fatalf("ожидали отказ %d, получили %d", repNotAllowed, code)
	}
	c, code := socksDial(t, socks, "mail.example", 587)
	if code != repOK {
		t.Fatalf("разрешённый порт отвергнут: %d", code)
	}
	c.Close()
}

func TestSOCKSPicksExitThatAllowsPort(t *testing.T) {
	d := newFakeDialer(t, 4, map[int][]string{0: {"25"}, 1: {"25"}, 2: {"25"}})
	socks, _ := startProxy(t, d)
	c, code := socksDial(t, socks, "mail.example", 25)
	if code != repOK {
		t.Fatalf("отказ %d", code)
	}
	c.Close()
	if used := d.usedSlots(); len(used) != 1 || used[0] != 3 {
		t.Fatalf("порт 25 обслужили слоты %v, а пропускает его только третий", used)
	}
}

func TestSOCKSFailsOverToAnotherCircuit(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	socks, _ := startProxy(t, d)
	d.circ.opts.FailThreshold = 1

	target := "failover.example"
	first := d.circ.Pick(target, 443)
	d.mu.Lock()
	d.failing[first.Idx] = true
	d.mu.Unlock()

	if _, code := socksDial(t, socks, target, 443); code == repOK {
		t.Fatal("сломанная цепочка не должна отдавать успех")
	}
	c, code := socksDial(t, socks, target, 443)
	if code != repOK {
		t.Fatalf("после сбоя соединение должно уйти в другую цепочку, код %d", code)
	}
	c.Close()
	for _, idx := range d.usedSlots() {
		if idx == first.Idx {
			t.Fatal("трафик снова попал в сломанную цепочку")
		}
	}
}

func TestSOCKSRejectsUDPAssociate(t *testing.T) {
	d := newFakeDialer(t, 2, nil)
	socks, _ := startProxy(t, d)

	c, err := net.Dial("tcp", socks)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	host := "example.com"
	req := append([]byte{5, 3, 0, 3, byte(len(host))}, host...) // 3 = UDP ASSOCIATE
	req = binary.BigEndian.AppendUint16(req, 443)
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != repCmdUnsupported {
		t.Fatalf("на UDP ASSOCIATE ответили %d, ожидали %d", rep[1], repCmdUnsupported)
	}
}

func TestSOCKSIgnoresWrongVersion(t *testing.T) {
	d := newFakeDialer(t, 2, nil)
	socks, _ := startProxy(t, d)
	c, err := net.Dial("tcp", socks)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{4, 1, 0}) // SOCKS4
	if _, err := io.ReadFull(c, make([]byte, 2)); err == nil {
		t.Fatal("на не-SOCKS5 приветствие не должно быть ответа")
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────

func TestHTTPConnect(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	_, httpAddr := startProxy(t, d)

	c, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT secure.example:443 HTTP/1.1\r\nHost: secure.example:443\r\n\r\n")
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT вернул %q", strings.TrimSpace(line))
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("туннель вернул %q", buf)
	}
	found := false
	for _, targets := range d.served() {
		for _, x := range targets {
			if x == "secure.example:443" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("цель CONNECT не дошла до цепочки: %v", d.served())
	}
}

func TestHTTPPlainRequest(t *testing.T) {
	// echo-сервер не говорит по HTTP, поэтому поднимаем настоящий origin
	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		fmt.Fprint(w, "тело ответа")
	})}
	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go origin.Serve(ol)
	defer origin.Close()

	d := newFakeDialer(t, 2, nil)
	d.echo = ol // цепочки ведут на origin
	_, httpAddr := startProxy(t, d)

	client := &http.Client{
		Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + httpAddr)
		}},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get("http://plain.example/path")
	if err != nil {
		t.Fatalf("запрос через прокси не прошёл: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Origin") != "yes" {
		t.Error("ответ пришёл не от origin")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "тело ответа" {
		t.Fatalf("тело %q", body)
	}
	if used := d.usedSlots(); len(used) == 0 {
		t.Fatal("запрос не прошёл ни через одну цепочку")
	}
}

func TestHTTPRejectsRelativeRequest(t *testing.T) {
	d := newFakeDialer(t, 2, nil)
	_, httpAddr := startProxy(t, d)
	c, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "400") {
		t.Fatalf("прокси принял относительный запрос: %q", strings.TrimSpace(line))
	}
}

// silentDialer изображает мёртвую цепочку: соединение открывается, но с той
// стороны не приходит ни байта. Именно так выглядит сорванное рукопожатие
// Reality, потому что ядро отдаёт соединение до его завершения.
type silentDialer struct {
	*fakeDialer
	silent map[int]bool
	hole   net.Listener
}

// blackhole принимает соединение, глотает запрос и закрывается, не ответив.
func blackhole(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(buf) // прочитали запрос и молча ушли
			}(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l
}

func (s *silentDialer) Dial(ctx context.Context, slot *Slot, host string, port int) (net.Conn, error) {
	if s.silent[slot.Idx] {
		s.mu.Lock()
		s.seen[slot.Idx] = append(s.seen[slot.Idx], fmt.Sprintf("%s:%d", host, port))
		s.mu.Unlock()
		return net.Dial("tcp", s.hole.Addr().String())
	}
	return s.fakeDialer.Dial(ctx, slot, host, port)
}

func TestSilentCircuitIsMarkedDead(t *testing.T) {
	base := newFakeDialer(t, 4, nil)
	base.circ.opts.FailThreshold = 1
	target := "silent.example"
	victim := base.circ.Pick(target, 443)
	d := &silentDialer{fakeDialer: base, silent: map[int]bool{victim.Idx: true},
		hole: blackhole(t)}
	socks, _ := startProxy(t, d)

	c, code := socksDial(t, socks, target, 443)
	if code != repOK {
		t.Fatalf("SOCKS5 отвечает до рукопожатия, ожидали успех, получили %d", code)
	}
	c.Write([]byte("запрос ушёл"))     // без этого о цепочке ничего не известно
	io.Copy(io.Discard, c)             // ждём, пока «цепочка» молча закроется
	c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if base.circ.Pick(target, 443) != victim {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("цепочка, не пропустившая ни байта, осталась в выборе")
}

func TestWorkingCircuitStaysAlive(t *testing.T) {
	d := newFakeDialer(t, 4, nil)
	d.circ.opts.FailThreshold = 1
	target := "alive.example"
	chosen := d.circ.Pick(target, 443)
	socks, _ := startProxy(t, d)

	for i := 0; i < 3; i++ {
		c, code := socksDial(t, socks, target, 443)
		if code != repOK {
			t.Fatalf("отказ %d", code)
		}
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		c.Close()
		time.Sleep(100 * time.Millisecond)
	}
	if d.circ.Pick(target, 443) != chosen {
		t.Fatal("рабочая цепочка не должна выпадать из выбора")
	}
}

// deadDialer отдаёт соединение, которое уже закрыто: так выглядит цепочка,
// оборвавшаяся на рукопожатии раньше, чем приложение успело что-то отправить.
type deadDialer struct {
	*fakeDialer
	dead map[int]bool
}

func (s *deadDialer) Dial(ctx context.Context, slot *Slot, host string, port int) (net.Conn, error) {
	if s.dead[slot.Idx] {
		a, b := net.Pipe()
		a.Close()
		b.Close()
		return b, nil
	}
	return s.fakeDialer.Dial(ctx, slot, host, port)
}

func TestCircuitBrokenBeforeWriteIsMarkedDead(t *testing.T) {
	base := newFakeDialer(t, 4, nil)
	base.circ.opts.FailThreshold = 1
	target := "broken.example"
	victim := base.circ.Pick(target, 443)
	d := &deadDialer{fakeDialer: base, dead: map[int]bool{victim.Idx: true}}
	socks, _ := startProxy(t, d)

	c, code := socksDial(t, socks, target, 443)
	if code != repOK {
		t.Fatalf("ожидали оптимистичный успех SOCKS, получили %d", code)
	}
	c.Write([]byte("запрос, который некуда доставить"))
	io.Copy(io.Discard, c)
	c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if base.circ.Pick(target, 443) != victim {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("оборванная цепочка осталась в выборе")
}

// ctxDialer запоминает контекст, с которым его позвали: ядро продолжает
// дозвон в фоне, и отмена этого контекста обрывает ещё не законченные хопы.
type ctxDialer struct {
	*fakeDialer
	mu   sync.Mutex
	last context.Context
}

func (d *ctxDialer) Dial(ctx context.Context, s *Slot, host string, port int) (net.Conn, error) {
	d.mu.Lock()
	d.last = ctx
	d.mu.Unlock()
	return d.fakeDialer.Dial(ctx, s, host, port)
}

func (d *ctxDialer) ctx() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last
}

// Регрессия: контекст соединения обязан жить, пока живо соединение.
// С отменой сразу после возврата из connect() дальние хопы цепочки не успевали
// договориться и дозвон падал с «context canceled».
func TestDialContextOutlivesConnect(t *testing.T) {
	d := &ctxDialer{fakeDialer: newFakeDialer(t, 2, nil)}
	socks, _ := startProxy(t, d)

	c, code := socksDial(t, socks, "slowhop.example", 443)
	if code != repOK {
		t.Fatalf("SOCKS5 отказ %d", code)
	}
	ctx := d.ctx()
	if ctx == nil {
		t.Fatal("контекст дозвона не захвачен")
	}
	// даём время сработать преждевременной отмене, если она есть
	time.Sleep(300 * time.Millisecond)
	if err := ctx.Err(); err != nil {
		c.Close()
		t.Fatalf("контекст отменён при живом соединении: %v", err)
	}

	// и соединение всё ещё рабочее
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись в соединение: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("чтение из соединения: %v", err)
	}
	c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return // после закрытия контекст обязан освободиться
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("после закрытия соединения контекст остался незакрытым")
}

func TestDialContextCancelledWhenDialFails(t *testing.T) {
	base := newFakeDialer(t, 1, nil)
	base.failing[0] = true
	d := &ctxDialer{fakeDialer: base}
	p := &Proxy{D: d, Logf: func(string, ...any) {}}
	if _, _, code := p.connect("nowhere.example", 443); code == repOK {
		t.Fatal("неудачный дозвон не должен давать успех")
	}
	if ctx := d.ctx(); ctx != nil && ctx.Err() == nil {
		t.Fatal("после неудачного дозвона контекст обязан быть отменён")
	}
}
