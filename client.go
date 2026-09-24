package main

// Клиент: «луковые» цепочки на встроенном ядре Xray.
//
//	клиент ──Reality+Vision──► guard ──Reality──► middle ──Reality──► exit ──► интернет
//
// Каждый следующий туннель поднимается ВНУТРИ предыдущего через
// sockopt.dialerProxy, поэтому guard видит клиента и адрес middle, middle видит
// только соседей, а exit видит цель, но не клиента.
//
// Маршрутизация опирается на постоянные слоты: правило slot-N → exit-sN
// задаётся один раз, а смена цепочки — это подмена трёх outbound-ов за теми же
// тегами. Снятие обработчика не закрывает уже открытые потоки, поэтому ротация
// не рвёт соединения.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const visionFlow = "xtls-rprx-vision"

// ── описание outbound в терминах конфига Xray ────────────────────────────

type realitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type sockopt struct {
	DialerProxy string `json:"dialerProxy,omitempty"`
}

type streamSettings struct {
	Network  string          `json:"network"`
	Security string          `json:"security"`
	Reality  realitySettings `json:"realitySettings"`
	Sockopt  *sockopt        `json:"sockopt,omitempty"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type vnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessSettings struct {
	Vnext []vnext `json:"vnext"`
}

type outboundJSON struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       vlessSettings  `json:"settings"`
	StreamSettings streamSettings `json:"streamSettings"`
}

// hopOutbound описывает один хоп. via — тег предыдущего хопа.
func hopOutbound(tag string, n Node, uuid, flow, fingerprint, via string) outboundJSON {
	ob := outboundJSON{Tag: tag, Protocol: "vless"}
	ob.Settings.Vnext = []vnext{{
		Address: n.IP, Port: n.Port,
		Users: []vlessUser{{ID: uuid, Encryption: "none", Flow: flow}},
	}}
	ob.StreamSettings = streamSettings{
		Network: "tcp", Security: "reality",
		Reality: realitySettings{
			ServerName: n.SNI, Fingerprint: fingerprint,
			PublicKey: n.PBK, ShortID: n.SID, SpiderX: "/",
		},
	}
	if via != "" {
		ob.StreamSettings.Sockopt = &sockopt{DialerProxy: via}
	}
	return ob
}

// ── слоты ────────────────────────────────────────────────────────────────

// Slot — постоянная «полоса» маршрутизации.
type Slot struct {
	Idx int
	Tag string // inbound-тег, по которому роутер выбирает цепочку

	mu        sync.Mutex
	path      Path
	ready     bool
	fails     int
	downUntil time.Time
	ok        int64
}

func (s *Slot) hopTags() (string, string, string) {
	return fmt.Sprintf("hop1-s%d", s.Idx), fmt.Sprintf("hop2-s%d", s.Idx),
		fmt.Sprintf("exit-s%d", s.Idx)
}

func (s *Slot) Path() Path {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// labelLocked вызывается там, где s.mu уже захвачен: sync.Mutex не
// реентерабелен, и повторный Lock в том же потоке — это дедлок.
func (s *Slot) labelLocked() string {
	if s.path.Guard.ID == "" {
		return fmt.Sprintf("c%d(пусто)", s.Idx)
	}
	return fmt.Sprintf("c%d(%s→%s→%s)", s.Idx,
		s.path.Guard.Short(), s.path.Middle.Short(), s.path.Exit.Short())
}

func (s *Slot) Label() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.labelLocked()
}

func (s *Slot) healthy(now time.Time) bool {
	return s.ready && now.After(s.downUntil)
}

// ── менеджер цепочек ─────────────────────────────────────────────────────

type CircuitsOpts struct {
	Count         int
	Fingerprint   string
	NoVision      bool // диагностика: первый хоп без flow
	FailThreshold int
	Cooldown      time.Duration
	LogLevel      string
}

type Circuits struct {
	inst *core.Instance
	mgr  outbound.Manager
	opts CircuitsOpts
	logf func(string, ...any)

	mu    sync.RWMutex
	slots []*Slot
}

// clientCoreConfig — конфиг ядра без inbound-ов: трафик приходит через
// core.Dial, а правила навсегда связывают slot-N с exit-sN.
func clientCoreConfig(count int, logLevel string) string {
	rules := make([]string, 0, count+1)
	for i := 0; i < count; i++ {
		rules = append(rules, fmt.Sprintf(
			`{"type":"field","inboundTag":["slot-%d"],"outboundTag":"exit-s%d"}`, i, i))
	}
	rules = append(rules, `{"type":"field","network":"tcp,udp","outboundTag":"block"}`)
	// запас на рукопожатие: у свежего узла Reality сперва разведывает
	// сайт-прикрытие, и стандартных четырёх секунд на три вложенных
	// рукопожатия не хватает
	return fmt.Sprintf(`{
  "log": {"loglevel": %q},
  "inbounds": [],
  "outbounds": [{"tag": "block", "protocol": "blackhole", "settings": {}}],
  "policy": {"levels": {"0": {"handshake": 30, "connIdle": 300}}},
  "routing": {"domainStrategy": "AsIs", "rules": [%s]}
}`, logLevel, strings.Join(rules, ","))
}

func NewCircuits(opts CircuitsOpts, logf func(string, ...any)) (*Circuits, error) {
	if opts.Fingerprint == "" {
		opts.Fingerprint = "firefox"
	}
	cfg, err := serial.LoadJSONConfig(strings.NewReader(clientCoreConfig(opts.Count, opts.LogLevel)))
	if err != nil {
		return nil, fmt.Errorf("базовый конфиг не собран: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("ядро не создано: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("ядро не запустилось: %w", err)
	}
	mgr, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		inst.Close()
		return nil, fmt.Errorf("менеджер outbound недоступен")
	}
	c := &Circuits{inst: inst, mgr: mgr, opts: opts, logf: logf}
	for i := 0; i < opts.Count; i++ {
		c.slots = append(c.slots, &Slot{Idx: i, Tag: fmt.Sprintf("slot-%d", i)})
	}
	return c, nil
}

func (c *Circuits) Close() error { return c.inst.Close() }

func (c *Circuits) addOutbound(ob outboundJSON) error {
	raw, err := json.Marshal(ob)
	if err != nil {
		return err
	}
	var detour conf.OutboundDetourConfig
	if err := json.Unmarshal(raw, &detour); err != nil {
		return err
	}
	built, err := detour.Build()
	if err != nil {
		return fmt.Errorf("outbound %s не собран: %w", ob.Tag, err)
	}
	obj, err := core.CreateObject(c.inst, built)
	if err != nil {
		return fmt.Errorf("outbound %s не создан: %w", ob.Tag, err)
	}
	handler, ok := obj.(outbound.Handler)
	if !ok {
		return fmt.Errorf("outbound %s не является обработчиком", ob.Tag)
	}
	return c.mgr.AddHandler(context.Background(), handler)
}

// Install ставит цепочку в слот, заменяя прежнюю.
//
// RemoveHandler только убирает обработчик из таблицы и не закрывает открытые
// соединения, поэтому ротация слота не рвёт текущие потоки: они доживают на
// старом обработчике, а новые идут по новой цепочке.
func (c *Circuits) Install(idx int, p Path) error {
	if err := p.Validate(); err != nil {
		return err
	}
	c.mu.RLock()
	if idx < 0 || idx >= len(c.slots) {
		c.mu.RUnlock()
		return fmt.Errorf("слот %d не существует", idx)
	}
	s := c.slots[idx]
	c.mu.RUnlock()

	h1, h2, ex := s.hopTags()
	ctx := context.Background()
	for _, tag := range []string{ex, h2, h1} {
		_ = c.mgr.RemoveHandler(ctx, tag)
	}

	fp := c.opts.Fingerprint
	flow, id := visionFlow, p.Guard.UUIDVision
	if c.opts.NoVision {
		flow, id = "", p.Guard.UUIDPlain
	}
	chain := []outboundJSON{
		hopOutbound(h1, p.Guard, id, flow, fp, ""),
		hopOutbound(h2, p.Middle, p.Middle.UUIDPlain, "", fp, h1),
		hopOutbound(ex, p.Exit, p.Exit.UUIDPlain, "", fp, h2),
	}
	for _, ob := range chain {
		if err := c.addOutbound(ob); err != nil {
			for _, tag := range []string{ex, h2, h1} {
				_ = c.mgr.RemoveHandler(ctx, tag)
			}
			s.mu.Lock()
			s.ready = false
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Lock()
	s.path = p
	s.ready = true
	s.fails = 0
	s.downUntil = time.Time{}
	s.mu.Unlock()
	return nil
}

func (c *Circuits) Slots() []*Slot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Slot, len(c.slots))
	copy(out, c.slots)
	return out
}

// score — rendezvous hashing: привязка хоста к слоту не перемешивается, когда
// соседний слот выпадает или меняет цепочку.
func score(host string, s *Slot, exitNick string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(host))
	h.Write([]byte{'|'})
	h.Write([]byte(exitNick))
	h.Write([]byte{'|'})
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(s.Idx))
	h.Write(idx[:])
	return h.Sum64()
}

// Pick выбирает слот для (host, port): один хост всегда идёт через одну
// цепочку, мёртвые слоты пропускаются, политика выхода учитывается.
func (c *Circuits) Pick(host string, port int) *Slot {
	now := time.Now()
	c.mu.RLock()
	slots := make([]*Slot, len(c.slots))
	copy(slots, c.slots)
	c.mu.RUnlock()

	var allowed, live []*Slot
	for _, s := range slots {
		s.mu.Lock()
		ready, rejected := s.ready, PortRejected(s.path.Exit.RejectPorts, port)
		healthy := s.healthy(now)
		s.mu.Unlock()
		if !ready || rejected {
			continue
		}
		allowed = append(allowed, s)
		if healthy {
			live = append(live, s)
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	if len(live) == 0 {
		// все подходящие слоты помечены мёртвыми — снимаем пометки, иначе
		// клиент останется совсем без выхода
		for _, s := range allowed {
			s.mu.Lock()
			s.downUntil = time.Time{}
			s.fails = 0
			s.mu.Unlock()
		}
		live = allowed
		c.logf("все цепочки были помечены мёртвыми, пробую заново")
	}
	best := live[0]
	bestScore := score(host, best, best.Path().Exit.ID)
	for _, s := range live[1:] {
		if sc := score(host, s, s.Path().Exit.ID); sc > bestScore {
			best, bestScore = s, sc
		}
	}
	return best
}

// Report отмечает исход попытки соединения через слот.
func (c *Circuits) Report(s *Slot, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.fails = 0
		s.ok++
		return
	}
	s.fails++
	if s.fails >= c.opts.FailThreshold {
		s.downUntil = time.Now().Add(c.opts.Cooldown)
		c.logf("цепочка %s не отвечает (%d подряд), пауза %s",
			s.labelLocked(), s.fails, c.opts.Cooldown)
	}
}

// Dial открывает соединение через конкретный слот.
func (c *Circuits) Dial(ctx context.Context, s *Slot, host string, port int) (net.Conn, error) {
	dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: s.Tag})
	return core.Dial(ctx, c.inst, dest)
}

// ── SOCKS5 и HTTP ────────────────────────────────────────────────────────

const (
	socksVer   = 5
	cmdConnect = 1

	atypIPv4 = 1
	atypHost = 3
	atypIPv6 = 4

	repOK             = 0
	repFail           = 1
	repNotAllowed     = 2
	repHostUnreach    = 4
	repCmdUnsupported = 7
)

// Dialer — то, что умеет выбрать цепочку и открыть через неё соединение.
type Dialer interface {
	Pick(host string, port int) *Slot
	Report(s *Slot, ok bool)
	Dial(ctx context.Context, s *Slot, host string, port int) (net.Conn, error)
}

// Proxy — SOCKS5 и HTTP на одном наборе цепочек.
type Proxy struct {
	D        Dialer
	Logf     func(string, ...any)
	Verbose  bool
	mu       sync.Mutex
	listener []net.Listener
}

func (p *Proxy) debugf(format string, args ...any) {
	if p.Verbose {
		p.Logf(format, args...)
	}
}

func (p *Proxy) track(l net.Listener) {
	p.mu.Lock()
	p.listener = append(p.listener, l)
	p.mu.Unlock()
}

func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.listener {
		_ = l.Close()
	}
	p.listener = nil
}

// closeWriter — соединение, умеющее полузакрытие: так «я всё отправил»
// доходит до другой стороны, не обрывая обратный поток.
type closeWriter interface {
	CloseWrite() error
}

// cancelConn держит контекст соединения живым, пока живо само соединение.
type cancelConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *cancelConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

// CloseWrite пробрасывает полузакрытие внутрь: без этого обёртка перестала бы
// передавать конец передачи, и другая сторона ждала бы данные до таймаута.
func (c *cancelConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// connect выбирает цепочку и открывает через неё соединение.
//
// Два важных свойства ядра. Первое: соединение отдаётся сразу, до того как
// отработают рукопожатия Reality на всех трёх хопах, поэтому успешный дозвон
// ещё не означает, что цепочка жива — живость определяется по факту прошедших
// данных, см. finish(). Второе: дозвон продолжается в фоне и привязан к
// переданному контексту. Отменить контекст при выходе из этой функции значит
// оборвать ещё не законченный дозвон дальних хопов, поэтому контекст живёт
// столько же, сколько соединение, и отменяется при его закрытии. Тайм-аут
// здесь не ставится: он оборвал бы и долгие рабочие соединения, а у дозвона
// есть собственный предел.
func (p *Proxy) connect(host string, port int) (net.Conn, *Slot, byte) {
	slot := p.D.Pick(host, port)
	if slot == nil {
		p.Logf("нет цепочки, чей выход пропускает порт %d (%s)", port, host)
		return nil, nil, repNotAllowed
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := p.D.Dial(ctx, slot, host, port)
	if err != nil {
		cancel()
		p.D.Report(slot, false)
		p.Logf("%s: %s:%d не открылось (%v)", slot.Label(), host, port, err)
		return nil, slot, repHostUnreach
	}
	p.debugf("%s: %s:%d", slot.Label(), host, port)
	return &cancelConn{Conn: conn, cancel: cancel}, slot, repOK
}

// finish подводит итог сеанса.
//
// Цепочка считается живой, если по ней пришли данные, и мёртвой, если клиент
// отправил запрос, а ответа не было вовсе: именно так выглядит сорванное
// рукопожатие. Если клиент сам ничего не отправил, о цепочке ничего не
// известно и счётчики не трогаются.
func (p *Proxy) finish(slot *Slot, sent, received int64, host string, port int) {
	if slot == nil {
		return
	}
	switch {
	case received > 0:
		p.D.Report(slot, true)
	case sent > 0:
		p.debugf("%s: %s:%d — запрос ушёл, ответа нет", slot.Label(), host, port)
		p.D.Report(slot, false)
	}
}

func (p *Proxy) ServeSOCKS(addr string) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	p.track(l)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.handleSOCKS(c)
		}
	}()
	return l, nil
}

func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVer, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func (p *Proxy) handleSOCKS(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != socksVer {
		return
	}
	if _, err := io.ReadFull(client, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := client.Write([]byte{socksVer, 0}); err != nil { // без аутентификации
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[0] != socksVer {
		return
	}
	var host string
	switch req[3] {
	case atypIPv4, atypIPv6:
		n := 4
		if req[3] == atypIPv6 {
			n = 16
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case atypHost:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(client, ln); err != nil {
			return
		}
		buf := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		host = string(buf)
	default:
		_ = socksReply(client, repFail)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(client, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))

	if req[1] != cmdConnect {
		// UDP ASSOCIATE и BIND не поддерживаются: изоляция по назначению
		// определена для потоков TCP
		_ = socksReply(client, repCmdUnsupported)
		return
	}

	upstream, slot, code := p.connect(host, port)
	if code != repOK {
		_ = socksReply(client, code)
		return
	}
	defer upstream.Close()
	if err := socksReply(client, repOK); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	sent, received := pipe(client, upstream)
	p.finish(slot, sent, received, host, port)
}

func (p *Proxy) ServeHTTP(addr string) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	p.track(l)
	srv := &http.Server{Handler: http.HandlerFunc(p.httpHandler)}
	go func() { _ = srv.Serve(l) }()
	return l, nil
}

func splitHostPort(hostport string, defPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.Trim(hostport, "[]"), defPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defPort
	}
	return host, port
}

func (p *Proxy) httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		host, port := splitHostPort(r.Host, 443)
		upstream, slot, code := p.connect(host, port)
		if code != repOK {
			http.Error(w, "цепочка недоступна", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack недоступен", http.StatusInternalServerError)
			return
		}
		client, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		if buf != nil && buf.Reader.Buffered() > 0 {
			if _, err := io.CopyN(upstream, buf, int64(buf.Reader.Buffered())); err != nil {
				return
			}
		}
		sent, received := pipe(client, upstream)
		p.finish(slot, sent, received, host, port)
		return
	}

	if !r.URL.IsAbs() {
		http.Error(w, "нужен absolute-URI или CONNECT", http.StatusBadRequest)
		return
	}
	defPort := 80
	if r.URL.Scheme == "https" {
		defPort = 443
	}
	host, port := splitHostPort(r.URL.Host, defPort)

	// транспорт вызывает DialContext из своей горутины, поэтому слот
	// передаётся через указатель под атомарной записью, а не обычной переменной
	var used atomic.Pointer[Slot]
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, slot, code := p.connect(host, port)
			used.Store(slot)
			if code != repOK {
				return nil, fmt.Errorf("цепочка недоступна")
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if slot := used.Load(); slot != nil {
			p.D.Report(slot, false)
		}
		http.Error(w, "запрос не прошёл: "+err.Error(), http.StatusBadGateway)
		return
	}
	if slot := used.Load(); slot != nil {
		p.D.Report(slot, true)
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// countingReader считает прочитанное на стороне чтения, а не записи: если
// цепочка оборвалась, запись в неё не состоится, но знать, что приложение
// пыталось ею воспользоваться, всё равно нужно.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// pipe перекачивает данные в обе стороны и возвращает, сколько байт клиент
// отправил в цепочку и сколько получил обратно.
func pipe(client, upstream net.Conn) (sent, received int64) {
	var wg sync.WaitGroup
	var fromClient, fromUpstream atomic.Int64
	wg.Add(2)
	cp := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
	go cp(client, countingReader{upstream, &fromUpstream})
	go cp(upstream, countingReader{client, &fromClient})
	wg.Wait()
	return fromClient.Load(), fromUpstream.Load()
}

// ── запуск клиента ───────────────────────────────────────────────────────

type clientApp struct {
	dirs *DirectorySet
	st   *State
	circ *Circuits
	opts SelectOpts
}

func (a *clientApp) logf(format string, args ...any) { logf(format, args...) }

// refresh забирает консенсус и раскладывает свежие цепочки по слотам.
// slots == nil означает «обновить все».
// nodePool берёт свежий набор у директорий, а если кворум не собрался —
// поднимает последний проверенный из кеша.
//
// Кеш не обходит кворум: в нём лежит набор, который кворум уже подтвердил.
// Каждый узел проверяется заново, поэтому просроченные дескрипторы отсеются
// сами, и через сутки кеш опустеет.
func (a *clientApp) nodePool() (public, bridges []Node, stale bool, err error) {
	res, ferr := a.dirs.Fetch(a.logf)
	if ferr == nil {
		a.st.DirKeys = a.dirs.Keys()
		a.st.LogHeads = a.dirs.Heads()
		if res.Rejected > 0 {
			a.logf("узлов без кворума: %d (в цепочки не пойдут)", res.Rejected)
		}
		a.st.Cached = &CachedSet{
			SavedAt: time.Now().Unix(), Nodes: res.Nodes, Bridges: res.Bridges,
		}
		return res.Nodes, res.Bridges, false, nil
	}

	cached := a.st.Cached
	if cached == nil {
		return nil, nil, false, ferr
	}
	quiet := func(string, ...any) {}
	pub := FilterValid(cached.Nodes, quiet)
	br := FilterValid(cached.Bridges, quiet)
	if len(pub)+len(br) == 0 {
		return nil, nil, false, fmt.Errorf(
			"%w; кеш пуст или дескрипторы в нём просрочены", ferr)
	}
	age := time.Since(time.Unix(cached.SavedAt, 0)).Round(time.Minute)
	dropped := len(cached.Nodes) + len(cached.Bridges) - len(pub) - len(br)
	note := ""
	if dropped > 0 {
		note = fmt.Sprintf(", просрочено и отброшено: %d", dropped)
	}
	a.logf("ВНИМАНИЕ: директории недоступны (%v)", ferr)
	a.logf("работаю на кеше возрастом %s: узлов %d, мостов %d%s", age, len(pub), len(br), note)
	return pub, br, true, nil
}

func (a *clientApp) refresh(slots []int) error {
	public, bridges, stale, err := a.nodePool()
	if err != nil {
		return err
	}
	pool := append(append([]Node{}, public...), bridges...)
	if len(pool) == 0 {
		return fmt.Errorf("консенсус пуст")
	}

	// мост — входной узел, которого нет в публичном списке; если мосты есть,
	// публичные guard не используются вовсе
	guardPool := pool
	var onlyBridges []Node
	for _, n := range bridges {
		if n.HasRole("guard") {
			onlyBridges = append(onlyBridges, n)
		}
	}
	if len(onlyBridges) > 0 {
		guardPool = onlyBridges
	}

	guards := ChooseGuards(guardPool, a.st, a.opts, a.logf)
	paths, err := BuildCircuits(pool, guards, a.opts)
	if err != nil {
		return err
	}
	if err := a.st.Save(); err != nil {
		a.logf("состояние не сохранено: %v", err)
	}

	if slots == nil {
		for i := range a.circ.Slots() {
			slots = append(slots, i)
		}
	}
	installed := 0
	for n, idx := range slots {
		p := paths[n%len(paths)]
		if err := a.circ.Install(idx, p); err != nil {
			a.logf("слот %d не собран: %v", idx, err)
			continue
		}
		installed++
		note := ""
		if len(p.Exit.RejectPorts) > 0 {
			note = fmt.Sprintf(", выход не пропускает %v", p.Exit.RejectPorts)
		}
		a.logf("слот %d: %s → %s → %s%s", idx,
			p.Guard.Short(), p.Middle.Short(), p.Exit.Short(), note)
	}
	if installed == 0 {
		return fmt.Errorf("ни одна цепочка не установилась")
	}
	source := "с кворумом"
	if stale {
		source = "из кеша"
	}
	a.logf("узлов %s: %d, мостов: %d, слотов обновлено: %d",
		source, len(public), len(bridges), installed)
	return nil
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	directory := fs.String("directory", "",
		"адреса директорий через запятую (обязателен)")
	dirKey := fs.String("dir-key", "",
		"публичные ключи директорий через запятую, в том же порядке; пусто — доверие при первом обращении")
	quorum := fs.Int("quorum", 0,
		"сколько директорий должны подтвердить узел (0 — большинство)")
	allowNoLog := fs.Bool("allow-no-log", false,
		"работать с директорией без журнала прозрачности")
	readToken := fs.String("read-token", "", "токены чтения консенсуса через запятую")
	bridgeToken := fs.String("bridge-token", "", "токены выдачи мостов через запятую")
	bridgeFile := fs.String("bridge-file", "", "файл со списком мостов (JSON)")
	statePath := fs.String("state", defaultClientStatePath(), "файл состояния")
	circuits := fs.Int("circuits", 4, "сколько цепочек держать")
	guards := fs.Int("guards", 2, "сколько входных узлов закрепить")
	guardDays := fs.Int("guard-days", 30, "срок закрепления входного узла, суток")
	guardRetire := fs.Int("guard-retire-days", 7,
		"суток непрерывной недоступности до снятия закрепления")
	bwCap := fs.Float64("bw-cap", 5.0, "во сколько раз вес узла может превышать медианный")
	ignoreNet := fs.Bool("ignore-net", false, "не требовать разных сетей /16 (только для стенда)")
	asnFile := fs.String("asn-file", "",
		"таблица ip2asn-v4.tsv: разводить цепочку ещё и по автономным системам")
	listen := fs.String("listen", "127.0.0.1", "адрес прослушивания прокси")
	socksPort := fs.Int("socks", 9050, "порт SOCKS5")
	httpPort := fs.Int("http", 9080, "порт HTTP-прокси (0 = выключить)")
	fingerprint := fs.String("fingerprint", "firefox", "отпечаток TLS для Reality")
	failThreshold := fs.Int("fail-threshold", 2,
		"подряд неудачных соединений до пометки цепочки мёртвой")
	cooldown := fs.Duration("cooldown", 2*time.Minute, "пауза для мёртвой цепочки")
	rotate := fs.Duration("rotate", 0,
		"период полного круга ротации, слоты меняются по очереди (0 = не менять)")
	logLevel := fs.String("loglevel", "warning", "уровень лога ядра Xray")
	verbose := fs.Bool("verbose", false, "печатать каждое соединение")
	noVision := fs.Bool("no-vision", false,
		"первый хоп без xtls-rprx-vision (диагностика)")
	_ = fs.Parse(args)

	if *directory == "" {
		return fmt.Errorf("нужен -directory")
	}
	refs, err := buildDirectoryRefs(*directory, *dirKey, "", *readToken, *bridgeToken)
	if err != nil {
		return err
	}

	var asn *ASNTable
	if *asnFile != "" {
		var err error
		if asn, err = LoadASNTable(*asnFile); err != nil {
			return fmt.Errorf("таблица автономных систем: %w", err)
		}
		logf("таблица автономных систем: %d диапазонов", asn.Len())
	}

	st := LoadState(*statePath)
	dirs, err := NewDirectorySet(refs, *quorum, st.DirKeys)
	if err != nil {
		return err
	}
	dirs.HTTP = defaultHTTPClient()
	dirs.AllowNoLog = *allowNoLog
	dirs.WithHeads(st.LogHeads)
	if *bridgeFile != "" {
		dirs.BridgeFile = *bridgeFile
	}

	a := &clientApp{
		st:   st,
		dirs: dirs,
		opts: SelectOpts{
			Guards: *guards, GuardDays: *guardDays, GuardRetireDays: *guardRetire,
			BWCap: *bwCap, Circuits: *circuits, IgnoreNet: *ignoreNet, ASN: asn,
		},
	}

	a.logf("директории: %s", dirs.Describe())

	circ, err := NewCircuits(CircuitsOpts{
		Count: *circuits, Fingerprint: *fingerprint,
		FailThreshold: *failThreshold, Cooldown: *cooldown, LogLevel: *logLevel,
		NoVision:      *noVision,
	}, a.logf)
	if err != nil {
		return err
	}
	a.circ = circ
	defer circ.Close()
	a.logf("ядро Xray запущено внутри процесса, слотов: %d, отпечаток: %s",
		*circuits, *fingerprint)

	stop := waitForSignal()
	var lastErr error
	for attempt := 0; attempt < 60; attempt++ {
		if lastErr = a.refresh(nil); lastErr == nil {
			break
		}
		a.logf("консенсус пока недоступен (%v), повтор через 10 с", lastErr)
		select {
		case <-stop:
			return nil
		case <-time.After(10 * time.Second):
		}
	}
	if lastErr != nil {
		return lastErr
	}

	p := &Proxy{D: circ, Logf: a.logf, Verbose: *verbose}
	defer p.Close()
	if _, err := p.ServeSOCKS(net.JoinHostPort(*listen, strconv.Itoa(*socksPort))); err != nil {
		return fmt.Errorf("SOCKS5 не поднялся: %w", err)
	}
	a.logf("SOCKS5 на %s:%d (одна цель — одна цепочка)", *listen, *socksPort)
	if *httpPort > 0 {
		if _, err := p.ServeHTTP(net.JoinHostPort(*listen, strconv.Itoa(*httpPort))); err != nil {
			return fmt.Errorf("HTTP-прокси не поднялся: %w", err)
		}
		a.logf("HTTP-прокси на %s:%d", *listen, *httpPort)
	}

	if *rotate <= 0 {
		<-stop
		a.logf("останавливаюсь")
		return nil
	}

	// слоты меняются по очереди: в любой момент обновляется только один,
	// остальные продолжают обслуживать соединения
	step := *rotate / time.Duration(*circuits)
	if step < time.Second {
		step = time.Second
	}
	ticker := time.NewTicker(step)
	defer ticker.Stop()
	a.logf("ротация: слот каждые %s, полный круг за %s", step, *rotate)
	for next := 0; ; next++ {
		select {
		case <-stop:
			a.logf("останавливаюсь")
			return nil
		case <-ticker.C:
			idx := next % *circuits
			if err := a.refresh([]int{idx}); err != nil {
				a.logf("ротация слота %d не удалась: %v", idx, err)
			}
		}
	}
}
