package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

// realityTestSNI — сайт-прикрытие для стенда. Reality проксирует рукопожатие
// на него, поэтому он обязан быть доступен и подходить по параметрам TLS.
func realityTestSNI() string {
	if v := os.Getenv("REALITY_SNI"); v != "" {
		return v
	}
	return "www.cloudflare.com"
}

func sampleNodeConfig(role string) *NodeConfig {
	priv, _, err := NewIdentity()
	if err != nil {
		panic(err)
	}
	return &NodeConfig{
		IdentityKey: EncodeIdentity(priv),
		Nick:        "n1", Listen: "127.0.0.1", Port: 443, Roles: []string{role},
		PublicIP: "127.0.0.1", SNI: "a.example", Dest: "a.example:443",
		PrivateKey: testPBK, PublicKey: testPBK, ShortID: "0123abcd",
		UUIDVision: "11111111-1111-1111-1111-111111111111",
		UUIDPlain:  "22222222-2222-2222-2222-222222222222",
		RejectPorts: []string{"25", "465"}, DNSServers: []string{"localhost"},
		LogLevel: "none",
	}
}

func parseCoreConfig(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("конфиг ядра не разобран: %v\n%s", err, raw)
	}
	return m
}

func TestExitResolvesNamesBeforeMatchingRules(t *testing.T) {
	// иначе блокировка приватных сетей обходится доменным именем
	raw, err := nodeCoreConfig(sampleNodeConfig("exit"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseCoreConfig(t, raw)
	routing := cfg["routing"].(map[string]any)
	if routing["domainStrategy"] != "IPIfNonMatch" {
		t.Errorf("выход работает в режиме %v", routing["domainStrategy"])
	}
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	settings := out["settings"].(map[string]any)
	if settings["domainStrategy"] != "UseIP" {
		t.Errorf("исходящий дозвон выхода: %v", settings["domainStrategy"])
	}
	if _, ok := cfg["dns"]; !ok {
		t.Error("у выхода нет секции dns, резолв правил работать не будет")
	}
	rules := routing["rules"].([]any)
	var blockedIPs, blockedPorts bool
	for _, r := range rules {
		m := r.(map[string]any)
		if m["outboundTag"] != "block" {
			continue
		}
		if ips, ok := m["ip"].([]any); ok {
			for _, ip := range ips {
				if ip == "127.0.0.0/8" {
					blockedIPs = true
				}
			}
		}
		if p, ok := m["port"].(string); ok && strings.Contains(p, "25") {
			blockedPorts = true
		}
	}
	if !blockedIPs {
		t.Error("выход не блокирует приватные сети")
	}
	if !blockedPorts {
		t.Error("выход не применяет политику портов")
	}
}

func TestRelayHasNoPeerRulesInRouting(t *testing.T) {
	// список соседей меняется слишком часто для правил маршрутизации:
	// его держит policyDialer, поэтому правил быть не должно
	raw, err := nodeCoreConfig(sampleNodeConfig("guard"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseCoreConfig(t, raw)
	routing := cfg["routing"].(map[string]any)
	if routing["domainStrategy"] != "AsIs" {
		t.Errorf("промежуточный узел работает в режиме %v", routing["domainStrategy"])
	}
	if rules := routing["rules"].([]any); len(rules) != 0 {
		t.Errorf("у промежуточного узла %d правил, ожидали 0", len(rules))
	}
	if _, ok := cfg["dns"]; ok {
		t.Error("промежуточному узлу не нужен резолвер: он ходит только по адресам")
	}
}

func TestInboundHasBothClients(t *testing.T) {
	raw, _ := nodeCoreConfig(sampleNodeConfig("guard"))
	cfg := parseCoreConfig(t, raw)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	clients := in["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("клиентов %d, ожидали 2", len(clients))
	}
	if clients[0].(map[string]any)["flow"] != visionFlow {
		t.Error("у входного UUID нет flow vision")
	}
	if _, ok := clients[1].(map[string]any)["flow"]; ok {
		t.Error("у промежуточного UUID не должно быть flow")
	}
}

func mustDescriptor(t *testing.T, c *NodeConfig, bw int64) Node {
	t.Helper()
	priv, err := DecodeIdentity(c.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Descriptor(bw, priv)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDescriptorOnlyExitPublishesPolicy(t *testing.T) {
	relay := mustDescriptor(t, sampleNodeConfig("middle"), 123)
	if len(relay.RejectPorts) != 0 {
		t.Error("политика выхода опубликована узлом, который не является выходом")
	}
	exit := mustDescriptor(t, sampleNodeConfig("exit"), 123)
	if len(exit.RejectPorts) == 0 {
		t.Error("выход не опубликовал политику портов")
	}
	if err := ValidateDescriptor(exit); err != nil {
		t.Fatalf("директория отвергла дескриптор узла: %v", err)
	}
	if err := VerifyDescriptor(exit, time.Now()); err != nil {
		t.Fatalf("дескриптор не проходит проверку подписи: %v", err)
	}
}

// Дескриптор, выпущенный узлом, обязан пройти проверку личности целиком:
// имя выведено из ключа, подпись сходится, срок не вышел.
func TestDescriptorIsSelfCertifying(t *testing.T) {
	c := sampleNodeConfig("exit")
	n := mustDescriptor(t, c, 0)
	priv, _ := DecodeIdentity(c.IdentityKey)
	if n.ID != Fingerprint(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("имя узла не выведено из ключа личности")
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("свой же дескриптор не проходит проверку: %v", err)
	}
	// правка любого поля ломает подпись
	tampered := n
	tampered.BW = n.BW + 1
	if err := VerifyDescriptor(tampered, time.Now()); err == nil {
		t.Fatal("правка дескриптора не замечена")
	}
	// как и просрочка
	old := n
	old.Expires = time.Now().Add(-time.Hour).Unix()
	if err := VerifyDescriptor(old, time.Now()); err == nil {
		t.Fatal("просроченный дескриптор принят")
	}
}

func dest(ip string, port int) xnet.Destination {
	return xnet.TCPDestination(xnet.ParseAddress(ip), xnet.Port(port))
}

func TestPeerPolicy(t *testing.T) {
	p := &peerPolicy{allowed: map[string]time.Time{
		"1.2.3.4:443": time.Now().Add(time.Hour),
		"5.6.7.8:443": time.Now().Add(-time.Hour), // срок вышел
	}}
	if !p.permits(dest("1.2.3.4", 443)) {
		t.Error("сосед из списка должен пропускаться")
	}
	if p.permits(dest("1.2.3.4", 444)) {
		t.Error("другой порт того же адреса пропускать нельзя")
	}
	if p.permits(dest("9.9.9.9", 443)) {
		t.Error("чужой адрес пропускать нельзя")
	}
	if p.permits(dest("5.6.7.8", 443)) {
		t.Error("просроченный сосед пропускаться не должен")
	}
	if p.permits(xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)) {
		t.Error("промежуточный узел не должен дозваниваться по именам")
	}
	if !(&peerPolicy{allowAll: true}).permits(dest("9.9.9.9", 80)) {
		t.Error("выход должен пропускать всё, что разрешила маршрутизация")
	}
	var nilPolicy *peerPolicy
	if !nilPolicy.permits(dest("9.9.9.9", 80)) {
		t.Error("пустая политика не должна ронять дозвон")
	}
}

func TestPeerTrackerGrace(t *testing.T) {
	tr := newPeerTracker(time.Hour)
	peer := mkNode("a", "1.1.0.1", []string{"middle"})
	self := mkNode("self", "2.2.0.1", []string{"guard"})

	p := tr.update([]Node{peer, self}, self.ID)
	if !p.permits(dest("1.1.0.1", 443)) {
		t.Fatal("сосед из консенсуса не разрешён")
	}
	if p.permits(dest("2.2.0.1", 443)) {
		t.Fatal("узел не должен разрешать сам себя")
	}
	// сосед пропал из консенсуса: до истечения отсрочки он остаётся разрешённым
	p = tr.update(nil, self.ID)
	if !p.permits(dest("1.1.0.1", 443)) {
		t.Fatal("исчезнувший сосед должен доживать отсрочку")
	}
}

func TestPeerTrackerDropsAfterGrace(t *testing.T) {
	tr := newPeerTracker(10 * time.Millisecond)
	tr.update([]Node{mkNode("a", "1.1.0.1", []string{"middle"})}, "self")
	time.Sleep(30 * time.Millisecond)
	if tr.update(nil, "self").permits(dest("1.1.0.1", 443)) {
		t.Fatal("после истечения отсрочки сосед должен выпасть")
	}
}

// Узел с негодной подписью не должен попадать в список разрешённых соседей:
// иначе директория смогла бы подсунуть промежуточному узлу чужой адрес.
func TestPeerTrackerSkipsUnsignedNodes(t *testing.T) {
	tr := newPeerTracker(time.Hour)
	bad := mkNode("bad", "3.3.0.1", []string{"middle"})
	bad.Sig = ""
	if tr.update([]Node{bad}, "self").permits(dest("3.3.0.1", 443)) {
		t.Fatal("узел без подписи попал в разрешённые соседи")
	}
}

func TestPolicyDialerBlocksAndPasses(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	d := &policyDialer{inner: &internet.DefaultSystemDialer{}}
	d.policy.Store(&peerPolicy{allowed: map[string]time.Time{}})
	if _, err := d.Dial(context.Background(), nil, dest("127.0.0.1", port), nil); err == nil {
		t.Fatal("дозвон на запрещённый адрес обязан отклоняться")
	}
	if d.denied.Load() != 1 {
		t.Errorf("отказов насчитано %d", d.denied.Load())
	}

	d.policy.Store(&peerPolicy{allowed: map[string]time.Time{
		fmt.Sprintf("127.0.0.1:%d", port): time.Now().Add(time.Hour),
	}})
	conn, err := d.Dial(context.Background(), nil, dest("127.0.0.1", port), nil)
	if err != nil {
		t.Fatalf("разрешённый дозвон не состоялся: %v", err)
	}
	conn.Close()
}

// ── сквозная проверка всей цепочки ───────────────────────────────────────

// liveNode — настоящий узел сети: встроенное ядро Xray со входом VLESS+Reality.
type liveNode struct {
	cfg  *NodeConfig
	inst *core.Instance
}

func startLiveNode(t *testing.T, nick string, roles []string, family string) *liveNode {
	_ = family
	t.Helper()
	priv, pub, err := x25519Pair()
	if err != nil {
		t.Fatal(err)
	}

	sid, _ := randomHex(8)
	uv, _ := newUUID()
	up, _ := newUUID()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	l.Close() // порт освобождаем: его займёт ядро

	identity, _, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &NodeConfig{
		IdentityKey: EncodeIdentity(identity),
		Nick:        nick, Listen: "127.0.0.1", Port: port, Roles: roles,
		PublicIP: "127.0.0.1",
		SNI:      realityTestSNI(), Dest: realityTestSNI() + ":443",
		PrivateKey: priv, PublicKey: pub, ShortID: sid,
		UUIDVision: uv, UUIDPlain: up,
		DNSServers: []string{"localhost"}, LogLevel: "none",
		AllowPrivate: true, // стенд целиком на 127.0.0.1
		Show:         os.Getenv("REALITY_SHOW") == "1",
	}
	raw, err := nodeCoreConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	coreCfg, err := serial.LoadJSONConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("конфиг узла %s не собран: %v", nick, err)
	}
	inst, err := core.New(coreCfg)
	if err != nil {
		t.Fatalf("ядро узла %s не создано: %v", nick, err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("узел %s не запустился: %v", nick, err)
	}
	t.Cleanup(func() { inst.Close() })
	return &liveNode{cfg: cfg, inst: inst}
}

func (n *liveNode) descriptor() Node {
	priv, err := DecodeIdentity(n.cfg.IdentityKey)
	if err != nil {
		panic(err)
	}
	d, err := n.cfg.Descriptor(0, priv)
	if err != nil {
		panic(err)
	}
	return d
}

// TestOnionPathEndToEnd поднимает директорию, три настоящих узла и клиента,
// после чего проводит HTTP-запрос через всю цепочку. Проверяется весь путь:
// подпись консенсуса, сборка цепочки, вложенные рукопожатия Reality и то, что
// каждый узел видит только своих соседей.
func TestOnionPathEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("сквозная проверка не для -short")
	}

	// цель запроса
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "через луковицу")
	}))
	defer target.Close()

	// в стенде всё на 127.0.0.1, поэтому политика узлов пропускает всё:
	// подменённый дозвонщик один на процесс, а узлы и клиент тут в одном
	pd := &policyDialer{inner: &internet.DefaultSystemDialer{}}
	pd.policy.Store(&peerPolicy{allowAll: true})
	internet.UseAlternativeSystemDialer(pd)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(&internet.DefaultSystemDialer{}) })

	guard := startLiveNode(t, "guard1", []string{"guard"}, "opA")
	middle := startLiveNode(t, "middle1", []string{"middle"}, "opB")
	exit := startLiveNode(t, "exit1", []string{"exit"}, "opC")

	// директория с настоящей подписью
	tmp := t.TempDir()
	key, err := loadOrCreateDirKey(tmp + "/dir.key")
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(tmp+"/nodes.json", time.Hour, 0, 0, false, func(string, ...any) {})
	for _, n := range []*liveNode{guard, middle, exit} {
		if _, err := store.Register(n.descriptor(), "127.0.0.1", ""); err != nil {
			t.Fatalf("узел %s не зарегистрирован: %v", n.cfg.Nick, err)
		}
	}
	srv := httptest.NewServer(&dirServer{
		store: store, consensus: NewConsensus(store, key, 0),
		sharedToken: "t", logf: func(string, ...any) {},
	})
	defer srv.Close()

	// клиент
	circ, err := NewCircuits(CircuitsOpts{
		Count: 1, Fingerprint: "firefox", FailThreshold: 2,
		Cooldown: time.Minute, LogLevel: "none",
	}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()

	dir := &DirectoryClient{URL: srv.URL}
	public, _, err := dir.Fetch(pubKeyString(key), func(string, ...any) {})
	if err != nil {
		t.Fatalf("консенсус не получен: %v", err)
	}
	if len(public) != 3 {
		t.Fatalf("в консенсусе %d узлов, ожидали 3", len(public))
	}
	pool := FilterValid(public, func(string, ...any) {})
	opts := SelectOpts{Guards: 1, GuardDays: 30, GuardRetireDays: 7, BWCap: 5,
		Circuits: 1, IgnoreNet: true}
	paths, err := BuildCircuits(pool, withRole(pool, "guard"), opts)
	if err != nil {
		t.Fatalf("цепочка не собрана: %v", err)
	}
	if err := circ.Install(0, paths[0]); err != nil {
		t.Fatalf("цепочка не установилась: %v", err)
	}
	t.Logf("цепочка: %s", strings.Join(paths[0].Nicks(), " → "))

	// запрос идёт через настоящий SOCKS5 клиента, а не мимо него: именно на
	// этом пути когда-то обрывался дозвон дальних хопов
	proxy := &Proxy{D: circ, Logf: t.Logf}
	defer proxy.Close()
	sl, err := proxy.ServeSOCKS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, socksPortStr, _ := net.SplitHostPort(sl.Addr().String())
	var socksPort int
	fmt.Sscanf(socksPortStr, "%d", &socksPort)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, port := splitHostPort(addr, 80)
				c, code := socksDial(t, sl.Addr().String(), host, port)
				if code != repOK {
					return nil, fmt.Errorf("SOCKS5 отказ %d", code)
				}
				// снимаем срок из помощника: первое рукопожатие Reality ждёт
				// разведку сайта-прикрытия и занимает около десяти секунд
				_ = c.SetDeadline(time.Time{})
				return c, nil
			},
			DisableKeepAlives: true,
		},
		Timeout: 40 * time.Second,
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("запрос через цепочку не прошёл: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "через луковицу" {
		t.Fatalf("цель вернула %q", body)
	}

	// каждый узел видел только своего соседа, но не всю цепочку
	if got := circ.Slots()[0].Path().Nicks(); len(got) != 3 {
		t.Fatalf("цепочка из %d узлов", len(got))
	}
}

// TestRotationKeepsLiveConnection показывает главное свойство встроенного ядра:
// смена цепочки в слоте не рвёт уже открытые соединения.
func TestRotationKeepsLiveConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("сквозная проверка не для -short")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	pd := &policyDialer{inner: &internet.DefaultSystemDialer{}}
	pd.policy.Store(&peerPolicy{allowAll: true})
	internet.UseAlternativeSystemDialer(pd)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(&internet.DefaultSystemDialer{}) })

	g1 := startLiveNode(t, "g1", []string{"guard"}, "fa")
	m1 := startLiveNode(t, "m1", []string{"middle"}, "fb")
	e1 := startLiveNode(t, "e1", []string{"exit"}, "fc")
	e2 := startLiveNode(t, "e2", []string{"exit"}, "fd")

	circ, err := NewCircuits(CircuitsOpts{Count: 1, Fingerprint: "firefox",
		FailThreshold: 2, Cooldown: time.Minute, LogLevel: "none"}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()

	first := Path{Guard: g1.descriptor(), Middle: m1.descriptor(), Exit: e1.descriptor()}
	if err := circ.Install(0, first); err != nil {
		t.Fatal(err)
	}
	conn, err := circ.Dial(context.Background(), circ.Slots()[0], host, port)
	if err != nil {
		t.Fatalf("соединение не открылось: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("aaaa")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("эхо не пришло: %v", err)
	}

	// ротация слота: выход меняется на другой узел
	second := Path{Guard: g1.descriptor(), Middle: m1.descriptor(), Exit: e2.descriptor()}
	if err := circ.Install(0, second); err != nil {
		t.Fatalf("ротация не удалась: %v", err)
	}

	if _, err := conn.Write([]byte("bbbb")); err != nil {
		t.Fatalf("старое соединение порвалось при записи: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("старое соединение порвалось при чтении: %v", err)
	}
	if string(buf) != "bbbb" {
		t.Fatalf("старое соединение вернуло %q", buf)
	}

	fresh, err := circ.Dial(context.Background(), circ.Slots()[0], host, port)
	if err != nil {
		t.Fatalf("новое соединение не открылось после ротации: %v", err)
	}
	defer fresh.Close()
	fresh.Write([]byte("cccc"))
	if _, err := io.ReadFull(fresh, buf); err != nil {
		t.Fatalf("новая цепочка не работает: %v", err)
	}
}
