package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/features/outbound"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ── из path_test.go ──
// настоящий публичный ключ x25519: Xray проверяет его при сборке outbound
const testPBK = "M7ZqjD-7v8PxC9wZfvhbhkJ9gofVYhRmg9WhExlo5zQ"

// ключи личностей, выпущенные помощником: нужны, чтобы переподписать
// дескриптор после правки полей
var testKeys = map[string]ed25519.PrivateKey{}

// mkNode выпускает подписанный дескриптор со свежей личностью.
func mkNode(nick, ip string, roles []string, opts ...func(*Node)) Node {
	priv, _, err := NewIdentity()
	if err != nil {
		panic(err)
	}
	canon, _ := NormalizeRoles(roles)
	n := Node{
		Nick: nick, IP: ip, Port: 443, Roles: canon, Family: []string{},
		UUIDVision:  "11111111-1111-1111-1111-111111111111",
		UUIDPlain:   "22222222-2222-2222-2222-222222222222",
		PBK:         testPBK, SID: "0123abcd", SNI: "a.example",
		RejectPorts: []string{},
	}
	for _, o := range opts {
		o(&n)
	}
	signed, err := SignDescriptor(n, priv, DescriptorLifetime)
	if err != nil {
		panic(err)
	}
	testKeys[signed.ID] = priv
	return signed
}

// resign переподписывает дескриптор после правки полей.
func resign(n Node) Node {
	priv, ok := testKeys[n.ID]
	if !ok {
		panic("ключ личности узла неизвестен")
	}
	signed, err := SignDescriptor(n, priv, DescriptorLifetime)
	if err != nil {
		panic(err)
	}
	return signed
}

// linkFamily объявляет узлы роднёй взаимно, как того требует правило.
func linkFamily(a, b Node) (Node, Node) {
	a.Family = []string{b.ID}
	b.Family = []string{a.ID}
	return resign(a), resign(b)
}

func bw(v int64) func(*Node) { return func(n *Node) { n.BW = v } }

func testOpts() SelectOpts {
	return SelectOpts{Guards: 2, GuardDays: 30, GuardRetireDays: 7, BWCap: 5, Circuits: 4}
}

func TestCompatible(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	cases := []struct {
		name string
		n    Node
		want bool
	}{
		{"тот же узел", a, false},
		{"та же сеть /16", mkNode("c", "1.1.9.9", []string{"middle"}), false},
		{"соседняя сеть", mkNode("d", "1.2.0.1", []string{"middle"}), true},
		{"другой адрес", mkNode("e", "3.3.0.1", []string{"middle"}), true},
	}
	for _, c := range cases {
		if got := Compatible(c.n, []Node{a}, testOpts()); got != c.want {
			t.Errorf("%s: получили %v, ожидали %v", c.name, got, c.want)
		}
	}
	lab := testOpts()
	lab.IgnoreNet = true
	same := mkNode("c", "1.1.9.9", []string{"middle"})
	if !Compatible(same, []Node{a}, lab) {
		t.Error("с ignoreNet узлы из одной сети должны считаться совместимыми")
	}
}

func TestFamilyMustBeReciprocal(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"middle"})

	// одностороннее заявление ничего не значит: иначе враждебный узел
	// объявил бы роднёй пол-сети и вытеснил честные узлы из цепочек
	a1 := resign(func() Node { a.Family = []string{b.ID}; return a }())
	if !Compatible(b, []Node{a1}, testOpts()) {
		t.Error("одностороннее родство не должно разводить узлы")
	}

	a2, b2 := linkFamily(a, b)
	if Compatible(b2, []Node{a2}, testOpts()) {
		t.Error("взаимно объявленные родственники не должны попадать в одну цепочку")
	}
	if err := a2.Validate(); err != nil {
		t.Errorf("дескриптор с роднёй не проходит проверку: %v", err)
	}
}

func TestSameASSeparatesNodes(t *testing.T) {
	// разные /16 могут принадлежать одному провайдеру
	table := &ASNTable{ranges: []asnRange{
		{lo: mustIPv4("1.1.0.0"), hi: mustIPv4("1.1.255.255"), asn: 100},
		{lo: mustIPv4("9.9.0.0"), hi: mustIPv4("9.9.255.255"), asn: 100},
		{lo: mustIPv4("7.7.0.0"), hi: mustIPv4("7.7.255.255"), asn: 200},
	}}
	opts := testOpts()
	opts.ASN = table

	a := mkNode("a", "1.1.0.1", []string{"guard"})
	sameAS := mkNode("b", "9.9.0.1", []string{"middle"})
	otherAS := mkNode("c", "7.7.0.1", []string{"middle"})
	unknown := mkNode("d", "3.3.0.1", []string{"middle"})

	if Compatible(sameAS, []Node{a}, opts) {
		t.Error("узлы одной автономной системы не должны попадать в одну цепочку")
	}
	if !Compatible(otherAS, []Node{a}, opts) {
		t.Error("узлы разных автономных систем совместимы")
	}
	if !Compatible(unknown, []Node{a}, opts) {
		t.Error("узел вне таблицы не должен отбрасываться")
	}
	// без таблицы разведение идёт только по сетям
	if !Compatible(sameAS, []Node{a}, testOpts()) {
		t.Error("без таблицы узлы разных /16 совместимы")
	}
}

func mustIPv4(s string) uint32 {
	v, ok := ipv4ToUint(s)
	if !ok {
		panic(s)
	}
	return v
}

func TestCompatibleRejectsBadAddress(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	bad := mkNode("b", "не адрес", []string{"middle"})
	if Compatible(bad, []Node{a}, testOpts()) {
		t.Error("узел с некорректным адресом не должен попадать в цепочку")
	}
}

func TestBWWeightsCapALiar(t *testing.T) {
	pool := []Node{
		mkNode("slow", "1.1.0.1", []string{"exit"}, bw(1000)),
		mkNode("mid", "2.2.0.1", []string{"exit"}, bw(2000)),
		mkNode("liar", "3.3.0.1", []string{"exit"}, bw(1<<40)),
	}
	w := BWWeights(pool, 5)
	if w[2] != 2000*5 {
		t.Fatalf("вес лжеца %v, ожидали %v", w[2], 2000*5.0)
	}
}

func TestBWWeightsUnmeasuredGetsMedian(t *testing.T) {
	pool := []Node{
		mkNode("a", "1.1.0.1", []string{"exit"}, bw(1000)),
		mkNode("b", "2.2.0.1", []string{"exit"}, bw(3000)),
		mkNode("new", "3.3.0.1", []string{"exit"}),
	}
	if w := BWWeights(pool, 5); w[2] != 3000 {
		t.Fatalf("вес неизмеренного узла %v, ожидали медиану 3000", w[2])
	}
	all := []Node{mkNode("a", "1.1.0.1", nil), mkNode("b", "2.2.0.1", nil)}
	for _, x := range BWWeights(all, 5) {
		if x != 1 {
			t.Fatalf("без измерений веса должны быть равны, получили %v", x)
		}
	}
}

func TestWeightedPickFavoursFasterNodes(t *testing.T) {
	pool := []Node{
		mkNode("slow", "1.1.0.1", []string{"exit"}, bw(1000)),
		mkNode("fast", "2.2.0.1", []string{"exit"}, bw(5000)),
	}
	counts := map[string]int{}
	for i := 0; i < 600; i++ {
		n, ok := WeightedPick(pool, nil, testOpts())
		if !ok {
			t.Fatal("выбор не состоялся")
		}
		counts[n.Nick]++
	}
	if counts["fast"] <= counts["slow"] {
		t.Fatalf("быстрый узел должен выбираться чаще: %v", counts)
	}
	if counts["slow"] == 0 {
		t.Fatal("медленный узел не должен полностью исключаться")
	}
}

func TestBuildCircuitsUsesDistinctNodes(t *testing.T) {
	var pool []Node
	for i := 1; i <= 3; i++ {
		pool = append(pool,
			mkNode(fmt.Sprintf("g%d", i), fmt.Sprintf("%d.1.0.1", i), []string{"guard"}),
			mkNode(fmt.Sprintf("m%d", i), fmt.Sprintf("%d.2.0.1", i+10), []string{"middle"}),
			mkNode(fmt.Sprintf("e%d", i), fmt.Sprintf("%d.3.0.1", i+20), []string{"exit"}))
	}
	guards := withRole(pool, "guard")
	paths, err := BuildCircuits(pool, guards, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("ни одной цепочки")
	}
	for _, p := range paths {
		set := map[string]bool{p.Guard.Nick: true, p.Middle.Nick: true, p.Exit.Nick: true}
		if len(set) != 3 {
			t.Errorf("узлы цепочки повторяются: %v", p.Nicks())
		}
	}
}

func TestBuildCircuitsFailsWithoutExits(t *testing.T) {
	pool := []Node{
		mkNode("g1", "1.1.0.1", []string{"guard"}),
		mkNode("m1", "2.2.0.1", []string{"middle"}),
	}
	if _, err := BuildCircuits(pool, withRole(pool, "guard"), testOpts()); err == nil {
		t.Fatal("без выходных узлов сборка обязана падать")
	}
}

func guardPool() []Node {
	var pool []Node
	for i := 1; i <= 5; i++ {
		pool = append(pool, mkNode(fmt.Sprintf("g%d", i),
			fmt.Sprintf("%d.%d.0.1", i, i), []string{"guard"}))
	}
	return pool
}

func TestGuardSurvivesTemporaryAbsence(t *testing.T) {
	st, opts := &State{}, testOpts()
	pool := guardPool()
	quiet := func(string, ...any) {}

	first := ChooseGuards(pool, st, opts, quiet)
	if len(first) != 2 {
		t.Fatalf("ожидали 2 закреплённых guard, получили %d", len(first))
	}
	gone := first[0].ID

	var degraded []Node
	for _, n := range pool {
		if n.ID != gone {
			degraded = append(degraded, n)
		}
	}
	ChooseGuards(degraded, st, opts, quiet)
	if !pinnedHas(st, gone) {
		t.Fatal("временно недоступный guard обязан остаться закреплённым")
	}

	back := ChooseGuards(pool, st, opts, quiet)
	if !contains(back, gone) {
		t.Fatal("вернувшийся guard должен снова использоваться")
	}
}

func TestPinnedSetIsBounded(t *testing.T) {
	st := &State{}
	opts := testOpts()
	pool := guardPool()
	for round := 0; round < 8; round++ {
		var sub []Node
		for i, n := range pool {
			if i%2 == round%2 {
				sub = append(sub, n)
			}
		}
		ChooseGuards(sub, st, opts, func(string, ...any) {})
	}
	if len(st.Guards) > opts.Guards*2 {
		t.Fatalf("закреплённых guard стало %d, предел %d", len(st.Guards), opts.Guards*2)
	}
}

func TestGuardRetiredAfterLongAbsence(t *testing.T) {
	st, opts := &State{}, testOpts()
	opts.Guards = 1
	pool := guardPool()
	ChooseGuards(pool, st, opts, func(string, ...any) {})
	id := st.Guards[0].ID
	st.Guards[0].LastSeen = time.Now().Add(-8 * 24 * time.Hour).Unix()

	var degraded []Node
	for _, n := range pool {
		if n.ID != id {
			degraded = append(degraded, n)
		}
	}
	ChooseGuards(degraded, st, opts, func(string, ...any) {})
	if pinnedHas(st, id) {
		t.Fatal("guard, недоступный дольше срока, обязан быть снят")
	}
}

func TestGuardRotatesAfterGuardDays(t *testing.T) {
	st, opts := &State{}, testOpts()
	opts.Guards = 1
	pool := guardPool()
	ChooseGuards(pool, st, opts, func(string, ...any) {})
	expired := time.Now().Add(-31 * 24 * time.Hour).Unix()
	st.Guards[0].Since = expired

	ChooseGuards(pool, st, opts, func(string, ...any) {})
	if len(st.Guards) != 1 {
		t.Fatalf("закреплённых guard стало %d", len(st.Guards))
	}
	// закрепление обязано быть переоформлено заново, даже если жребий
	// снова выпал на тот же узел
	if st.Guards[0].Since == expired {
		t.Fatal("guard с истёкшим сроком закрепления не сменился")
	}
}

func TestPortRejected(t *testing.T) {
	cases := []struct {
		reject []string
		port   int
		want   bool
	}{
		{[]string{"25"}, 25, true},
		{[]string{"25"}, 26, false},
		{[]string{"1-79"}, 79, true},
		{[]string{"1-79"}, 80, false},
		{[]string{"25", "465", "1-79"}, 465, true},
		{nil, 25, false},
	}
	for _, c := range cases {
		if got := PortRejected(c.reject, c.port); got != c.want {
			t.Errorf("PortRejected(%v, %d) = %v, ожидали %v", c.reject, c.port, got, c.want)
		}
	}
}

func TestRandomnessSpreadsOverRange(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 400; i++ {
		v := randIntn(8)
		if v < 0 || v >= 8 {
			t.Fatalf("randIntn(8) вернул %d", v)
		}
		seen[v] = true
	}
	if len(seen) < 8 {
		var got []int
		for k := range seen {
			got = append(got, k)
		}
		sort.Ints(got)
		t.Fatalf("случайность покрыла только %v", got)
	}
}

func pinnedHas(st *State, id string) bool {
	for _, g := range st.Guards {
		if g.ID == id {
			return true
		}
	}
	return false
}

func contains(nodes []Node, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// ── из client_circuits_test.go ──
func samplePath(i int) Path {
	return Path{
		Guard: mkNode("g"+itoa(i), "10."+itoa(i)+".0.1", []string{"guard"}),
		Middle: mkNode("m"+itoa(i), "10."+itoa(i+50)+".0.1", []string{"middle"}),
		Exit:   mkNode("e"+itoa(i), "10."+itoa(i+100)+".0.1", []string{"exit"}),
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ── сборка outbound-ов ───────────────────────────────────────────────────

func TestHopOutboundNesting(t *testing.T) {
	p := samplePath(1)
	h1 := hopOutbound("hop1-s0", p.Guard, p.Guard.UUIDVision, visionFlow, "firefox", "")
	h2 := hopOutbound("hop2-s0", p.Middle, p.Middle.UUIDPlain, "", "firefox", "hop1-s0")
	ex := hopOutbound("exit-s0", p.Exit, p.Exit.UUIDPlain, "", "firefox", "hop2-s0")

	if h1.StreamSettings.Sockopt != nil {
		t.Error("первый хоп не должен идти через dialerProxy")
	}
	if h2.StreamSettings.Sockopt.DialerProxy != "hop1-s0" {
		t.Errorf("второй хоп идёт через %q", h2.StreamSettings.Sockopt.DialerProxy)
	}
	if ex.StreamSettings.Sockopt.DialerProxy != "hop2-s0" {
		t.Errorf("выход идёт через %q", ex.StreamSettings.Sockopt.DialerProxy)
	}
	if h1.Settings.Vnext[0].Users[0].Flow != visionFlow {
		t.Error("на первом хопе обязан быть flow vision")
	}
	for _, ob := range []outboundJSON{h2, ex} {
		if ob.Settings.Vnext[0].Users[0].Flow != "" {
			t.Errorf("%s: внутри туннеля flow быть не должно", ob.Tag)
		}
	}
	if h1.StreamSettings.Reality.Fingerprint != "firefox" {
		t.Errorf("отпечаток %q", h1.StreamSettings.Reality.Fingerprint)
	}
}

func TestHopOutboundUsesDistinctUUIDs(t *testing.T) {
	p := samplePath(1)
	h1 := hopOutbound("a", p.Guard, p.Guard.UUIDVision, visionFlow, "firefox", "")
	h2 := hopOutbound("b", p.Guard, p.Guard.UUIDPlain, "", "firefox", "a")
	if h1.Settings.Vnext[0].Users[0].ID == h2.Settings.Vnext[0].Users[0].ID {
		t.Error("входной и промежуточный хопы обязаны использовать разные UUID")
	}
}

func TestBaseConfigPinsSlotsToExits(t *testing.T) {
	raw := clientCoreConfig(3, "warning")
	var cfg struct {
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
				Network     string   `json:"network"`
			} `json:"rules"`
		} `json:"routing"`
		Inbounds []any `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("базовый конфиг не разобран: %v\n%s", err, raw)
	}
	if len(cfg.Inbounds) != 0 {
		t.Error("ядру не нужны inbound-ы: трафик приходит через core.Dial")
	}
	if len(cfg.Routing.Rules) != 4 {
		t.Fatalf("правил %d, ожидали 4", len(cfg.Routing.Rules))
	}
	for i := 0; i < 3; i++ {
		r := cfg.Routing.Rules[i]
		if r.InboundTag[0] != "slot-"+itoa(i) || r.OutboundTag != "exit-s"+itoa(i) {
			t.Errorf("правило %d: %v → %s", i, r.InboundTag, r.OutboundTag)
		}
	}
	last := cfg.Routing.Rules[3]
	if last.OutboundTag != "block" || last.Network != "tcp,udp" {
		t.Error("последнее правило обязано закрывать всё остальное")
	}
}

// ── работа с живым ядром ─────────────────────────────────────────────────

func newTestCircuits(t *testing.T, count int) *Circuits {
	t.Helper()
	c, err := NewCircuits(CircuitsOpts{
		Count: count, Fingerprint: "firefox", FailThreshold: 2,
		Cooldown: time.Minute, LogLevel: "none",
	}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("ядро не поднялось: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func handlerTags(c *Circuits) map[string]bool {
	out := map[string]bool{}
	for _, h := range c.mgr.ListHandlers(context.Background()) {
		out[h.Tag()] = true
	}
	return out
}

func TestInstallAddsRealHandlers(t *testing.T) {
	c := newTestCircuits(t, 2)
	if err := c.Install(0, samplePath(1)); err != nil {
		t.Fatalf("цепочка не установилась: %v", err)
	}
	tags := handlerTags(c)
	for _, want := range []string{"hop1-s0", "hop2-s0", "exit-s0"} {
		if !tags[want] {
			t.Errorf("обработчик %s не зарегистрирован", want)
		}
	}
	if tags["hop1-s1"] {
		t.Error("второй слот не должен быть заполнен")
	}
}

func TestInstallReplacesChainInPlace(t *testing.T) {
	c := newTestCircuits(t, 1)
	if err := c.Install(0, samplePath(1)); err != nil {
		t.Fatal(err)
	}
	before := c.Slots()[0].Path().Exit.Nick

	if err := c.Install(0, samplePath(2)); err != nil {
		t.Fatalf("ротация слота не удалась: %v", err)
	}
	after := c.Slots()[0].Path().Exit.Nick
	if before == after {
		t.Fatal("цепочка в слоте не сменилась")
	}
	// теги те же, значит правила маршрутизации трогать не пришлось
	tags := handlerTags(c)
	for _, want := range []string{"hop1-s0", "hop2-s0", "exit-s0"} {
		if !tags[want] {
			t.Errorf("после ротации нет обработчика %s", want)
		}
	}
	if h := c.mgr.GetHandler("exit-s0"); h == nil {
		t.Fatal("выходной обработчик исчез")
	}
}

func TestInstallRejectsUnknownSlot(t *testing.T) {
	c := newTestCircuits(t, 1)
	if err := c.Install(5, samplePath(1)); err == nil {
		t.Fatal("установка в несуществующий слот обязана падать")
	}
}

func TestInstallRollsBackOnBadNode(t *testing.T) {
	c := newTestCircuits(t, 1)
	bad := samplePath(1)
	bad.Exit.IP = "" // адрес, который Xray не примет
	if err := c.Install(0, bad); err == nil {
		t.Fatal("цепочка с негодным узлом не должна устанавливаться")
	}
	if c.Slots()[0].ready {
		t.Error("слот помечен готовым после неудачной установки")
	}
	if tags := handlerTags(c); tags["hop1-s0"] || tags["hop2-s0"] {
		t.Error("после отката не должно остаться половины цепочки")
	}
}

func TestCoreOutboundManagerIsLive(t *testing.T) {
	c := newTestCircuits(t, 1)
	var _ outbound.Manager = c.mgr
	if c.mgr.GetHandler("block") == nil {
		t.Fatal("базовый обработчик block отсутствует")
	}
}

// ── выбор слота ──────────────────────────────────────────────────────────

func fakeCircuits(count int, reject map[int][]string) *Circuits {
	c := &Circuits{
		opts: CircuitsOpts{Count: count, FailThreshold: 2, Cooldown: time.Minute},
		logf: func(string, ...any) {},
	}
	for i := 0; i < count; i++ {
		p := samplePath(i + 1)
		p.Exit.RejectPorts = reject[i]
		c.slots = append(c.slots, &Slot{
			Idx: i, Tag: "slot-" + itoa(i), path: p, ready: true,
		})
	}
	return c
}

func TestPickIsStableForOneHost(t *testing.T) {
	c := fakeCircuits(4, nil)
	for _, host := range []string{"example.com", "api.ipify.org", "1.2.3.4"} {
		first := c.Pick(host, 443)
		for i := 0; i < 50; i++ {
			if got := c.Pick(host, 443); got != first {
				t.Fatalf("%s ушёл в разные цепочки: %d и %d", host, first.Idx, got.Idx)
			}
		}
	}
}

func TestPickSpreadsDifferentHosts(t *testing.T) {
	c := fakeCircuits(4, nil)
	used := map[int]bool{}
	for i := 0; i < 200; i++ {
		used[c.Pick("host"+itoa(i)+".example", 443).Idx] = true
	}
	if len(used) < 2 {
		t.Fatal("все хосты ушли в одну цепочку")
	}
}

func TestPickHonoursExitPolicy(t *testing.T) {
	c := fakeCircuits(4, map[int][]string{0: {"25"}, 1: {"25"}, 2: {"25"}})
	if got := c.Pick("mail.example", 25).Idx; got != 3 {
		t.Fatalf("порт 25 ушёл в цепочку %d, а её выход его не пропускает", got)
	}
	if c.Pick("mail.example", 443) == nil {
		t.Fatal("для 443 цепочка должна найтись")
	}
}

func TestPickReturnsNilWhenEveryExitBlocksPort(t *testing.T) {
	c := fakeCircuits(2, map[int][]string{0: {"25"}, 1: {"1-100"}})
	if c.Pick("mail.example", 25) != nil {
		t.Fatal("цепочка выбрана вопреки политике всех выходов")
	}
}

func TestPickSkipsEmptySlots(t *testing.T) {
	c := fakeCircuits(2, nil)
	c.slots[0].ready = false
	for i := 0; i < 20; i++ {
		if got := c.Pick("host"+itoa(i)+".example", 443); got.Idx != 1 {
			t.Fatal("выбран незаполненный слот")
		}
	}
}

func TestDeadCircuitIsAvoided(t *testing.T) {
	c := fakeCircuits(4, nil)
	host := "example.com"
	dead := c.Pick(host, 443)
	c.Report(dead, false)
	if c.Pick(host, 443) != dead {
		t.Fatal("одна ошибка не должна выводить цепочку из строя")
	}
	c.Report(dead, false)
	if c.Pick(host, 443) == dead {
		t.Fatal("мёртвая цепочка обязана выпасть из выбора")
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	c := fakeCircuits(4, nil)
	s := c.Pick("example.com", 443)
	c.Report(s, false)
	c.Report(s, true)
	c.Report(s, false)
	if c.Pick("example.com", 443) != s {
		t.Fatal("успешное соединение должно обнулять счётчик ошибок")
	}
}

func TestOtherHostsKeepTheirCircuits(t *testing.T) {
	c := fakeCircuits(4, nil)
	c.opts.FailThreshold = 1
	hosts := make([]string, 60)
	before := map[string]int{}
	for i := range hosts {
		hosts[i] = "h" + itoa(i) + ".example"
		before[hosts[i]] = c.Pick(hosts[i], 443).Idx
	}
	victim := before[hosts[0]]
	c.Report(c.slots[victim], false)

	moved := 0
	for _, h := range hosts {
		if before[h] != victim && c.Pick(h, 443).Idx != before[h] {
			moved++
		}
	}
	if moved != 0 {
		t.Fatalf("падение одной цепочки перетасовало %d чужих привязок", moved)
	}
}

func TestTotalFailureRecovers(t *testing.T) {
	c := fakeCircuits(2, nil)
	c.opts.FailThreshold = 1
	c.opts.Cooldown = time.Hour
	for _, s := range c.slots {
		c.Report(s, false)
	}
	if c.Pick("example.com", 443) == nil {
		t.Fatal("клиент не должен остаться совсем без выхода")
	}
}

func TestSlotLabel(t *testing.T) {
	c := fakeCircuits(1, nil)
	if got := c.slots[0].Label(); !strings.Contains(got, "→") {
		t.Errorf("метка слота %q не показывает цепочку", got)
	}
	empty := &Slot{Idx: 7}
	if got := empty.Label(); !strings.Contains(got, "пусто") {
		t.Errorf("метка пустого слота %q", got)
	}
}

// ── директория ──

// Золотые образцы подписанного консенсуса лежат в testdata. Они закрепляют
// формат: любое изменение канонического JSON или состава дескриптора ломает
// подпись, и тест это замечает. Пересоздать: REGEN_FIXTURES=1 go test -run Fixture
func fixtureKey() string { return pubKeyString(detKey(1)) }

func fixturePath(name string) string { return filepath.Join("testdata", name) }

// detKey даёт воспроизводимый ключ, чтобы образцы не менялись от запуска к запуску.
func detKey(seed byte) ed25519.PrivateKey {
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return ed25519.NewKeyFromSeed(raw)
}

func buildFixtureStore(t *testing.T) (*Store, ed25519.PrivateKey) {
	t.Helper()
	dirKey := detKey(1)
	// срок годности образца должен быть заведомо больше его срока жизни в
	// репозитории: иначе тест начинает падать через час после создания
	const forever = 100 * 365 * 24 * time.Hour
	store := NewStore(filepath.Join(t.TempDir(), "n.json"), forever, 0, 0, false,
		func(string, ...any) {})
	plan := []struct {
		nick    string
		ip      string
		roles   []string
		private bool
		reject  []string
		bw      int64
		seed    byte
	}{
		{"bridge1", "10.1.0.1", []string{"guard"}, true, nil, 0, 10},
		{"guard1", "10.2.0.1", []string{"guard", "middle"}, false, nil, 1500000, 20},
		{"middle1", "10.3.0.1", []string{"middle"}, false, nil, 0, 30},
		{"exit1", "10.4.0.1", []string{"exit"}, false, []string{"1-79", "25", "465"}, 987654321, 40},
	}
	for _, p := range plan {
		roles, err := NormalizeRoles(p.roles)
		if err != nil {
			t.Fatal(err)
		}
		reject := p.reject
		if reject == nil {
			reject = []string{}
		}
		n := Node{
			Nick: p.nick, IP: p.ip, Port: 443,
			UUIDVision:  "11111111-1111-1111-1111-111111111111",
			UUIDPlain:   "22222222-2222-2222-2222-222222222222",
			PBK:         testPBK, SID: "0123abcd", SNI: "www.cloudflare.com",
			Roles:       roles, Family: []string{}, BW: p.bw,
			RejectPorts: reject, Private: p.private,
		}
		signed, err := SignDescriptor(n, detKey(p.seed), 100*365*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Register(signed, p.ip, ""); err != nil {
			t.Fatalf("узел %s не зарегистрирован: %v", p.nick, err)
		}
	}
	return store, dirKey
}

func TestSignedFixtures(t *testing.T) {
	store, dirKey := buildFixtureStore(t)
	cons := NewConsensus(store, dirKey, 0)
	public, bridges := cons.Document(false), cons.Document(true)

	if os.Getenv("REGEN_FIXTURES") == "1" {
		for name, body := range map[string][]byte{
			"consensus.json": public, "bridges.json": bridges,
		} {
			if err := os.WriteFile(fixturePath(name), body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Log("образцы пересозданы")
	}

	key := pubKeyString(dirKey)
	body, err := VerifyDoc(readFixture(t, "consensus.json"), key)
	if err != nil {
		t.Fatalf("образец консенсуса не проходит проверку: %v", err)
	}
	var nicks []string
	for _, n := range body.Nodes {
		if err := n.Validate(); err != nil {
			t.Errorf("узел из образца негоден: %v", err)
		}
		nicks = append(nicks, n.Nick)
	}
	sort.Strings(nicks)
	if got := strings.Join(nicks, ","); got != "exit1,guard1,middle1" {
		t.Fatalf("узлы образца: %q", got)
	}
	if body.Bridges {
		t.Error("публичный консенсус помечен как список мостов")
	}

	br, err := VerifyDoc(readFixture(t, "bridges.json"), key)
	if err != nil {
		t.Fatalf("образец мостов не проходит проверку: %v", err)
	}
	if !br.Bridges || len(br.Nodes) != 1 || br.Nodes[0].Nick != "bridge1" {
		t.Fatalf("образец мостов: %+v", br.Nodes)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("образец %s не прочитан: %v", name, err)
	}
	return data
}

// Подмена дескриптора внутри подписанного консенсуса обязана быть замечена:
// подпись директории покрывает весь документ, а подпись узла — его дескриптор.
func TestTamperedDescriptorRejected(t *testing.T) {
	store, dirKey := buildFixtureStore(t)
	doc := NewConsensus(store, dirKey, 0).Document(false)
	body, err := VerifyDoc(doc, pubKeyString(dirKey))
	if err != nil {
		t.Fatal(err)
	}
	victim := body.Nodes[0]
	if err := victim.Validate(); err != nil {
		t.Fatalf("исходный узел негоден: %v", err)
	}

	// директория пытается подменить ключ Reality на свой
	forged := victim
	forged.PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := forged.Validate(); err == nil {
		t.Fatal("подмена ключа Reality не замечена")
	}
	// и адрес
	moved := victim
	moved.IP = "6.6.6.6"
	if err := moved.Validate(); err == nil {
		t.Fatal("подмена адреса не замечена")
	}
	// и чужая подпись под своим именем
	stolen := victim
	stolen.IDKey = base64.StdEncoding.EncodeToString(
		detKey(200).Public().(ed25519.PublicKey))
	if err := stolen.Validate(); err == nil {
		t.Fatal("подмена ключа личности не замечена")
	}
}

func TestVerifyRejectsWrongDirectoryKey(t *testing.T) {
	store, dirKey := buildFixtureStore(t)
	doc := NewConsensus(store, dirKey, 0).Document(false)
	other := pubKeyString(detKey(99))
	if _, err := VerifyDoc(doc, other); err == nil {
		t.Fatal("документ принят с чужим ключом директории")
	}
}

func TestCanonicalJSONRules(t *testing.T) {
	// ключи по алфавиту, без пробелов, целые числа без экспоненты
	got, err := canonicalJSON([]byte(`{"b": 2, "a": {"z": 1, "y": 1790069686}, "c": [3, true]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"y":1790069686,"z":1},"b":2,"c":[3,true]}`
	if string(got) != want {
		t.Fatalf("канонизация: получили %s, ожидали %s", got, want)
	}
}

func TestFetchUsesBridgesWhenTokenGiven(t *testing.T) {
	cons := readFixture(t, "consensus.json")
	bridges := readFixture(t, "bridges.json")
	var gotBridgeAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/consensus":
			w.Write(cons)
		case "/bridges":
			gotBridgeAuth = r.Header.Get("Authorization")
			if gotBridgeAuth != "Bearer secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write(bridges)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	d := &DirectoryClient{URL: srv.URL, BridgeToken: "secret"}
	public, br, err := d.Fetch(fixtureKey(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(public) != 3 || len(br) != 1 {
		t.Fatalf("публичных %d, мостов %d", len(public), len(br))
	}
	if !br[0].Bridge {
		t.Error("мост не помечен флагом Bridge")
	}
	if gotBridgeAuth != "Bearer secret" {
		t.Errorf("токен мостов не отправлен: %q", gotBridgeAuth)
	}
}

func TestFetchSurvivesMissingBridges(t *testing.T) {
	cons := readFixture(t, "consensus.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/consensus" {
			w.Write(cons)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := &DirectoryClient{URL: srv.URL, BridgeToken: "wrong"}
	public, br, err := d.Fetch(fixtureKey(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("недоступные мосты не должны валить работу: %v", err)
	}
	if len(public) != 3 || len(br) != 0 {
		t.Fatalf("публичных %d, мостов %d", len(public), len(br))
	}
}

// ── директория: что она теперь не может ──

func newTestStore(t *testing.T, opts ...func(*Store)) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "nodes.json"), time.Hour, 0, 0, false,
		func(string, ...any) {})
	for _, o := range opts {
		o(s)
	}
	return s
}

func TestRegisterRequiresSelfSignature(t *testing.T) {
	s := newTestStore(t)
	n := mkNode("a", "1.1.0.1", []string{"guard"})

	unsigned := n
	unsigned.Sig = ""
	if _, err := s.Register(unsigned, "1.1.0.1", ""); err == nil {
		t.Fatal("дескриптор без подписи принят")
	}

	forged := n
	forged.PBK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := s.Register(forged, "1.1.0.1", ""); err == nil {
		t.Fatal("дескриптор с подменённым ключом Reality принят")
	}

	if _, err := s.Register(n, "1.1.0.1", ""); err != nil {
		t.Fatalf("подписанный дескриптор отвергнут: %v", err)
	}
}

func TestRegisterChecksObservedAddress(t *testing.T) {
	s := newTestStore(t)
	n := mkNode("a", "1.1.0.1", []string{"guard"})
	_, err := s.Register(n, "9.9.9.9", "")
	mism, ok := err.(addressMismatch)
	if !ok {
		t.Fatalf("ожидали расхождение адреса, получили %v", err)
	}
	if mism.observed != "9.9.9.9" {
		t.Fatalf("директория не сообщила наблюдаемый адрес: %q", mism.observed)
	}
}

func TestRegisterBindsTokenToIdentity(t *testing.T) {
	s := newTestStore(t)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"guard"})

	if _, err := s.Register(a, "1.1.0.1", ""); err != nil {
		t.Fatal(err)
	}
	// токен уже закреплён за первой личностью: второй узел им не пройдёт
	if _, err := s.Register(b, "2.2.0.1", a.ID); err == nil {
		t.Fatal("чужой личности разрешили использовать закреплённый токен")
	}
	if _, err := s.Register(a, "1.1.0.1", a.ID); err != nil {
		t.Fatalf("владельцу токена отказали: %v", err)
	}
}

func TestRegisterKeepsEndpointUnique(t *testing.T) {
	s := newTestStore(t)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "1.1.0.1", []string{"guard"})
	if _, err := s.Register(a, "1.1.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(b, "1.1.0.1", ""); err == nil {
		t.Fatal("вторая личность заняла чужую точку входа")
	}
}

func TestRegisterHonoursLimits(t *testing.T) {
	s := newTestStore(t, func(s *Store) { s.maxNodes = 1 })
	if _, err := s.Register(mkNode("a", "1.1.0.1", []string{"guard"}), "1.1.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(mkNode("b", "2.2.0.1", []string{"guard"}), "2.2.0.1", ""); err == nil {
		t.Fatal("предел числа узлов не сработал")
	}

	s2 := newTestStore(t, func(s *Store) { s.maxPerIP = 1 })
	n1 := mkNode("a", "1.1.0.1", []string{"guard"})
	n2 := mkNode("b", "1.1.0.1", []string{"guard"}, func(n *Node) { n.Port = 444 })
	if _, err := s2.Register(n1, "1.1.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Register(n2, "1.1.0.1", ""); err == nil {
		t.Fatal("предел числа узлов с адреса не сработал")
	}
}

func TestExpiredDescriptorLeavesConsensus(t *testing.T) {
	s := newTestStore(t)
	n := mkNode("a", "1.1.0.1", []string{"guard"})
	if _, err := s.Register(n, "1.1.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if len(s.Alive(false)) != 1 {
		t.Fatal("свежий узел не попал в консенсус")
	}
	s.mu.Lock()
	s.nodes[n.ID].Expires = time.Now().Add(-time.Minute).Unix()
	s.mu.Unlock()
	if len(s.Alive(false)) != 0 {
		t.Fatal("узел с просроченным дескриптором остался в консенсусе")
	}
}

// ── кворум директорий ──

// fakeDirectory — директория, отдающая заранее заданный набор узлов.
// Журнал прозрачности у неё есть: клиент требует его по умолчанию.
func fakeDirectory(t *testing.T, key ed25519.PrivateKey, public, bridges []Node,
	bridgeToken string) *httptest.Server {
	return fakeDirectoryOpt(t, key, public, bridges, bridgeToken, true)
}

// fakeDirectoryNoLog — директория без журнала, для проверок самого требования.
func fakeDirectoryNoLog(t *testing.T, key ed25519.PrivateKey, public, bridges []Node,
	bridgeToken string) *httptest.Server {
	return fakeDirectoryOpt(t, key, public, bridges, bridgeToken, false)
}

func fakeDirectoryOpt(t *testing.T, key ed25519.PrivateKey, public, bridges []Node,
	bridgeToken string, withLog bool) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "n.json"), time.Hour, 0, 0, false,
		func(string, ...any) {})
	for _, n := range append(append([]Node{}, public...), bridges...) {
		if _, err := store.Register(n, n.IP, ""); err != nil {
			t.Fatalf("узел %s не зарегистрирован: %v", n.Short(), err)
		}
	}
	srv := &dirServer{
		store: store, consensus: NewConsensus(store, key, 0),
		sharedToken: "t", bridgeToken: bridgeToken, logf: func(string, ...any) {},
	}
	if withLog {
		tlog := NewTransparencyLog(filepath.Join(dir, "log.json"), key)
		srv.log = tlog
		srv.consensus = srv.consensus.WithLog(tlog)
	}
	return httptest.NewServer(srv)
}

func refsOf(srv ...*httptest.Server) []DirectoryRef {
	out := make([]DirectoryRef, len(srv))
	for i, s := range srv {
		out[i] = DirectoryRef{URL: s.URL}
	}
	return out
}

func withKeys(refs []DirectoryRef, keys ...ed25519.PrivateKey) []DirectoryRef {
	for i := range refs {
		refs[i].Key = pubKeyString(keys[i])
	}
	return refs
}

func quietLog(string, ...any) {}

func TestQuorumNeedsSeveralDirectories(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"middle"})
	lonely := mkNode("lonely", "3.3.0.1", []string{"exit"})

	k1, k2, k3 := detKey(1), detKey(2), detKey(3)
	// третья директория в одиночку добавила свой узел
	d1 := fakeDirectory(t, k1, []Node{a, b}, nil, "")
	d2 := fakeDirectory(t, k2, []Node{a, b}, nil, "")
	d3 := fakeDirectory(t, k3, []Node{a, b, lonely}, nil, "")
	defer func() { d1.Close(); d2.Close(); d3.Close() }()

	set, err := NewDirectorySet(withKeys(refsOf(d1, d2, d3), k1, k2, k3), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.Quorum != 2 {
		t.Fatalf("кворум по умолчанию %d, ожидали большинство из трёх", set.Quorum)
	}
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range res.Nodes {
		got[n.Nick] = true
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("узлы с кворумом потерялись: %v", got)
	}
	if got["lonely"] {
		t.Fatal("узел, о котором сказала одна директория, попал в набор")
	}
	if res.Rejected != 1 {
		t.Fatalf("отвергнуто %d узлов, ожидали 1", res.Rejected)
	}
}

func TestQuorumSurvivesOneDirectoryOmittingNode(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"middle"})
	k1, k2, k3 := detKey(1), detKey(2), detKey(3)

	// первая директория умалчивает об узле b
	d1 := fakeDirectory(t, k1, []Node{a}, nil, "")
	d2 := fakeDirectory(t, k2, []Node{a, b}, nil, "")
	d3 := fakeDirectory(t, k3, []Node{a, b}, nil, "")
	defer func() { d1.Close(); d2.Close(); d3.Close() }()

	set, _ := NewDirectorySet(withKeys(refsOf(d1, d2, d3), k1, k2, k3), 0, nil)
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидали 2: умолчание одной директории не должно скрывать узел",
			len(res.Nodes))
	}
}

func TestQuorumFailsWhenTooFewAnswer(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	k1, k2 := detKey(1), detKey(2)
	d1 := fakeDirectory(t, k1, []Node{a}, nil, "")
	d2 := fakeDirectory(t, k2, []Node{a}, nil, "")
	refs := withKeys(refsOf(d1, d2), k1, k2)
	d2.Close() // вторая недоступна
	defer d1.Close()

	set, _ := NewDirectorySet(refs, 2, nil)
	if _, err := set.Fetch(quietLog); err == nil {
		t.Fatal("кворум собран, хотя ответила одна директория из двух")
	}
}

func TestQuorumTakesNewestDescriptor(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	older := a
	time.Sleep(1100 * time.Millisecond) // отметка времени в секундах
	newer := resign(a)

	k1, k2 := detKey(1), detKey(2)
	d1 := fakeDirectory(t, k1, []Node{older}, nil, "")
	d2 := fakeDirectory(t, k2, []Node{newer}, nil, "")
	defer func() { d1.Close(); d2.Close() }()

	set, _ := NewDirectorySet(withKeys(refsOf(d1, d2), k1, k2), 2, nil)
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидали 1", len(res.Nodes))
	}
	if res.Nodes[0].Published != newer.Published {
		t.Fatal("взят не самый свежий дескриптор")
	}
}

func TestQuorumRejectsForgedDirectoryKey(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	k1 := detKey(1)
	d1 := fakeDirectory(t, k1, []Node{a}, nil, "")
	defer d1.Close()

	// закреплён чужой ключ: директория не пройдёт проверку
	refs := []DirectoryRef{{URL: d1.URL, Key: pubKeyString(detKey(77))}}
	set, _ := NewDirectorySet(refs, 1, nil)
	if _, err := set.Fetch(quietLog); err == nil {
		t.Fatal("директория с чужим ключом принята")
	}
}

func TestQuorumUnionsBridges(t *testing.T) {
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	br := mkNode("br", "4.4.0.1", []string{"guard"}, func(n *Node) { n.Private = true })
	k1, k2 := detKey(1), detKey(2)
	// мост известен только одной директории: мосты выдают адресно
	d1 := fakeDirectory(t, k1, []Node{a}, []Node{br}, "bt")
	d2 := fakeDirectory(t, k2, []Node{a}, nil, "bt")
	defer func() { d1.Close(); d2.Close() }()

	refs := withKeys(refsOf(d1, d2), k1, k2)
	for i := range refs {
		refs[i].BridgeToken = "bt"
	}
	set, _ := NewDirectorySet(refs, 2, nil)
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bridges) != 1 || res.Bridges[0].Nick != "br" {
		t.Fatalf("мосты: %+v (к ним кворум не применяется)", res.Bridges)
	}
}

func TestBuildDirectoryRefs(t *testing.T) {
	refs, err := buildDirectoryRefs("http://a, http://b", "", "t1,t2", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Token != "t1" || refs[1].Token != "t2" {
		t.Fatalf("разбор списков: %+v", refs)
	}
	// одно значение растягивается на все директории
	refs, err = buildDirectoryRefs("http://a,http://b", "", "one", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if refs[0].Token != "one" || refs[1].Token != "one" {
		t.Fatalf("одиночный токен не растянут: %+v", refs)
	}
	if _, err := buildDirectoryRefs("http://a,http://b", "", "t1,t2,t3", "", ""); err == nil {
		t.Fatal("несовпадение длин списков не замечено")
	}
	if _, err := NewDirectorySet([]DirectoryRef{{URL: "http://a"}, {URL: "http://a"}}, 0, nil); err == nil {
		t.Fatal("повтор директории не замечен")
	}
}
