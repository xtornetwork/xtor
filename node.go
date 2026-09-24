package main

// Узел сети: встроенный сервер Xray (VLESS + Reality), регистрация в
// директории и политика исходящих соединений.
//
// Guard и middle обязаны выпускать трафик только на другие узлы сети, иначе
// они работают как открытый прокси. Список соседей меняется постоянно, и в
// правилах маршрутизации это означало бы перезапуск ядра при каждом изменении.
// Поэтому политика вынесена в подменённый системный дозвонщик: список
// обновляется атомарно, ядро не перезапускается, живые соединения не рвутся.
//
// Фолбэк Reality (ответ на активное зондирование) ходит мимо этого дозвонщика,
// своим net.Dialer, поэтому маскировка продолжает работать.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

// NodeConfig — описание узла на диске.
type NodeConfig struct {
	// ключ личности: им узел подписывает свой дескриптор, из него выведено
	// его имя, и именно он не даёт директории подменить ключ Reality
	IdentityKey string `json:"identity_key"`

	Nick    string   `json:"nick"`
	Listen  string   `json:"listen"`
	Port    int      `json:"port"`
	Roles   []string `json:"roles"`
	Family  []string `json:"family"` // имена личностей родственных узлов
	Private bool     `json:"private"`

	// адрес, который директория видит снаружи; узнаётся при первой
	// регистрации и входит в подписанный дескриптор
	PublicIP string `json:"public_ip"`

	SNI        string `json:"sni"`
	Dest       string `json:"dest"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	UUIDVision string `json:"uuid_vision"`
	UUIDPlain  string `json:"uuid_plain"`

	// директории независимы: узел регистрируется в каждой, иначе он не
	// наберёт кворум у клиентов
	Directories []DirectoryRef `json:"directories"`
	Quorum      int            `json:"quorum"` // 0 — большинство

	RejectPorts  []string `json:"reject_ports"`
	DNSServers   []string `json:"dns_servers"`
	AllowPrivate bool     `json:"allow_private"`
	LogLevel     string   `json:"loglevel"`
	Show         bool     `json:"show"` // диагностика рукопожатия Reality
}

func LoadNodeConfig(path string) (*NodeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c NodeConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0"
	}
	if c.Dest == "" {
		c.Dest = c.SNI + ":443"
	}
	if c.LogLevel == "" {
		c.LogLevel = "warning"
	}
	if len(c.DNSServers) == 0 {
		c.DNSServers = []string{"localhost"}
	}
	if len(c.Directories) == 0 {
		return nil, fmt.Errorf("%s: не задано ни одной директории", path)
	}
	return &c, nil
}

func (c *NodeConfig) isExit() bool {
	for _, r := range c.Roles {
		if r == "exit" {
			return true
		}
	}
	return false
}

// Descriptor собирает и подписывает то, что узел сообщает о себе директории.
//
// Поля приводятся к канону здесь, до подписи: ни директория, ни клиент не
// вправе их переписывать, иначе подпись перестанет сходиться.
func (c *NodeConfig) Descriptor(bw int64, priv ed25519.PrivateKey) (Node, error) {
	reject := []string{}
	if c.isExit() {
		var err error
		if reject, err = NormalizePorts(c.RejectPorts); err != nil {
			return Node{}, err
		}
	}
	roles, err := NormalizeRoles(c.Roles)
	if err != nil {
		return Node{}, err
	}
	family := append([]string{}, c.Family...)
	sort.Strings(family)
	n := Node{
		Nick: c.Nick, IP: c.PublicIP, Port: c.Port,
		UUIDVision: strings.ToLower(c.UUIDVision), UUIDPlain: strings.ToLower(c.UUIDPlain),
		PBK: c.PublicKey, SID: strings.ToLower(c.ShortID), SNI: c.SNI,
		Roles: roles, Family: family, BW: bw, RejectPorts: reject, Private: c.Private,
	}
	return SignDescriptor(n, priv, DescriptorLifetime)
}

// ── политика исходящих соединений ────────────────────────────────────────

type peerPolicy struct {
	allowAll bool
	allowed  map[string]time.Time // "ip:port" -> до какого момента разрешён
}

func (p *peerPolicy) permits(dest xnet.Destination) bool {
	if p == nil || p.allowAll {
		return true
	}
	if dest.Address == nil || dest.Address.Family().IsDomain() {
		return false // промежуточный узел дозванивается только по адресам соседей
	}
	until, ok := p.allowed[fmt.Sprintf("%s:%d", dest.Address.IP().String(), dest.Port.Value())]
	return ok && time.Now().Before(until)
}

// policyDialer пропускает исходящие соединения ядра только туда, куда
// разрешает текущая политика.
type policyDialer struct {
	inner  internet.SystemDialer
	policy atomic.Pointer[peerPolicy]
	denied atomic.Int64
}

func (d *policyDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination,
	sockopt *internet.SocketConfig) (xnet.Conn, error) {
	if !d.policy.Load().permits(dest) {
		d.denied.Add(1)
		return nil, fmt.Errorf("узел не выпускает трафик на %s: адрес не принадлежит сети", dest)
	}
	return d.inner.Dial(ctx, src, dest, sockopt)
}

func (d *policyDialer) DestIpAddress() xnet.IP { return d.inner.DestIpAddress() }

// peerTracker хранит разрешённых соседей с отсрочкой удаления: узел, на минуту
// выпавший из консенсуса, не должен мгновенно становиться недоступным.
type peerTracker struct {
	grace time.Duration
	mu    sync.Mutex
	seen  map[string]time.Time
}

func newPeerTracker(grace time.Duration) *peerTracker {
	return &peerTracker{grace: grace, seen: map[string]time.Time{}}
}

func (t *peerTracker) update(nodes []Node, selfID string) *peerPolicy {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, n := range nodes {
		if n.ID == selfID {
			continue
		}
		if err := n.Validate(); err != nil {
			continue
		}
		t.seen[fmt.Sprintf("%s:%d", n.IP, n.Port)] = now.Add(t.grace)
	}
	allowed := make(map[string]time.Time, len(t.seen))
	for k, until := range t.seen {
		if now.After(until) {
			delete(t.seen, k)
			continue
		}
		allowed[k] = until
	}
	return &peerPolicy{allowed: allowed}
}

// ── конфиг ядра ──────────────────────────────────────────────────────────

var privateNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10",
}

// nodeCoreConfig собирает конфиг встроенного ядра.
//
// У выходного узла маршрутизация обязана резолвить имена до сопоставления
// правил: в режиме AsIs правило по адресам не срабатывает для доменного
// назначения, и блокировка приватных сетей обходится именем, которое
// резолвится в приватный адрес.
func nodeCoreConfig(c *NodeConfig) (string, error) {
	inbound := map[string]any{
		"tag": "onion-in", "listen": c.Listen, "port": c.Port, "protocol": "vless",
		"settings": map[string]any{
			"clients": []any{
				map[string]any{"id": c.UUIDVision, "flow": visionFlow, "email": "guard"},
				map[string]any{"id": c.UUIDPlain, "email": "relay"},
			},
			"decryption": "none",
		},
		"streamSettings": map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{
				"show": c.Show, "dest": c.Dest, "xver": 0,
				"serverNames": []string{c.SNI},
				"privateKey":  c.PrivateKey,
				"shortIds":    []string{c.ShortID},
			},
		},
		"sniffing": map[string]any{"enabled": false},
	}

	direct := map[string]any{"tag": "direct", "protocol": "freedom",
		"settings": map[string]any{}}
	rules := []any{}
	routing := map[string]any{"domainStrategy": "AsIs"}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": c.LogLevel},
		"inbounds":  []any{inbound},
		"outbounds": []any{direct, map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}}},
		"stats":     map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{
				// Запас на рукопожатие больше стандартных четырёх секунд: Reality
				// на свежем узле ждёт, пока закончится разведка сайта-прикрытия,
				// и повторяет проверку раз в пять секунд. С коротким запасом
				// сторона, которая дозванивается, обрывает связь раньше времени.
				"handshake": 30, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5,
				"bufferSize": 512,
			}},
			"system": map[string]any{
				"statsInboundUplink": true, "statsInboundDownlink": true,
			},
		},
	}

	if c.isExit() {
		routing["domainStrategy"] = "IPIfNonMatch"
		direct["settings"] = map[string]any{"domainStrategy": "UseIP"}
		cfg["dns"] = map[string]any{"servers": c.DNSServers, "queryStrategy": "UseIP"}
		if !c.AllowPrivate {
			rules = append(rules, map[string]any{
				"type": "field", "ip": privateNets, "outboundTag": "block"})
		}
		if ports, err := NormalizePorts(c.RejectPorts); err != nil {
			return "", err
		} else if len(ports) > 0 {
			rules = append(rules, map[string]any{
				"type": "field", "port": strings.Join(ports, ","), "outboundTag": "block"})
		}
	}
	// у guard и middle список соседей меняется слишком часто для правил
	// маршрутизации: их ограничивает policyDialer

	routing["rules"] = rules
	cfg["routing"] = routing
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ── измерение скорости ───────────────────────────────────────────────────

// bwMeter берёт счётчики прямо у встроенного ядра, без внешних вызовов.
type bwMeter struct {
	mgr   stats.Manager
	prev  int64
	at    time.Time
	rate  int64
	valid bool
}

func (m *bwMeter) sample() int64 {
	if m.mgr == nil {
		return 0
	}
	var total int64
	for _, name := range []string{
		"inbound>>>onion-in>>>traffic>>>uplink",
		"inbound>>>onion-in>>>traffic>>>downlink",
	} {
		if c := m.mgr.GetCounter(name); c != nil {
			total += c.Value()
		}
	}
	now := time.Now()
	if m.valid && total >= m.prev && now.After(m.at) {
		m.rate = int64(float64(total-m.prev) / now.Sub(m.at).Seconds())
	}
	m.prev, m.at, m.valid = total, now, true
	return m.rate
}

// ── запуск ───────────────────────────────────────────────────────────────

func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	cfgPath := fs.String("config", defaultNodeConfigPath(), "описание узла (JSON)")
	interval := fs.Duration("interval", 5*time.Minute, "период heartbeat и обновления соседей")
	peerGrace := fs.Duration("peer-grace", time.Hour,
		"сколько узел остаётся разрешённым после исчезновения из консенсуса")
	dump := fs.Bool("print-core-config", false, "напечатать конфиг ядра и выйти")
	_ = fs.Parse(args)

	c, err := LoadNodeConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("описание узла не прочитано: %w", err)
	}
	identity, err := DecodeIdentity(c.IdentityKey)
	if err != nil {
		return fmt.Errorf("ключ личности: %w", err)
	}
	nodeID := Fingerprint(identity.Public().(ed25519.PublicKey))
	dirs, err := NewDirectorySet(c.Directories, c.Quorum, nil)
	if err != nil {
		return err
	}
	dirs.HTTP = defaultHTTPClient()
	coreCfg, err := nodeCoreConfig(c)
	if err != nil {
		return err
	}
	if *dump {
		fmt.Println(coreCfg)
		return nil
	}

	// политика ставится до запуска ядра: до первого консенсуса узел никуда
	// не выпускает трафик, кроме случая выходного узла
	tracker := newPeerTracker(*peerGrace)
	pd := &policyDialer{inner: &internet.DefaultSystemDialer{}}
	pd.policy.Store(&peerPolicy{allowAll: c.isExit(), allowed: map[string]time.Time{}})
	internet.UseAlternativeSystemDialer(pd)

	cfg, err := serial.LoadJSONConfig(strings.NewReader(coreCfg))
	if err != nil {
		return fmt.Errorf("конфиг ядра не собран: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("ядро не создано: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("ядро не запустилось: %w", err)
	}
	defer inst.Close()

	meter := &bwMeter{}
	if sm, ok := inst.GetFeature(stats.ManagerType()).(stats.Manager); ok {
		meter.mgr = sm
	}

	logf("узел %s/%s: роли %s, Reality на %s:%d, SNI %s",
		c.Nick, nodeID[:8], strings.Join(c.Roles, ","), c.Listen, c.Port, c.SNI)
	if len(c.Family) > 0 {
		logf("объявленная родня: %d узлов (учитывается только взаимная)", len(c.Family))
	}
	if c.isExit() {
		ports, _ := NormalizePorts(c.RejectPorts)
		logf("выход: имена резолвятся до правил, не пропускаю приватные сети и порты %v", ports)
	} else {
		logf("промежуточный узел: выпускаю трафик только на соседей из консенсуса")
	}
	if c.Private {
		logf("узел непубличный: попадёт только в выдачу мостов")
	}
	logf("директории: %s", dirs.Describe())

	stop := waitForSignal()
	first := true
	for {
		bw := meter.sample()
		// адрес входит в подпись: при расхождении директория сообщает
		// наблюдаемый адрес, и дескриптор переподписывается
		accepted, observed := dirs.Register(func(ip string) (Node, error) {
			saved := c.PublicIP
			c.PublicIP = ip
			d, err := c.Descriptor(bw, identity)
			c.PublicIP = saved
			return d, err
		}, logf, c.PublicIP)
		if observed != "" && observed != c.PublicIP {
			logf("директории видят адрес %s, запоминаю", observed)
			c.PublicIP = observed
			if err := writeJSONAtomic(*cfgPath, c, 0o600); err != nil {
				logf("адрес не сохранён: %v", err)
			}
		}
		if accepted == 0 {
			logf("ни одна директория не приняла регистрацию")
		} else if first {
			logf("зарегистрирован как %s, адрес %s, принято директорий: %d из %d",
				nodeID, c.PublicIP, accepted, len(dirs.Refs))
			first = false
		}

		if !c.isExit() {
			// список соседей тоже идёт через кворум: иначе одна директория
			// могла бы вписать свой адрес и заставить узел ходить к ней
			res, err := dirs.Fetch(logf)
			if err != nil {
				logf("консенсус не получен: %v", err)
			} else {
				policy := tracker.update(res.Nodes, nodeID)
				pd.policy.Store(policy)
				logf("соседей разрешено: %d (с кворумом %d), отказов с прошлого раза: %d",
					len(policy.allowed), len(res.Nodes), pd.denied.Swap(0))
			}
		}

		select {
		case <-stop:
			logf("останавливаюсь")
			return nil
		case <-time.After(*interval):
		}
	}
}
