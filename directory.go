package main

// Директория — аналог directory authority в Tor: узлы регистрируются и шлют
// heartbeat, клиенты забирают подписанный список. Здесь же клиентская сторона
// этого протокола.
//
//	POST /register   регистрация / heartbeat узла (Authorization: Bearer <токен>)
//	GET  /consensus  подписанный Ed25519 список публичных узлов
//	GET  /bridges    подписанный список непубличных входных узлов
//	GET  /health
//
// Узел попадает в консенсус, только если прислал heartbeat не позже --stale
// назад И директория смогла открыть TCP-соединение на его ip:port.

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── протокол ─────────────────────────────────────────────────────────────

type signedDoc struct {
	Consensus json.RawMessage `json:"consensus"`
	Signature string          `json:"signature"`
	PubKey    string          `json:"pubkey"`
	// доказательство, что этот набор узлов лежит в журнале директории
	Log *LogProof `json:"log,omitempty"`
}

type consensusBody struct {
	Version    int    `json:"version"`
	Generated  int64  `json:"generated"`
	ValidUntil int64  `json:"valid_until"`
	Bridges    bool   `json:"bridges"`
	Nodes      []Node `json:"nodes"`
}

// normalizeDirKey приводит ключ к той записи, в которой он идёт по проводу.
// Стандартный base64 содержит символы «/» и «+», неудобные в командной строке,
// поэтому URL-безопасная запись того же ключа тоже принимается.
func normalizeDirKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil &&
		len(raw) == ed25519.PublicKeySize {
		return s
	}
	for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding,
		base64.RawStdEncoding} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
			return base64.StdEncoding.EncodeToString(raw)
		}
	}
	return s
}

// VerifyDoc проверяет подпись документа директории и возвращает его тело.
func VerifyDoc(raw []byte, pinnedKey string) (*consensusBody, error) {
	var doc signedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ответ директории не разобран: %w", err)
	}
	pinnedKey = normalizeDirKey(pinnedKey)
	if pinnedKey != doc.PubKey {
		return nil, fmt.Errorf("ключ директории не совпадает: ожидался %s, получен %s",
			pinnedKey, doc.PubKey)
	}
	key, err := base64.StdEncoding.DecodeString(doc.PubKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ключ директории повреждён")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return nil, fmt.Errorf("подпись повреждена")
	}
	msg, err := canonicalJSON(doc.Consensus)
	if err != nil {
		return nil, fmt.Errorf("консенсус не канонизирован: %w", err)
	}
	if !ed25519.Verify(key, msg, sig) {
		return nil, fmt.Errorf("подпись консенсуса неверна")
	}
	var body consensusBody
	if err := json.Unmarshal(doc.Consensus, &body); err != nil {
		return nil, fmt.Errorf("тело консенсуса не разобрано: %w", err)
	}
	if body.ValidUntil < time.Now().Unix()-60 {
		return nil, fmt.Errorf("консенсус просрочен")
	}
	return &body, nil
}

// ── клиентская сторона ───────────────────────────────────────────────────

// DirectoryClient забирает консенсус и мосты.
type DirectoryClient struct {
	URL         string
	ReadToken   string
	BridgeToken string
	HTTP        *http.Client
}

func (d *DirectoryClient) get(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: код %d", url, resp.StatusCode)
	}
	return body, nil
}

// PubKeyOf возвращает ключ, которым подписан ответ (для режима TOFU).
func (d *DirectoryClient) PubKeyOf() (string, error) {
	raw, err := d.get(strings.TrimRight(d.URL, "/")+"/consensus", d.ReadToken)
	if err != nil {
		return "", err
	}
	var doc signedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	return doc.PubKey, nil
}

// Fetch возвращает публичные узлы и мосты.
func (d *DirectoryClient) Fetch(key string, logf func(string, ...any)) ([]Node, []Node, error) {
	public, bridges, _, err := d.FetchWithProof(key)
	if err != nil {
		return nil, nil, err
	}
	_ = logf
	return public, bridges, nil
}

// FetchWithProof возвращает узлы, мосты и доказательство того, что отданный
// набор лежит в журнале прозрачности директории.
func (d *DirectoryClient) FetchWithProof(key string) ([]Node, []Node, *LogProof, error) {
	raw, err := d.get(strings.TrimRight(d.URL, "/")+"/consensus", d.ReadToken)
	if err != nil {
		return nil, nil, nil, err
	}
	body, err := VerifyDoc(raw, key)
	if err != nil {
		return nil, nil, nil, err
	}
	var doc signedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, err
	}

	var bridges []Node
	if d.BridgeToken != "" {
		braw, err := d.get(strings.TrimRight(d.URL, "/")+"/bridges", d.BridgeToken)
		if err == nil {
			if bbody, err := VerifyDoc(braw, key); err == nil {
				bridges = bbody.Nodes
			}
		}
	}
	for i := range bridges {
		bridges[i].Bridge = true
	}
	return body.Nodes, bridges, doc.Log, nil
}

// RegisterResult — ответ директории на регистрацию.
type RegisterResult struct {
	IP        string // адрес, который директория видит на самом деле
	Reachable bool
	Mismatch  bool // адрес в дескрипторе не совпал: нужно переподписать
}

// ConsistencyProof просит директорию доказать, что журнал только дополнялся.
func (d *DirectoryClient) ConsistencyProof(first, second int) ([]Hash, Hash, error) {
	url := fmt.Sprintf("%s/log/consistency?first=%d&second=%d",
		strings.TrimRight(d.URL, "/"), first, second)
	raw, err := d.get(url, d.ReadToken)
	if err != nil {
		return nil, Hash{}, err
	}
	var out struct {
		Root  string   `json:"root"`
		Proof []string `json:"proof"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, Hash{}, err
	}
	root, err := hashFromHex(out.Root)
	if err != nil {
		return nil, Hash{}, err
	}
	proof, err := hashesFromHex(out.Proof)
	if err != nil {
		return nil, Hash{}, err
	}
	return proof, root, nil
}

// Witnessed забирает корни других директорий, которые видела эта.
func (d *DirectoryClient) Witnessed() (map[string]SignedTreeHead, error) {
	raw, err := d.get(strings.TrimRight(d.URL, "/")+"/witness", d.ReadToken)
	if err != nil {
		return nil, err
	}
	var out map[string]SignedTreeHead
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Register отправляет подписанный дескриптор узла.
func (d *DirectoryClient) Register(desc Node, token string) (RegisterResult, error) {
	body, err := json.Marshal(desc)
	if err != nil {
		return RegisterResult{}, err
	}
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(d.URL, "/")+"/register", strings.NewReader(string(body)))
	if err != nil {
		return RegisterResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return RegisterResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		IP         string `json:"ip"`
		ObservedIP string `json:"observed_ip"`
		Reachable  bool   `json:"reachable"`
		Error      string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode == http.StatusConflict && out.ObservedIP != "" {
		return RegisterResult{IP: out.ObservedIP, Mismatch: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		msg := out.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return RegisterResult{}, fmt.Errorf("регистрация отклонена (%d): %s", resp.StatusCode, msg)
	}
	return RegisterResult{IP: out.IP, Reachable: out.Reachable}, nil
}

// ── ключ директории ──────────────────────────────────────────────────────

func loadOrCreateDirKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(raw) != ed25519.SeedSize {
			return nil, fmt.Errorf("ключ %s повреждён", path)
		}
		return ed25519.NewKeyFromSeed(raw), nil
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	enc := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func pubKeyString(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// ── хранилище узлов ──────────────────────────────────────────────────────

type storedNode struct {
	Node
	Seen      int64 `json:"seen"`
	Reachable bool  `json:"reachable"`
	Probed    int64 `json:"probed"`
}

// addressMismatch сообщает узлу адрес, который директория видит на самом деле:
// адрес входит в подписанный дескриптор, и узел должен переподписать его сам.
type addressMismatch struct{ observed string }

func (e addressMismatch) Error() string {
	return "адрес в дескрипторе не совпадает с наблюдаемым " + e.observed
}

type Store struct {
	path      string
	stale     time.Duration
	maxNodes  int
	maxPerIP  int
	probe     bool
	mu        sync.Mutex
	version   uint64
	nodes     map[string]*storedNode
	logf      func(string, ...any)
}

func NewStore(path string, stale time.Duration, maxNodes, maxPerIP int, probe bool,
	logf func(string, ...any)) *Store {
	s := &Store{
		path: path, stale: stale, maxNodes: maxNodes, maxPerIP: maxPerIP,
		probe: probe, nodes: map[string]*storedNode{}, logf: logf,
	}
	s.load()
	return s
}

// load читает состояние с диска, отбрасывая повреждённые записи.
func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var raw map[string]*storedNode
	if err := json.Unmarshal(data, &raw); err != nil {
		s.logf("состояние %s нечитаемо (%v), начинаю с пустого", s.path, err)
		return
	}
	for id, entry := range raw {
		if entry == nil {
			continue
		}
		if err := entry.Node.Validate(); err != nil || entry.Seen == 0 {
			// просроченный дескриптор не беда: узел пришлёт свежий
			s.logf("узел %q в состоянии негоден, пропускаю", id)
			continue
		}
		s.nodes[entry.ID] = entry
	}
}

func (s *Store) save() {
	if err := writeJSONAtomic(s.path, s.nodes, 0o600); err != nil {
		s.logf("состояние не сохранено: %v", err)
	}
}

// Register принимает подписанный дескриптор узла.
//
// Директория ничего в нём не меняет: он подписан личностью узла, и любая
// правка сломала бы подпись. Отсюда и главное свойство — подменить ключ
// Reality директория не может, у неё остаётся лишь право умолчать об узле.
func (s *Store) Register(desc Node, observedIP string, boundID string) (*storedNode, error) {
	if err := VerifyDescriptor(desc, time.Now()); err != nil {
		return nil, err
	}
	if err := ValidateDescriptor(desc); err != nil {
		return nil, err
	}
	if net.ParseIP(observedIP) == nil {
		return nil, fmt.Errorf("негодный адрес %q", observedIP)
	}
	if desc.IP != observedIP {
		return nil, addressMismatch{observed: observedIP}
	}
	if boundID != "" && desc.ID != boundID {
		return nil, errForbidden("токен закреплён за другой личностью")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.nodes[desc.ID]
	// ip:port уникален: нельзя занять чужую точку входа
	for _, other := range s.nodes {
		if other.ID == desc.ID {
			continue
		}
		if other.IP == desc.IP && other.Port == desc.Port {
			return nil, errForbidden(fmt.Sprintf("%s:%d уже занят узлом %s",
				desc.IP, desc.Port, other.Short()))
		}
	}
	if old == nil {
		if s.maxNodes > 0 && len(s.nodes) >= s.maxNodes {
			return nil, errForbidden("достигнут предел числа узлов")
		}
		if s.maxPerIP > 0 {
			same := 0
			for _, n := range s.nodes {
				if n.IP == desc.IP {
					same++
				}
			}
			if same >= s.maxPerIP {
				return nil, errForbidden("достигнут предел числа узлов с адреса " + desc.IP)
			}
		}
	}

	entry := &storedNode{Node: desc, Seen: time.Now().Unix()}
	changed := true
	if old != nil {
		moved := old.IP != desc.IP || old.Port != desc.Port
		if !moved {
			entry.Reachable = old.Reachable
			entry.Probed = old.Probed
		}
		// подпись покрывает весь дескриптор: она же и признак изменения
		changed = moved || old.Sig != desc.Sig
	}
	s.nodes[desc.ID] = entry
	if changed {
		s.version++
	}
	s.save()
	return entry, nil
}

// Alive возвращает живые узлы: private=false — публичные, true — мосты.
func (s *Store) Alive(private bool) []Node {
	cutoff := time.Now().Add(-s.stale).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		if n.Seen < cutoff {
			continue
		}
		if s.probe && !n.Reachable {
			continue
		}
		if n.Private != private {
			continue
		}
		if VerifyDescriptor(n.Node, time.Now()) != nil {
			continue // просроченный дескриптор клиентам не отдаём
		}
		out = append(out, n.Node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

func (s *Store) probeTargets() []storedNode {
	cutoff := time.Now().Add(-s.stale).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		if n.Seen >= cutoff {
			out = append(out, *n)
		}
	}
	return out
}

func (s *Store) applyProbe(results map[string]bool) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ok := range results {
		n := s.nodes[id]
		if n == nil {
			continue
		}
		if n.Reachable != ok {
			s.version++
			if ok {
				s.logf("узел %s отвечает на %s:%d, включаю в консенсус", n.Short(), n.IP, n.Port)
			} else {
				s.logf("узел %s не отвечает на %s:%d, исключаю", n.Short(), n.IP, n.Port)
			}
		}
		n.Reachable = ok
		n.Probed = now
	}
	s.save()
}

func (s *Store) counts() map[string]int {
	cutoff := time.Now().Add(-s.stale).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	c := map[string]int{"known": len(s.nodes)}
	for _, n := range s.nodes {
		if n.Seen < cutoff {
			continue
		}
		c["fresh"]++
		if !s.probe || n.Reachable {
			c["reachable"]++
			if n.Private {
				c["bridges"]++
			} else {
				c["public"]++
			}
		}
	}
	return c
}

type forbiddenError string

func (e forbiddenError) Error() string   { return string(e) }
func errForbidden(msg string) error      { return forbiddenError(msg) }
func isForbidden(err error) bool         { _, ok := err.(forbiddenError); return ok }

// ── проверка достижимости ────────────────────────────────────────────────

// Prober периодически убеждается, что узлы действительно слушают свой порт:
// heartbeat на слово не принимается, иначе узел, не поднявший приём, отравлял
// бы каждую цепочку со своим участием.
type Prober struct {
	store    *Store
	interval time.Duration
	timeout  time.Duration
	wake     chan struct{}
	stop     chan struct{}
}

func NewProber(store *Store, interval, timeout time.Duration) *Prober {
	return &Prober{store: store, interval: interval, timeout: timeout,
		wake: make(chan struct{}, 1), stop: make(chan struct{})}
}

func (p *Prober) Kick() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *Prober) Stop() { close(p.stop) }

func (p *Prober) Run() {
	for {
		targets := p.store.probeTargets()
		if len(targets) > 0 {
			results := make(map[string]bool, len(targets))
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 16)
			for _, t := range targets {
				wg.Add(1)
				go func(t storedNode) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					ok := tcpProbe(t.IP, t.Port, p.timeout)
					mu.Lock()
					results[t.ID] = ok
					mu.Unlock()
				}(t)
			}
			wg.Wait()
			p.store.applyProbe(results)
		}
		select {
		case <-p.stop:
			return
		case <-p.wake:
		case <-time.After(p.interval):
		}
	}
}

func tcpProbe(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ── подписанный консенсус ────────────────────────────────────────────────

// Consensus кэширует подписанный документ: подпись не пересчитывается на
// каждый запрос, а только при изменении состава или истечении кэша.
type Consensus struct {
	store *Store
	key   ed25519.PrivateKey
	ttl   time.Duration
	log   *TransparencyLog

	mu    sync.Mutex
	cache map[bool]consensusCacheEntry
}

type consensusCacheEntry struct {
	body    []byte
	at      time.Time
	version uint64
}

func NewConsensus(store *Store, key ed25519.PrivateKey, ttl time.Duration) *Consensus {
	return &Consensus{store: store, key: key, ttl: ttl,
		cache: map[bool]consensusCacheEntry{}}
}

// WithLog подключает журнал прозрачности: каждый отданный набор узлов
// становится листом дерева, и директория доказывает его включение.
func (c *Consensus) WithLog(log *TransparencyLog) *Consensus {
	c.log = log
	return c
}

func (c *Consensus) Document(private bool) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	version := c.store.Version()
	if hit, ok := c.cache[private]; ok && hit.version == version && now.Sub(hit.at) < c.ttl {
		return hit.body
	}
	ts := now.Unix()
	body := consensusBody{
		Version: 1, Generated: ts,
		ValidUntil: ts + int64(c.store.stale.Seconds()),
		Bridges:    private,
		Nodes:      c.store.Alive(private),
	}
	if body.Nodes == nil {
		body.Nodes = []Node{}
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":"не удалось собрать консенсус"}`)
	}
	msg, err := canonicalJSON(rawBody)
	if err != nil {
		return []byte(`{"error":"не удалось канонизировать консенсус"}`)
	}
	doc := signedDoc{
		Consensus: rawBody,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(c.key, msg)),
		PubKey:    pubKeyString(c.key),
	}
	if c.log != nil {
		if p, err := c.logProof(private, body.Nodes); err == nil {
			doc.Log = p
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return []byte(`{"error":"не удалось подписать консенсус"}`)
	}
	c.cache[private] = consensusCacheEntry{body: out, at: now, version: version}
	return out
}

// ── токены ───────────────────────────────────────────────────────────────

// tokenEntry — выданный токен. ID пуст, пока токеном не воспользовались:
// первая успешная регистрация закрепляет токен за личностью узла, и другой
// узел этим же токеном уже не зарегистрируется.
type tokenEntry struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// logProof кладёт набор узлов в журнал и собирает доказательство включения.
func (c *Consensus) logProof(private bool, nodes []Node) (*LogProof, error) {
	leafData, err := consensusLeaf(private, nodes)
	if err != nil {
		return nil, err
	}
	leaf, index := c.log.Append(leafData)
	sth, err := c.log.Head()
	if err != nil {
		return nil, err
	}
	proof, err := c.log.InclusionProof(index)
	if err != nil {
		return nil, err
	}
	return &LogProof{
		Leaf: hashToHex(leaf), Index: index,
		Proof: hashesToHex(proof), STH: sth,
	}, nil
}

func loadTokens(path string) map[string]tokenEntry {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]tokenEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// bindToken закрепляет токен за личностью при первом использовании.
func bindToken(path, token, id string) error {
	tokens := loadTokens(path)
	if tokens == nil {
		return fmt.Errorf("файл токенов недоступен")
	}
	entry, ok := tokens[token]
	if !ok {
		return fmt.Errorf("токен не найден")
	}
	if entry.ID == id {
		return nil
	}
	entry.ID = id
	tokens[token] = entry
	return writeJSONAtomic(path, tokens, 0o600)
}

// MintToken выпускает индивидуальный токен и печатает его. Метка нужна только
// оператору: закрепление происходит по личности узла при первом использовании.
func MintToken(path, label string) error {
	if !nickRE.MatchString(label) {
		return fmt.Errorf("недопустимая метка")
	}
	tokens := loadTokens(path)
	if tokens == nil {
		tokens = map[string]tokenEntry{}
	}
	for tok, e := range tokens {
		if e.Label == label && e.ID == "" {
			fmt.Println(tok) // неиспользованный токен с той же меткой уже есть
			return nil
		}
	}
	tok, err := randomHex(16)
	if err != nil {
		return err
	}
	tokens[tok] = tokenEntry{Label: label}
	if err := writeJSONAtomic(path, tokens, 0o600); err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func tokenMatch(presented, expected string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// ── HTTP ─────────────────────────────────────────────────────────────────

type dirServer struct {
	store       *Store
	consensus   *Consensus
	log         *TransparencyLog
	witness     *Witness
	sharedToken string
	tokensPath  string
	readToken   string
	bridgeToken string
	trustIP     bool
	behindProxy bool
	prober      *Prober
	logf        func(string, ...any)
}

func (s *dirServer) bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *dirServer) clientIP(r *http.Request) string {
	if s.behindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (s *dirServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.counts())
	case r.URL.Path == "/consensus" && r.Method == http.MethodGet:
		if s.readToken != "" && !tokenMatch(s.bearer(r), s.readToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "нет доступа"})
			return
		}
		s.raw(w, s.consensus.Document(false))
	case r.URL.Path == "/bridges" && r.Method == http.MethodGet:
		if s.bridgeToken == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "не найдено"})
			return
		}
		if !tokenMatch(s.bearer(r), s.bridgeToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "нет доступа"})
			return
		}
		s.raw(w, s.consensus.Document(true))
	case r.URL.Path == "/sth" && r.Method == http.MethodGet:
		s.treeHead(w)
	case r.URL.Path == "/log/consistency" && r.Method == http.MethodGet:
		s.consistency(w, r)
	case r.URL.Path == "/witness" && r.Method == http.MethodGet:
		s.witnessed(w)
	case r.URL.Path == "/register" && r.Method == http.MethodPost:
		s.register(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "не найдено"})
	}
}

func (s *dirServer) raw(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *dirServer) treeHead(w http.ResponseWriter) {
	if s.log == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "журнал выключен"})
		return
	}
	sth, err := s.log.Head()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sth)
}

// consistency доказывает, что журнал только дополнялся между двумя размерами.
func (s *dirServer) consistency(w http.ResponseWriter, r *http.Request) {
	if s.log == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "журнал выключен"})
		return
	}
	first, err := strconv.Atoi(r.URL.Query().Get("first"))
	if err != nil || first < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "негодный first"})
		return
	}
	second := s.log.Size()
	if v := r.URL.Query().Get("second"); v != "" {
		if second, err = strconv.Atoi(v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "негодный second"})
			return
		}
	}
	proof, err := s.log.ConsistencyProofBetween(first, second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	root, err := s.log.RootAt(second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"first": first, "second": second,
		"root": hashToHex(root), "proof": hashesToHex(proof),
	})
}

// witnessed отдаёт корни других директорий, которые эта директория видела.
// Так подписанные корни расходятся по сети, и раздвоение журнала всплывает.
func (s *dirServer) witnessed(w http.ResponseWriter) {
	if s.witness == nil {
		writeJSON(w, http.StatusOK, map[string]SignedTreeHead{})
		return
	}
	writeJSON(w, http.StatusOK, s.witness.Seen())
}

func (s *dirServer) register(w http.ResponseWriter, r *http.Request) {
	presented := s.bearer(r)
	boundID, usedToken := "", ""
	if !tokenMatch(presented, s.sharedToken) {
		found := false
		for tok, entry := range loadTokens(s.tokensPath) {
			if tokenMatch(presented, tok) {
				boundID, usedToken, found = entry.ID, tok, true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "нет доступа"})
			return
		}
	}

	var desc Node
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&desc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "тело не разобрано"})
		return
	}
	ip := s.clientIP(r)
	if s.trustIP && desc.IP != "" {
		ip = desc.IP
	}
	saved, err := s.store.Register(desc, ip, boundID)
	if err != nil {
		if mism, ok := err.(addressMismatch); ok {
			// узел ещё не знает своего внешнего адреса: сообщаем его,
			// чтобы узел переподписал дескриптор
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": mism.Error(), "observed_ip": mism.observed,
			})
			return
		}
		code := http.StatusBadRequest
		if isForbidden(err) {
			code = http.StatusForbidden
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	if usedToken != "" && boundID == "" {
		if err := bindToken(s.tokensPath, usedToken, saved.ID); err != nil {
			s.logf("токен не закреплён за узлом %s: %v", saved.Short(), err)
		} else {
			s.logf("токен закреплён за личностью %s", saved.Short())
		}
	}
	if s.prober != nil && !saved.Reachable {
		s.prober.Kick()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "ip": saved.IP, "seen": saved.Seen, "reachable": saved.Reachable,
	})
}

// ── запуск ───────────────────────────────────────────────────────────────

func runDirectory(args []string) error {
	fs := flag.NewFlagSet("directory", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1", "адрес прослушивания")
	port := fs.Int("port", 8500, "порт")
	token := fs.String("token", "", "общий токен регистрации (слабее индивидуальных)")
	tokensFile := fs.String("tokens-file", "", "JSON {токен: имя узла} — индивидуальные токены")
	readToken := fs.String("read-token", "", "токен чтения консенсуса (пусто = открытая сеть)")
	bridgeToken := fs.String("bridge-token", "", "токен выдачи мостов (пусто = не выдавать)")
	keyPath := fs.String("key", "dir.key", "файл приватного ключа Ed25519 (создаётся)")
	state := fs.String("state", "nodes.json", "файл состояния")
	stale := fs.Duration("stale", 20*time.Minute, "без heartbeat дольше — узел выбывает")
	cache := fs.Duration("cache", 10*time.Second, "кэш подписанного консенсуса")
	maxNodes := fs.Int("max-nodes", 500, "предел числа узлов (0 = без предела)")
	maxPerIP := fs.Int("max-per-ip", 4, "предел числа узлов с одного адреса (0 = без предела)")
	probeInterval := fs.Duration("probe-interval", time.Minute, "период проверки достижимости")
	probeTimeout := fs.Duration("probe-timeout", 5*time.Second, "таймаут проверки")
	noProbe := fs.Bool("no-probe", false, "не проверять порты узлов (узлы за NAT)")
	trustIP := fs.Bool("trust-ip", false, "верить адресу из дескриптора (только для стенда)")
	behindProxy := fs.Bool("behind-proxy", false, "адрес узла из X-Forwarded-For")
	logPath := fs.String("log-file", "",
		"файл журнала прозрачности (пусто — рядом с состоянием)")
	noLog := fs.Bool("no-log", false, "выключить журнал прозрачности")
	witnessPeers := fs.String("witness", "",
		"адреса других директорий через запятую: следить за их корнями и отдавать увиденное")
	witnessEvery := fs.Duration("witness-interval", 10*time.Minute,
		"период опроса корней других директорий")
	_ = fs.Parse(args)

	if *token == "" && *tokensFile == "" {
		return fmt.Errorf("нужен -token или -tokens-file")
	}
	if *trustIP {
		logf("ВНИМАНИЕ: -trust-ip позволяет узлу назвать любой адрес, только для стенда")
	}

	key, err := loadOrCreateDirKey(*keyPath)
	if err != nil {
		return err
	}
	store := NewStore(*state, *stale, *maxNodes, *maxPerIP, !*noProbe, logf)

	var tlog *TransparencyLog
	if !*noLog {
		path := *logPath
		if path == "" {
			path = strings.TrimSuffix(*state, filepath.Ext(*state)) + "-log.json"
		}
		tlog = NewTransparencyLog(path, key)
		logf("журнал прозрачности: %s, листьев %d", path, tlog.Size())
	}
	var witness *Witness
	if peers := splitList(*witnessPeers); len(peers) > 0 {
		witness = NewWitness(peers, *witnessEvery, logf)
		go witness.Run()
		defer witness.Stop()
		logf("свидетельствую о корнях: %s", strings.Join(peers, ", "))
	}

	var prober *Prober
	if !*noProbe {
		prober = NewProber(store, *probeInterval, *probeTimeout)
		go prober.Run()
		defer prober.Stop()
	}

	consensus := NewConsensus(store, key, *cache)
	if tlog != nil {
		consensus = consensus.WithLog(tlog)
	}
	srv := &dirServer{
		store: store, consensus: consensus, log: tlog, witness: witness,
		sharedToken: *token, tokensPath: *tokensFile, readToken: *readToken,
		bridgeToken: *bridgeToken, trustIP: *trustIP, behindProxy: *behindProxy,
		prober: prober, logf: logf,
	}

	addr := net.JoinHostPort(*listen, fmt.Sprint(*port))
	logf("публичный ключ директории: %s", pubKeyString(key))
	probeNote := fmt.Sprintf("проверка портов каждые %s", *probeInterval)
	if *noProbe {
		probeNote = "проверка портов выключена"
	}
	logf("директория слушает %s, узел выбывает после %s без heartbeat, %s",
		addr, *stale, probeNote)

	httpSrv := &http.Server{Addr: addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-waitForSignal()
		logf("останавливаюсь")
		_ = httpSrv.Close()
	}()
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
