package main

// Кворум директорий.
//
// Подпись дескриптора отняла у директории возможность подменить ключ узла, но
// оставила две: умолчать об узле и показать разным клиентам разные наборы.
// Закрывается это не доверием к одной директории, а опросом нескольких.
//
// Директории независимы и между собой не переговариваются: каждая сама
// проверяет узлы и публикует то, что видит. Клиент опрашивает все и берёт
// узел, о котором сказали не меньше Quorum из них. Чтобы умолчать об узле,
// теперь нужен сговор Quorum директорий.
//
// Дескрипторы разных директорий про один узел могут отличаться: узел
// переподписывает их по сроку. Побеждает самый свежий, а голоса считаются по
// личности узла.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DirectoryRef — одна директория и всё, что нужно для работы с ней.
type DirectoryRef struct {
	URL         string `json:"url"`
	Key         string `json:"key,omitempty"`          // публичный ключ; пусто — доверие при первом обращении
	Token       string `json:"token,omitempty"`        // токен регистрации, нужен узлу
	ReadToken   string `json:"read_token,omitempty"`   // токен чтения консенсуса
	BridgeToken string `json:"bridge_token,omitempty"` // токен выдачи мостов
}

// DirectorySet — набор директорий и требуемое число голосов.
type DirectorySet struct {
	Refs   []DirectoryRef
	Quorum int
	HTTP   *http.Client

	// необязательный файл со списком мостов: их выдают адресно, и директория
	// может быть вовсе недоступна
	BridgeFile string

	// AllowNoLog разрешает работать с директорией без журнала прозрачности.
	// По умолчанию журнал обязателен: без него раздвоение не заметить.
	AllowNoLog bool

	mu    sync.Mutex
	keys  map[string]string         // выученные ключи, если они не были заданы
	heads map[string]SignedTreeHead // последний проверенный корень журнала
}

// NewDirectorySet готовит набор. quorum <= 0 означает большинство.
func NewDirectorySet(refs []DirectoryRef, quorum int, known map[string]string) (*DirectorySet, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("не задано ни одной директории")
	}
	seen := map[string]bool{}
	for i, r := range refs {
		url := strings.TrimRight(strings.TrimSpace(r.URL), "/")
		if url == "" {
			return nil, fmt.Errorf("пустой адрес директории")
		}
		if seen[url] {
			return nil, fmt.Errorf("директория %s указана дважды", url)
		}
		seen[url] = true
		refs[i].URL = url
	}
	if quorum <= 0 {
		quorum = len(refs)/2 + 1 // большинство
	}
	if quorum > len(refs) {
		return nil, fmt.Errorf("кворум %d больше числа директорий (%d)", quorum, len(refs))
	}
	s := &DirectorySet{Refs: refs, Quorum: quorum,
		keys: map[string]string{}, heads: map[string]SignedTreeHead{}}
	for url, key := range known {
		s.keys[url] = key
	}
	return s, nil
}

// WithHeads подставляет корни журналов, запомненные в прошлый раз.
func (s *DirectorySet) WithHeads(heads map[string]SignedTreeHead) *DirectorySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	for url, h := range heads {
		s.heads[url] = h
	}
	return s
}

// Heads отдаёт проверенные корни для сохранения в состоянии клиента.
func (s *DirectorySet) Heads() map[string]SignedTreeHead {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]SignedTreeHead, len(s.heads))
	for k, v := range s.heads {
		out[k] = v
	}
	return out
}

func (s *DirectorySet) head(url string) SignedTreeHead {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heads[url]
}

func (s *DirectorySet) setHead(url string, h SignedTreeHead) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heads[url] = h
}

// Key возвращает ключ директории: заданный явно, выученный ранее или пустой.
func (s *DirectorySet) Key(ref DirectoryRef) string {
	if ref.Key != "" {
		return ref.Key
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[ref.URL]
}

func (s *DirectorySet) learnKey(url, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[url] = key
}

// Keys отдаёт выученные ключи для сохранения в состоянии клиента.
func (s *DirectorySet) Keys() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.keys))
	for k, v := range s.keys {
		out[k] = v
	}
	return out
}

func (s *DirectorySet) client(ref DirectoryRef) *DirectoryClient {
	return &DirectoryClient{
		URL: ref.URL, ReadToken: ref.ReadToken, BridgeToken: ref.BridgeToken, HTTP: s.HTTP,
	}
}

// dirReport — что ответила одна директория.
type dirReport struct {
	ref     DirectoryRef
	public  []Node
	bridges []Node
	sth     SignedTreeHead
	witness map[string]SignedTreeHead
	err     error
}

// QuorumResult — итог опроса.
type QuorumResult struct {
	Nodes    []Node // узлы, набравшие кворум
	Bridges  []Node // мосты: объединение, кворум к ним не применяется
	Answered int    // сколько директорий ответило
	Rejected int    // сколько узлов не набрали голосов
}

// Fetch опрашивает все директории и сводит ответы.
func (s *DirectorySet) Fetch(logf func(string, ...any)) (*QuorumResult, error) {
	reports := make([]dirReport, len(s.Refs))
	var wg sync.WaitGroup
	for i, ref := range s.Refs {
		wg.Add(1)
		go func(i int, ref DirectoryRef) {
			defer wg.Done()
			reports[i] = s.fetchOne(ref, logf)
		}(i, ref)
	}
	wg.Wait()

	// сверяем корни, которые директории видели друг у друга: та, что ведёт
	// две истории, не сведёт их одним доказательством
	s.crossCheck(reports, logf)

	answered := 0
	for _, r := range reports {
		if r.err != nil {
			logf("директория %s недоступна: %v", r.ref.URL, r.err)
			continue
		}
		answered++
		logf("директория %s: узлов %d, мостов %d, журнал: %d листьев",
			r.ref.URL, len(r.public), len(r.bridges), r.sth.Head.Size)
	}
	if answered < s.Quorum {
		return nil, fmt.Errorf("ответили %d директорий из %d, кворум %d не собран",
			answered, len(s.Refs), s.Quorum)
	}

	// голоса считаем по личности: дескрипторы разных директорий про один узел
	// могут отличаться версией, но личность у него одна
	votes := map[string]int{}
	newest := map[string]Node{}
	for _, r := range reports {
		if r.err != nil {
			continue
		}
		counted := map[string]bool{}
		for _, n := range r.public {
			if err := n.Validate(); err != nil {
				logf("директория %s отдала негодный узел: %v", r.ref.URL, err)
				continue
			}
			if !counted[n.ID] {
				counted[n.ID] = true
				votes[n.ID]++
			}
			if cur, ok := newest[n.ID]; !ok || n.Published > cur.Published {
				newest[n.ID] = n
			}
		}
	}

	res := &QuorumResult{Answered: answered}
	for id, n := range newest {
		if votes[id] >= s.Quorum {
			res.Nodes = append(res.Nodes, n)
			continue
		}
		res.Rejected++
		// узел, о котором знает меньшинство, — повод присмотреться:
		// так выглядит и отставшая директория, и попытка подсунуть свой узел
		logf("узел %s не набрал кворум: голосов %d из %d", n.Short(), votes[id], s.Quorum)
	}
	sort.Slice(res.Nodes, func(i, j int) bool { return res.Nodes[i].ID < res.Nodes[j].ID })

	// мосты раздаются адресно и по определению известны не всем директориям,
	// поэтому здесь объединение, а не кворум; подпись узла проверяется всё равно
	seenBridge := map[string]Node{}
	if s.BridgeFile != "" {
		fromFile, err := loadBridgeFile(s.BridgeFile)
		if err != nil {
			logf("мосты из файла не прочитаны: %v", err)
		} else {
			logf("мостов из файла: %d", len(fromFile))
			reports = append(reports, dirReport{
				ref: DirectoryRef{URL: s.BridgeFile}, bridges: fromFile})
		}
	}
	for _, r := range reports {
		for _, n := range r.bridges {
			if err := n.Validate(); err != nil {
				logf("директория %s отдала негодный мост: %v", r.ref.URL, err)
				continue
			}
			if cur, ok := seenBridge[n.ID]; !ok || n.Published > cur.Published {
				n.Bridge = true
				seenBridge[n.ID] = n
			}
		}
	}
	for _, n := range seenBridge {
		res.Bridges = append(res.Bridges, n)
	}
	sort.Slice(res.Bridges, func(i, j int) bool { return res.Bridges[i].ID < res.Bridges[j].ID })
	return res, nil
}

func (s *DirectorySet) fetchOne(ref DirectoryRef, logf func(string, ...any)) dirReport {
	c := s.client(ref)
	key := s.Key(ref)
	if key == "" {
		got, err := c.PubKeyOf()
		if err != nil {
			return dirReport{ref: ref, err: err}
		}
		logf("ВНИМАНИЕ: ключ директории %s не задан, принимаю при первом обращении: %s",
			ref.URL, got)
		s.learnKey(ref.URL, got)
		key = got
	}
	public, bridges, proof, err := c.FetchWithProof(key)
	if err != nil {
		return dirReport{ref: ref, err: err}
	}
	sth, err := s.checkLog(c, ref, key, false, public, proof, logf)
	if err != nil {
		return dirReport{ref: ref, err: err}
	}
	witness, err := c.Witnessed()
	if err != nil {
		witness = nil // свидетельства необязательны
	}
	return dirReport{ref: ref, public: public, bridges: bridges, sth: sth, witness: witness}
}

// checkLog проверяет, что полученный набор лежит в журнале директории и что
// журнал с прошлого раза только дополнялся.
func (s *DirectorySet) checkLog(c *DirectoryClient, ref DirectoryRef, key string,
	bridges bool, nodes []Node, proof *LogProof,
	logf func(string, ...any)) (SignedTreeHead, error) {
	prev := s.head(ref.URL)
	if proof == nil {
		if prev.Head.Size > 0 {
			return SignedTreeHead{}, fmt.Errorf(
				"журнал пропал: раньше директория его вела (было %d листьев)", prev.Head.Size)
		}
		if !s.AllowNoLog {
			return SignedTreeHead{}, fmt.Errorf(
				"директория не ведёт журнал прозрачности; чтобы работать без него, нужен -allow-no-log")
		}
		logf("ВНИМАНИЕ: директория %s работает без журнала прозрачности", ref.URL)
		return SignedTreeHead{}, nil
	}
	if err := proof.STH.Verify(key); err != nil {
		return SignedTreeHead{}, fmt.Errorf("корень журнала: %w", err)
	}
	leafData, err := consensusLeaf(bridges, nodes)
	if err != nil {
		return SignedTreeHead{}, err
	}
	want := leafHash(leafData)
	got, err := hashFromHex(proof.Leaf)
	if err != nil {
		return SignedTreeHead{}, err
	}
	if want != got {
		return SignedTreeHead{}, fmt.Errorf("полученный набор узлов не тот, что положен в журнал")
	}
	root, err := hashFromHex(proof.STH.Head.Root)
	if err != nil {
		return SignedTreeHead{}, err
	}
	path, err := hashesFromHex(proof.Proof)
	if err != nil {
		return SignedTreeHead{}, err
	}
	if !VerifyInclusion(got, proof.Index, proof.STH.Head.Size, path, root) {
		return SignedTreeHead{}, fmt.Errorf("набор узлов не доказан в журнале")
	}

	if prev.Head.Size > 0 {
		if proof.STH.Head.Size < prev.Head.Size {
			return SignedTreeHead{}, fmt.Errorf("журнал усох: было %d листьев, стало %d",
				prev.Head.Size, proof.STH.Head.Size)
		}
		prevRoot, err := hashFromHex(prev.Head.Root)
		if err != nil {
			return SignedTreeHead{}, err
		}
		if proof.STH.Head.Size == prev.Head.Size {
			if prevRoot != root {
				return SignedTreeHead{}, fmt.Errorf(
					"журнал того же размера, но с другим корнем: историю переписали")
			}
		} else {
			cons, _, err := c.ConsistencyProof(prev.Head.Size, proof.STH.Head.Size)
			if err != nil {
				return SignedTreeHead{}, fmt.Errorf(
					"доказательство согласованности не получено: %w", err)
			}
			if !VerifyConsistency(prev.Head.Size, proof.STH.Head.Size, cons, prevRoot, root) {
				return SignedTreeHead{}, fmt.Errorf(
					"журнал не согласован с прошлым обращением: историю переписали")
			}
		}
	}
	s.setHead(ref.URL, proof.STH)
	return proof.STH, nil
}

// crossCheck сверяет наш корень с тем, что видели у этой же директории другие.
//
// Директория, показавшая двум собеседникам разные истории, не свяжет два корня
// доказательством согласованности, и это её выдаёт.
func (s *DirectorySet) crossCheck(reports []dirReport, logf func(string, ...any)) {
	var witnessed []SignedTreeHead
	for _, r := range reports {
		for _, w := range r.witness {
			witnessed = append(witnessed, w)
		}
	}
	if len(witnessed) == 0 {
		return
	}
	for i := range reports {
		r := &reports[i]
		if r.err != nil || r.sth.Head.Size == 0 {
			continue
		}
		key := normalizeDirKey(s.Key(r.ref))
		c := s.client(r.ref)
		for _, w := range witnessed {
			if w.PubKey != key {
				continue
			}
			if err := w.Verify(key); err != nil {
				continue
			}
			if err := reconcile(c, r.sth, w); err != nil {
				logf("ТРЕВОГА: директория %s расходится в показаниях: %v", r.ref.URL, err)
				r.err = fmt.Errorf("журнал раздвоен: %w", err)
				break
			}
		}
	}
}

// reconcile требует связать два подписанных корня одной директории.
func reconcile(c *DirectoryClient, ours, theirs SignedTreeHead) error {
	if ours.Head.Size == theirs.Head.Size {
		if ours.Head.Root != theirs.Head.Root {
			return fmt.Errorf("два разных корня одного размера %d", ours.Head.Size)
		}
		return nil
	}
	lo, hi := ours, theirs
	if lo.Head.Size > hi.Head.Size {
		lo, hi = hi, lo
	}
	loRoot, err := hashFromHex(lo.Head.Root)
	if err != nil {
		return err
	}
	hiRoot, err := hashFromHex(hi.Head.Root)
	if err != nil {
		return err
	}
	proof, _, err := c.ConsistencyProof(lo.Head.Size, hi.Head.Size)
	if err != nil {
		return fmt.Errorf("директория не доказала связь корней %d и %d: %w",
			lo.Head.Size, hi.Head.Size, err)
	}
	if !VerifyConsistency(lo.Head.Size, hi.Head.Size, proof, loRoot, hiRoot) {
		return fmt.Errorf("корни размеров %d и %d из разных историй",
			lo.Head.Size, hi.Head.Size)
	}
	return nil
}

// Register рассылает подписанный дескриптор во все директории.
//
// Узлу важно попасть в набор каждой: иначе он не наберёт кворум у клиентов.
// Успехом считается хотя бы одна принявшая директория, остальные подтянутся
// на следующем круге.
func (s *DirectorySet) Register(desc func(ip string) (Node, error), logf func(string, ...any),
	knownIP string) (accepted int, observedIP string) {
	type outcome struct {
		ip  string
		ok  bool
		err error
	}
	results := make([]outcome, len(s.Refs))
	var wg sync.WaitGroup
	for i, ref := range s.Refs {
		wg.Add(1)
		go func(i int, ref DirectoryRef) {
			defer wg.Done()
			c := s.client(ref)
			ip := knownIP
			// адрес входит в подпись: при расхождении директория сообщает
			// наблюдаемый адрес, и дескриптор переподписывается
			for attempt := 0; attempt < 2; attempt++ {
				d, err := desc(ip)
				if err != nil {
					results[i] = outcome{err: err}
					return
				}
				res, err := c.Register(d, ref.Token)
				if err != nil {
					results[i] = outcome{err: err}
					return
				}
				if res.Mismatch {
					ip = res.IP
					continue
				}
				results[i] = outcome{ip: res.IP, ok: true}
				return
			}
			results[i] = outcome{err: fmt.Errorf("адрес не согласован")}
		}(i, ref)
	}
	wg.Wait()

	seen := map[string]int{}
	for i, r := range results {
		if r.err != nil {
			logf("директория %s не приняла регистрацию: %v", s.Refs[i].URL, r.err)
			continue
		}
		accepted++
		seen[r.ip]++
	}
	best := 0
	for ip, n := range seen {
		if n > best {
			best, observedIP = n, ip
		}
	}
	return accepted, observedIP
}

// Describe коротко описывает набор для лога.
func (s *DirectorySet) Describe() string {
	urls := make([]string, 0, len(s.Refs))
	for _, r := range s.Refs {
		urls = append(urls, r.URL)
	}
	return fmt.Sprintf("%d директорий (кворум %d): %s",
		len(s.Refs), s.Quorum, strings.Join(urls, ", "))
}

// defaultHTTPClient — общий таймаут на опрос директории.
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func loadBridgeFile(path string) ([]Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Node
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// buildDirectoryRefs разбирает списки через запятую.
//
// Ключ и токены можно задать одним значением на все директории или по одному
// на каждую, в том же порядке.
func buildDirectoryRefs(urls, keys, tokens, readTokens, bridgeTokens string) ([]DirectoryRef, error) {
	list := splitList(urls)
	if len(list) == 0 {
		return nil, fmt.Errorf("не задано ни одной директории")
	}
	pick := func(name, raw string) ([]string, error) {
		vals := splitList(raw)
		switch {
		case len(vals) == 0:
			return make([]string, len(list)), nil
		case len(vals) == 1:
			out := make([]string, len(list))
			for i := range out {
				out[i] = vals[0]
			}
			return out, nil
		case len(vals) == len(list):
			return vals, nil
		}
		return nil, fmt.Errorf("%s: задано %d значений на %d директорий",
			name, len(vals), len(list))
	}
	k, err := pick("-dir-key", keys)
	if err != nil {
		return nil, err
	}
	t, err := pick("-token", tokens)
	if err != nil {
		return nil, err
	}
	rt, err := pick("-read-token", readTokens)
	if err != nil {
		return nil, err
	}
	bt, err := pick("-bridge-token", bridgeTokens)
	if err != nil {
		return nil, err
	}
	refs := make([]DirectoryRef, len(list))
	for i, u := range list {
		refs[i] = DirectoryRef{URL: u, Key: normalizeDirKey(k[i]), Token: t[i],
			ReadToken: rt[i], BridgeToken: bt[i]}
	}
	return refs, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
