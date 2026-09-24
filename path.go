package main

// Общая часть: дескриптор узла, его проверка, выбор пути, канонический JSON
// и состояние клиента между запусками.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node — дескриптор узла: то, что узел подписывает и сообщает о себе
// директории, и то, что директория отдаёт клиентам без изменений.
type Node struct {
	// личность: имя выведено из ключа, дескриптор подписан этим ключом
	ID    string `json:"id"`
	IDKey string `json:"idkey"`
	Nick  string `json:"nick"` // произвольная метка, ничего не удостоверяет

	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	UUIDVision  string   `json:"uuid_vision"`
	UUIDPlain   string   `json:"uuid_plain"`
	PBK         string   `json:"pbk"`
	SID         string   `json:"sid"`
	SNI         string   `json:"sni"`
	Roles       []string `json:"roles"`
	Family      []string `json:"family"` // имена личностей родственных узлов
	BW          int64    `json:"bw"`
	RejectPorts []string `json:"reject_ports"`
	Private     bool     `json:"private,omitempty"`

	Published int64  `json:"published"`
	Expires   int64  `json:"expires"`
	Sig       string `json:"sig,omitempty"`

	Bridge bool `json:"-"` // получен через выдачу мостов, в общем списке его нет
}

// Path — одна цепочка из трёх узлов.
type Path struct {
	Guard  Node
	Middle Node
	Exit   Node
}

func (p Path) Nicks() []string {
	return []string{p.Guard.Short(), p.Middle.Short(), p.Exit.Short()}
}

// SelectOpts — параметры выбора пути.
type SelectOpts struct {
	Guards          int
	GuardDays       int
	GuardRetireDays int
	BWCap           float64
	Circuits        int
	IgnoreNet       bool      // для стенда, где все узлы в одной сети
	ASN             *ASNTable // необязательная таблица автономных систем
}

var (
	nickRE = regexp.MustCompile(`^[A-Za-z0-9_-]{0,32}$`)
	// Reality shortId — hex чётной длины, не длиннее 8 байт: нечётная длина
	// порождает конфиг, который ядро отвергает у всех клиентов сразу
	sidRE  = regexp.MustCompile(`^([0-9a-fA-F]{2}){0,8}$`)
	pbkRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	sniRE  = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	uuidRE = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	portSpecRE = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)
)

// MaxBW — верхняя граница заявленной узлом скорости, 10 ГБ/с.
const MaxBW = 10 * 1024 * 1024 * 1024

// DescriptorLifetime — срок годности подписанного дескриптора.
const DescriptorLifetime = 24 * time.Hour

var knownRoles = map[string]bool{"guard": true, "middle": true, "exit": true}

// NormalizePorts приводит список портов вида ["25", "1-79"] к канону.
func NormalizePorts(spec []string) ([]string, error) {
	if len(spec) > 32 {
		return nil, fmt.Errorf("слишком много портов в политике выхода")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, item := range spec {
		m := portSpecRE.FindStringSubmatch(strings.TrimSpace(item))
		if m == nil {
			return nil, fmt.Errorf("негодный порт %q", item)
		}
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("негодный диапазон %q", item)
		}
		s := strconv.Itoa(lo)
		if hi != lo {
			s = fmt.Sprintf("%d-%d", lo, hi)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// NormalizeRoles приводит роли к канону.
func NormalizeRoles(roles []string) ([]string, error) {
	if len(roles) == 0 {
		return nil, fmt.Errorf("не заданы роли")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if !knownRoles[r] {
			return nil, fmt.Errorf("неизвестная роль %q", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ValidateDescriptor проверяет содержимое дескриптора, ничего не переписывая.
//
// Переписывать нельзя: дескриптор подписан узлом, и любое приведение к канону
// на стороне директории или клиента сломало бы подпись. Приводит поля к канону
// сам узел, до подписи.
func ValidateDescriptor(n Node) error {
	if !nickRE.MatchString(n.Nick) {
		return fmt.Errorf("негодная метка узла")
	}
	if n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("негодный порт")
	}
	for _, u := range []string{n.UUIDVision, n.UUIDPlain} {
		if !uuidRE.MatchString(u) {
			return fmt.Errorf("негодный UUID (нужен нижний регистр)")
		}
	}
	if n.UUIDVision == n.UUIDPlain {
		return fmt.Errorf("UUID входного и промежуточного хопов должны различаться")
	}
	if !pbkRE.MatchString(n.PBK) {
		return fmt.Errorf("негодный ключ Reality")
	}
	if !sidRE.MatchString(n.SID) || strings.ToLower(n.SID) != n.SID {
		return fmt.Errorf("негодный shortId: нужен hex чётной длины в нижнем регистре")
	}
	if !sniRE.MatchString(n.SNI) {
		return fmt.Errorf("негодный SNI")
	}
	roles, err := NormalizeRoles(n.Roles)
	if err != nil {
		return err
	}
	if strings.Join(roles, ",") != strings.Join(n.Roles, ",") {
		return fmt.Errorf("роли не приведены к канону")
	}
	if n.BW < 0 || n.BW > MaxBW {
		return fmt.Errorf("негодная заявленная скорость")
	}
	ports, err := NormalizePorts(n.RejectPorts)
	if err != nil {
		return err
	}
	if strings.Join(ports, ",") != strings.Join(n.RejectPorts, ",") {
		return fmt.Errorf("политика портов не приведена к канону")
	}
	if len(n.Family) > 64 {
		return fmt.Errorf("слишком большая семья")
	}
	for _, f := range n.Family {
		if !identityRE.MatchString(f) {
			return fmt.Errorf("негодное имя родственника %q", f)
		}
		if f == n.ID {
			return fmt.Errorf("узел не может быть родственником самому себе")
		}
	}
	return nil
}

// Validate проверяет узел из консенсуса целиком: подпись личности, содержимое
// и адрес. Клиент не обязан верить директории на слово.
func (n Node) Validate() error {
	if net.ParseIP(n.IP) == nil {
		return fmt.Errorf("узел %s: некорректный адрес %q", n.Short(), n.IP)
	}
	if err := VerifyDescriptor(n, time.Now()); err != nil {
		return err
	}
	if err := ValidateDescriptor(n); err != nil {
		return fmt.Errorf("узел %s: %w", n.Short(), err)
	}
	return nil
}

// FilterValid отбрасывает узлы, которые нельзя использовать.
func FilterValid(pool []Node, logf func(string, ...any)) []Node {
	out := make([]Node, 0, len(pool))
	for _, n := range pool {
		if err := n.Validate(); err != nil {
			logf("узел отброшен: %v", err)
			continue
		}
		out = append(out, n)
	}
	return out
}

func (p Path) Validate() error {
	for _, n := range []Node{p.Guard, p.Middle, p.Exit} {
		if err := n.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (n Node) HasRole(role string) bool {
	for _, r := range n.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func withRole(pool []Node, role string) []Node {
	out := make([]Node, 0, len(pool))
	for _, n := range pool {
		if n.HasRole(role) {
			out = append(out, n)
		}
	}
	return out
}

// ── родство узлов ────────────────────────────────────────────────────────

func containsID(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

// SameFamily считает узлы родственными, только если они назвали друг друга.
//
// Одностороннего заявления мало: иначе враждебный узел объявил бы роднёй
// половину сети и вытеснил бы честные узлы из цепочек, где участвует сам.
// Взаимность делает такое заявление бесполезным.
func SameFamily(a, b Node) bool {
	if a.ID == "" || b.ID == "" {
		return false
	}
	return containsID(a.Family, b.ID) && containsID(b.Family, a.ID)
}

// netKey — ключ «семьи по сети»: /16 для IPv4, /32 для IPv6.
func netKey(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("некорректный адрес %q", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1]), nil
	}
	return ip.String() + "/128", nil
}

// Compatible сообщает, можно ли поставить n в цепочку рядом с chain.
func Compatible(n Node, chain []Node, opts SelectOpts) bool {
	nk, nkErr := netKey(n.IP)
	for _, b := range chain {
		if n.ID != "" && n.ID == b.ID {
			return false
		}
		if SameFamily(n, b) {
			return false
		}
		if opts.ASN != nil {
			if x, ok1 := opts.ASN.Lookup(n.IP); ok1 {
				if y, ok2 := opts.ASN.Lookup(b.IP); ok2 && x == y {
					return false
				}
			}
		}
		if opts.IgnoreNet {
			continue
		}
		bk, bkErr := netKey(b.IP)
		if nkErr != nil || bkErr != nil || nk == bk {
			return false
		}
	}
	return true
}

// ── таблица автономных систем ────────────────────────────────────────────

// ASNTable — необязательная таблица «адрес → автономная система».
// Читает формат ip2asn-v4.tsv: начало, конец, номер AS, страна, название.
// Разные сети /16 могут принадлежать одному провайдеру, и тогда развязка по
// сетям не спасает; таблица закрывает этот случай.
type ASNTable struct {
	ranges []asnRange
}

type asnRange struct {
	lo, hi uint32
	asn    uint32
}

func LoadASNTable(path string) (*ASNTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := &ASNTable{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		cols := strings.Split(text, "\t")
		if len(cols) < 3 {
			continue
		}
		lo, ok1 := ipv4ToUint(cols[0])
		hi, ok2 := ipv4ToUint(cols[1])
		asn, err := strconv.ParseUint(strings.TrimSpace(cols[2]), 10, 32)
		if !ok1 || !ok2 || err != nil || asn == 0 || lo > hi {
			continue
		}
		t.ranges = append(t.ranges, asnRange{lo: lo, hi: hi, asn: uint32(asn)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.ranges) == 0 {
		return nil, fmt.Errorf("в %s нет пригодных строк", path)
	}
	sort.Slice(t.ranges, func(i, j int) bool { return t.ranges[i].lo < t.ranges[j].lo })
	return t, nil
}

func (t *ASNTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.ranges)
}

// Lookup возвращает номер автономной системы. Для IPv6 таблица не заполняется,
// там остаётся развязка по сети.
func (t *ASNTable) Lookup(ipStr string) (uint32, bool) {
	if t == nil {
		return 0, false
	}
	v, ok := ipv4ToUint(ipStr)
	if !ok {
		return 0, false
	}
	i := sort.Search(len(t.ranges), func(i int) bool { return t.ranges[i].hi >= v })
	if i < len(t.ranges) && t.ranges[i].lo <= v && v <= t.ranges[i].hi {
		return t.ranges[i].asn, true
	}
	return 0, false
}

func ipv4ToUint(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// ── случайность ──────────────────────────────────────────────────────────
// Выбор пути в анонимной сети обязан идти от криптостойкого источника:
// состояние обычного ГПСЧ восстановимо по наблюдаемой выдаче, а выдача здесь
// частично видна операторам узлов.

func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("нет источника случайности: " + err.Error())
	}
	return int(v.Int64())
}

func randFloat() float64 {
	const prec = 1 << 53
	v, err := rand.Int(rand.Reader, big.NewInt(prec))
	if err != nil {
		panic("нет источника случайности: " + err.Error())
	}
	return float64(v.Int64()) / float64(prec)
}

// BWWeights — веса по заявленной пропускной способности.
//
// Скорость узел сообщает о себе сам, поэтому её можно завысить. Вес ограничен
// медианой, умноженной на capFactor, а узлы без измерения получают медиану,
// чтобы новый узел не остался без трафика навсегда.
func BWWeights(nodes []Node, capFactor float64) []float64 {
	known := make([]int64, 0, len(nodes))
	for _, n := range nodes {
		if n.BW > 0 {
			known = append(known, n.BW)
		}
	}
	w := make([]float64, len(nodes))
	if len(known) == 0 {
		for i := range w {
			w[i] = 1
		}
		return w
	}
	sort.Slice(known, func(i, j int) bool { return known[i] < known[j] })
	med := float64(known[len(known)/2])
	capped := med * capFactor
	if capped < 1 {
		capped = 1
	}
	for i, n := range nodes {
		v := float64(n.BW)
		if v <= 0 {
			v = med
		}
		if v > capped {
			v = capped
		}
		w[i] = v
	}
	return w
}

func weightedIndex(weights []float64) int {
	total := 0.0
	for _, x := range weights {
		total += x
	}
	if total <= 0 {
		return randIntn(len(weights))
	}
	target := randFloat() * total
	acc := 0.0
	for i, x := range weights {
		acc += x
		if target < acc {
			return i
		}
	}
	return len(weights) - 1
}

// WeightedPick выбирает узел, совместимый с chain, с учётом весов.
func WeightedPick(pool []Node, chain []Node, opts SelectOpts) (Node, bool) {
	cands := make([]Node, 0, len(pool))
	for _, n := range pool {
		if Compatible(n, chain, opts) {
			cands = append(cands, n)
		}
	}
	if len(cands) == 0 {
		return Node{}, false
	}
	return cands[weightedIndex(BWWeights(cands, opts.BWCap))], true
}

// ChooseGuards закрепляет входные узлы.
//
// Узел, временно выпавший из консенсуса, остаётся закреплённым: иначе
// противник, умеющий ронять guard, перебирал бы клиента на свой узел
// (guard discovery). Закрепление снимается по истечении GuardDays или после
// GuardRetireDays суток непрерывной недоступности.
func ChooseGuards(pool []Node, st *State, opts SelectOpts, logf func(string, ...any)) []Node {
	byID := map[string]Node{}
	for _, n := range pool {
		byID[n.ID] = n
	}
	now := time.Now().Unix()
	maxPinned := opts.Guards * 2
	if maxPinned < opts.Guards+1 {
		maxPinned = opts.Guards + 1
	}

	kept := make([]PinnedGuard, 0, len(st.Guards))
	for _, g := range st.Guards {
		lastSeen := g.LastSeen
		if lastSeen == 0 {
			lastSeen = g.Since
		}
		if n, ok := byID[g.ID]; ok && n.HasRole("guard") {
			lastSeen = now
		}
		if now-g.Since > int64(opts.GuardDays)*86400 {
			logf("guard %s: истёк срок закрепления, снимаю", g.ID[:8])
			continue
		}
		if now-lastSeen > int64(opts.GuardRetireDays)*86400 {
			logf("guard %s: недоступен дольше %d сут., снимаю", g.ID[:8], opts.GuardRetireDays)
			continue
		}
		kept = append(kept, PinnedGuard{ID: g.ID, Since: g.Since, LastSeen: lastSeen})
	}

	pinned := map[string]bool{}
	for _, g := range kept {
		pinned[g.ID] = true
	}
	var active []Node
	var down []string
	for _, g := range kept {
		if n, ok := byID[g.ID]; ok && n.HasRole("guard") {
			active = append(active, n)
		} else {
			down = append(down, g.ID[:8])
		}
	}
	sort.Strings(down)
	if len(down) > 0 {
		logf("закреплённые guard недоступны: %v (остаются закреплёнными)", down)
	}

	candidates := make([]Node, 0, len(pool))
	for _, n := range pool {
		if n.HasRole("guard") && !pinned[n.ID] {
			candidates = append(candidates, n)
		}
	}
	for len(active) < opts.Guards && len(kept) < maxPinned && len(candidates) > 0 {
		i := weightedIndex(BWWeights(candidates, opts.BWCap))
		cand := candidates[i]
		candidates = append(candidates[:i], candidates[i+1:]...)
		if !Compatible(cand, active, opts) {
			continue
		}
		kept = append(kept, PinnedGuard{ID: cand.ID, Since: now, LastSeen: now})
		active = append(active, cand)
		mark := ""
		if cand.Bridge {
			mark = " [мост]"
		}
		logf("новый guard: %s (%s)%s", cand.Short(), cand.IP, mark)
	}
	st.Guards = kept
	return active
}

// BuildCircuits собирает до opts.Circuits различных цепочек.
func BuildCircuits(pool, guards []Node, opts SelectOpts) ([]Path, error) {
	middles := withRole(pool, "middle")
	exits := withRole(pool, "exit")
	if len(guards) == 0 || len(middles) == 0 || len(exits) == 0 {
		return nil, fmt.Errorf("мало узлов: guards=%d middles=%d exits=%d",
			len(guards), len(middles), len(exits))
	}
	seen := map[string]bool{}
	var out []Path
	for tries := 0; tries < 400 && len(out) < opts.Circuits; tries++ {
		g := guards[randIntn(len(guards))]
		m, ok := WeightedPick(middles, []Node{g}, opts)
		if !ok {
			continue
		}
		e, ok := WeightedPick(exits, []Node{g, m}, opts)
		if !ok {
			continue
		}
		key := g.ID + "|" + m.ID + "|" + e.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Path{Guard: g, Middle: m, Exit: e})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не удалось собрать ни одной цепочки из несвязанных узлов")
	}
	return out, nil
}

// PortRejected проверяет, запрещён ли порт политикой выхода ("25", "1-79").
func PortRejected(reject []string, port int) bool {
	for _, spec := range reject {
		lo, hi, ok := parsePortSpec(spec)
		if ok && lo <= port && port <= hi {
			return true
		}
	}
	return false
}

func parsePortSpec(spec string) (lo, hi int, ok bool) {
	m := portSpecRE.FindStringSubmatch(strings.TrimSpace(spec))
	if m == nil {
		return 0, 0, false
	}
	lo, _ = strconv.Atoi(m[1])
	hi = lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	return lo, hi, true
}

// ── канонический JSON ────────────────────────────────────────────────────

// canonicalJSON приводит объект к виду, который подписывают директория и узел:
// ключи по алфавиту, без пробелов, числа в исходной записи. Любая реализация,
// повторяющая эти правила, получит те же байты и ту же подпись.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // иначе 1790069686 превратится в 1.790069686e+09
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func canonicalMarshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

// ── состояние между запусками ────────────────────────────────────────────

// PinnedGuard — закреплённый входной узел, опознаётся по имени личности.
type PinnedGuard struct {
	ID       string `json:"id"`
	Since    int64  `json:"since"`
	LastSeen int64  `json:"last_seen"`
}

// CachedSet — последний набор узлов, прошедший кворум и проверку журналов.
//
// Хранить его безопасно: дескрипторы подписаны самими узлами и несут срок
// годности, поэтому подменить кеш нельзя, а устаревает он сам. Нужен он на
// случай, когда директории недоступны: без него клиент останавливается
// целиком, хотя узлы сети живы.
type CachedSet struct {
	SavedAt int64  `json:"saved_at"`
	Nodes   []Node `json:"nodes"`
	Bridges []Node `json:"bridges"`
}

// State переживает перезапуск клиента.
type State struct {
	// ключи директорий, выученные при первом обращении, по их адресам
	DirKeys map[string]string `json:"dir_keys,omitempty"`
	// последний подписанный корень журнала каждой директории: с ним сверяется
	// согласованность при следующем обращении
	LogHeads map[string]SignedTreeHead `json:"log_heads,omitempty"`
	// последний проверенный набор узлов на случай недоступности директорий
	Cached *CachedSet    `json:"cached,omitempty"`
	Guards []PinnedGuard `json:"guards"`

	path string
}

func LoadState(path string) *State {
	st := &State{path: path}
	if data, err := os.ReadFile(path); err == nil {
		// повреждённое состояние не повод падать: начинаем с чистого
		_ = json.Unmarshal(data, st)
	}
	st.path = path
	if st.DirKeys == nil {
		st.DirKeys = map[string]string{}
	}
	if st.LogHeads == nil {
		st.LogHeads = map[string]SignedTreeHead{}
	}
	// отбрасываем записи без имени личности: они из прежнего формата
	kept := st.Guards[:0]
	for _, g := range st.Guards {
		if identityRE.MatchString(g.ID) {
			kept = append(kept, g)
		}
	}
	st.Guards = kept
	return st
}

func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	return writeJSONAtomic(s.path, s, 0o600)
}

func writeJSONAtomic(path string, v any, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
