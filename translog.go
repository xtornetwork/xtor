package main

// Журнал прозрачности.
//
// Кворум мешает директории умолчать об узле, но не доказывает, что она
// показала всем один и тот же набор. Директория может держать две истории:
// одну для большинства, другую для выбранного клиента. Снаружи это неотличимо.
//
// Журнал делает такое раздвоение обнаружимым. Каждый набор узлов, который
// директория когда-либо отдавала, становится листом дерева Меркла. Директория
// подписывает корень и размер дерева, а по запросу доказывает две вещи:
//
//   - включение: набор, который вы получили, действительно есть в дереве;
//   - согласованность: дерево с прошлого раза только дополнялось, ничего в нём
//     не переписывали.
//
// Клиент помнит последний подписанный корень каждой директории и требует
// согласованности при каждом обращении. Чтобы показать двум клиентам разные
// наборы, директории пришлось бы вести две несводимые истории, а подписанные
// корни от обеих рано или поздно встретятся: их разносят сами директории,
// свидетельствуя друг о друге.
//
// Хеширование как в RFC 6962: лист это SHA-256 от 0x00 и данных, узел — от
// 0x01 и двух детей. Разделение префиксами не даёт выдать лист за узел.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Hash = [32]byte

func leafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func hashToHex(h Hash) string { return hex.EncodeToString(h[:]) }

func hashFromHex(s string) (Hash, error) {
	var out Hash
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(out) {
		return out, fmt.Errorf("негодный хеш %q", s)
	}
	copy(out[:], raw)
	return out, nil
}

// largestPowerOfTwoBelow — наибольшая степень двойки строго меньше n.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// treeHash — корень дерева над списком листьев (MTH из RFC 6962).
func treeHash(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		var out Hash
		copy(out[:], sha256.New().Sum(nil))
		return out
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoBelow(len(leaves))
	return nodeHash(treeHash(leaves[:k]), treeHash(leaves[k:]))
}

// inclusionPath — путь доказательства включения листа index в дерево из leaves.
func inclusionPath(index int, leaves []Hash) []Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(len(leaves))
	if index < k {
		return append(inclusionPath(index, leaves[:k]), treeHash(leaves[k:]))
	}
	return append(inclusionPath(index-k, leaves[k:]), treeHash(leaves[:k]))
}

// consistencyPath — доказательство того, что дерево из first листьев является
// началом дерева из всех leaves.
func consistencyPath(first int, leaves []Hash) []Hash {
	return subProof(first, leaves, true)
}

func subProof(m int, leaves []Hash, complete bool) []Hash {
	n := len(leaves)
	if m == n {
		if complete {
			return nil
		}
		return []Hash{treeHash(leaves)}
	}
	k := largestPowerOfTwoBelow(n)
	if m <= k {
		return append(subProof(m, leaves[:k], complete), treeHash(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), treeHash(leaves[:k]))
}

// VerifyInclusion проверяет, что лист стоит в дереве под индексом index.
func VerifyInclusion(leaf Hash, index, size int, proof []Hash, root Hash) bool {
	if index < 0 || size <= 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// VerifyConsistency проверяет, что дерево размера first не переписывали:
// оно целиком является началом дерева размера second.
func VerifyConsistency(first, second int, proof []Hash, firstRoot, secondRoot Hash) bool {
	if first < 0 || second < first {
		return false
	}
	if first == 0 {
		return true // до первого наблюдения доказывать нечего
	}
	if first == second {
		return len(proof) == 0 && firstRoot == secondRoot
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	if len(proof) == 0 {
		return false
	}
	var fr, sr Hash
	if fn != 0 {
		fr, sr = proof[0], proof[0]
		proof = proof[1:]
	} else {
		fr, sr = firstRoot, firstRoot
	}
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(p, fr)
			sr = nodeHash(p, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == firstRoot && sr == secondRoot
}

// ── подписанный корень ───────────────────────────────────────────────────

// TreeHead — размер дерева и его корень на момент подписи.
type TreeHead struct {
	Size int    `json:"size"`
	Root string `json:"root"`
	Time int64  `json:"time"`
}

// SignedTreeHead — корень, подписанный директорией.
type SignedTreeHead struct {
	Head   TreeHead `json:"head"`
	Sig    string   `json:"sig"`
	PubKey string   `json:"pubkey"`
}

func signTreeHead(head TreeHead, key ed25519.PrivateKey) (SignedTreeHead, error) {
	raw, err := canonicalMarshal(head)
	if err != nil {
		return SignedTreeHead{}, err
	}
	return SignedTreeHead{
		Head:   head,
		Sig:    base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)),
		PubKey: pubKeyString(key),
	}, nil
}

// Verify проверяет подпись корня ключом директории.
func (s SignedTreeHead) Verify(pinnedKey string) error {
	if pinnedKey == "" {
		return fmt.Errorf("ключ директории не задан")
	}
	if normalizeDirKey(pinnedKey) != s.PubKey {
		return fmt.Errorf("корень подписан чужим ключом")
	}
	pub, err := base64.StdEncoding.DecodeString(s.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ключ директории повреждён")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return fmt.Errorf("подпись корня повреждена")
	}
	raw, err := canonicalMarshal(s.Head)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return fmt.Errorf("подпись корня неверна")
	}
	if s.Head.Size < 0 {
		return fmt.Errorf("негодный размер дерева")
	}
	if _, err := hashFromHex(s.Head.Root); err != nil {
		return err
	}
	return nil
}

// ── журнал директории ────────────────────────────────────────────────────

// TransparencyLog — append-only журнал наборов, которые директория отдавала.
type TransparencyLog struct {
	path string
	key  ed25519.PrivateKey

	mu     sync.Mutex
	leaves []Hash
	index  map[Hash]int
}

func NewTransparencyLog(path string, key ed25519.PrivateKey) *TransparencyLog {
	l := &TransparencyLog{path: path, key: key, index: map[Hash]int{}}
	l.load()
	return l
}

func (l *TransparencyLog) load() {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	var hexes []string
	if err := json.Unmarshal(data, &hexes); err != nil {
		return
	}
	for _, s := range hexes {
		h, err := hashFromHex(s)
		if err != nil {
			continue
		}
		if _, seen := l.index[h]; !seen {
			l.index[h] = len(l.leaves)
		}
		l.leaves = append(l.leaves, h)
	}
}

func (l *TransparencyLog) save() error {
	hexes := make([]string, len(l.leaves))
	for i, h := range l.leaves {
		hexes[i] = hashToHex(h)
	}
	return writeJSONAtomic(l.path, hexes, 0o600)
}

// Append добавляет набор в журнал и возвращает индекс листа.
//
// Повторный набор не дублируется: директория отдаёт один и тот же список
// многократно, а значение имеет только то, какие наборы вообще существовали.
func (l *TransparencyLog) Append(data []byte) (Hash, int) {
	h := leafHash(data)
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, ok := l.index[h]; ok {
		return h, i
	}
	l.index[h] = len(l.leaves)
	l.leaves = append(l.leaves, h)
	_ = l.save()
	return h, len(l.leaves) - 1
}

func (l *TransparencyLog) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.leaves)
}

// Head подписывает текущий корень.
func (l *TransparencyLog) Head() (SignedTreeHead, error) {
	l.mu.Lock()
	root := treeHash(l.leaves)
	size := len(l.leaves)
	l.mu.Unlock()
	return signTreeHead(TreeHead{Size: size, Root: hashToHex(root), Time: time.Now().Unix()}, l.key)
}

// InclusionProof доказывает, что лист стоит в дереве текущего размера.
func (l *TransparencyLog) InclusionProof(index int) ([]Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.leaves) {
		return nil, fmt.Errorf("листа %d нет в журнале", index)
	}
	return inclusionPath(index, l.leaves), nil
}

// ConsistencyProof доказывает, что дерево размера first не переписывали.
func (l *TransparencyLog) ConsistencyProof(first int) ([]Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if first < 0 || first > len(l.leaves) {
		return nil, fmt.Errorf("размер %d больше журнала (%d)", first, len(l.leaves))
	}
	if first == 0 {
		return nil, nil
	}
	return consistencyPath(first, l.leaves), nil
}

// ── представление доказательств в JSON ───────────────────────────────────

func hashesToHex(hs []Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hashToHex(h)
	}
	return out
}

func hashesFromHex(ss []string) ([]Hash, error) {
	out := make([]Hash, len(ss))
	for i, s := range ss {
		h, err := hashFromHex(s)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// LogProof — то, что директория прикладывает к консенсусу.
type LogProof struct {
	Leaf  string         `json:"leaf"`
	Index int            `json:"index"`
	Proof []string       `json:"proof"`
	STH   SignedTreeHead `json:"sth"`
}

// consensusLeaf — то, что попадает в журнал: сам набор узлов без отметок
// времени. Иначе журнал рос бы от каждого обновления времени, а важно только
// то, какие наборы директория вообще отдавала.
func consensusLeaf(bridges bool, nodes []Node) ([]byte, error) {
	if nodes == nil {
		nodes = []Node{}
	}
	return canonicalMarshal(map[string]any{"bridges": bridges, "nodes": nodes})
}

// RootAt возвращает корень дерева заданного размера.
func (l *TransparencyLog) RootAt(size int) (Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size < 0 || size > len(l.leaves) {
		return Hash{}, fmt.Errorf("размер %d больше журнала (%d)", size, len(l.leaves))
	}
	return treeHash(l.leaves[:size]), nil
}

// ConsistencyProofBetween доказывает, что дерево размера first является
// началом дерева размера second.
func (l *TransparencyLog) ConsistencyProofBetween(first, second int) ([]Hash, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if first < 0 || second < first || second > len(l.leaves) {
		return nil, fmt.Errorf("негодная пара размеров %d и %d при длине %d",
			first, second, len(l.leaves))
	}
	if first == 0 || first == second {
		return nil, nil
	}
	return consistencyPath(first, l.leaves[:second]), nil
}

// ── свидетельствование ───────────────────────────────────────────────────

// Witness собирает подписанные корни других директорий.
//
// Директория, ведущая две истории, рано или поздно попадётся: её корни,
// показанные разным собеседникам, встретятся здесь, и свести их одним
// доказательством согласованности она не сможет.
type Witness struct {
	peers    []string
	interval time.Duration
	http     *http.Client
	logf     func(string, ...any)

	mu   sync.Mutex
	seen map[string]SignedTreeHead // по открытому ключу директории
	stop chan struct{}
}

func NewWitness(peers []string, interval time.Duration, logf func(string, ...any)) *Witness {
	return &Witness{
		peers: peers, interval: interval, logf: logf,
		http: &http.Client{Timeout: 15 * time.Second},
		seen: map[string]SignedTreeHead{}, stop: make(chan struct{}),
	}
}

func (w *Witness) Seen() map[string]SignedTreeHead {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]SignedTreeHead, len(w.seen))
	for k, v := range w.seen {
		out[k] = v
	}
	return out
}

// Observe запоминает корень, если он подписан и новее прежнего.
func (w *Witness) Observe(sth SignedTreeHead) {
	if err := sth.Verify(sth.PubKey); err != nil {
		return // корень без верной подписи не свидетельство
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if cur, ok := w.seen[sth.PubKey]; ok && cur.Head.Size >= sth.Head.Size {
		return
	}
	w.seen[sth.PubKey] = sth
}

func (w *Witness) Stop() { close(w.stop) }

func (w *Witness) Run() {
	for {
		for _, url := range w.peers {
			sth, err := fetchSTH(w.http, url)
			if err != nil {
				w.logf("корень директории %s не получен: %v", url, err)
				continue
			}
			w.Observe(sth)
		}
		select {
		case <-w.stop:
			return
		case <-time.After(w.interval):
		}
	}
}

func fetchSTH(client *http.Client, url string) (SignedTreeHead, error) {
	resp, err := client.Get(strings.TrimRight(url, "/") + "/sth")
	if err != nil {
		return SignedTreeHead{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SignedTreeHead{}, fmt.Errorf("код %d", resp.StatusCode)
	}
	var sth SignedTreeHead
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sth); err != nil {
		return SignedTreeHead{}, err
	}
	if err := sth.Verify(sth.PubKey); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}
