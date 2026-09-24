package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// logDirectory поднимает настоящую директорию с журналом прозрачности.
func logDirectory(t *testing.T, key ed25519.PrivateKey, nodes []Node) (*httptest.Server,
	*dirServer, *TransparencyLog) {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "n.json"), time.Hour, 0, 0, false, func(string, ...any) {})
	for _, n := range nodes {
		if _, err := store.Register(n, n.IP, ""); err != nil {
			t.Fatalf("узел %s не зарегистрирован: %v", n.Short(), err)
		}
	}
	tlog := NewTransparencyLog(filepath.Join(dir, "log.json"), key)
	srv := &dirServer{
		store: store, consensus: NewConsensus(store, key, 0).WithLog(tlog),
		log: tlog, sharedToken: "t", logf: func(string, ...any) {},
	}
	return httptest.NewServer(srv), srv, tlog
}

func setFor(t *testing.T, srv *httptest.Server, key ed25519.PrivateKey) *DirectorySet {
	t.Helper()
	set, err := NewDirectorySet([]DirectoryRef{{URL: srv.URL, Key: pubKeyString(key)}}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestClientVerifiesLogProof(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srv, _, tlog := logDirectory(t, key, []Node{a})
	defer srv.Close()

	set := setFor(t, srv, key)
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatalf("консенсус с доказательством отвергнут: %v", err)
	}
	if len(res.Nodes) != 1 {
		t.Fatalf("узлов %d", len(res.Nodes))
	}
	heads := set.Heads()
	h, ok := heads[srv.URL]
	if !ok || h.Head.Size != tlog.Size() || h.Head.Size == 0 {
		t.Fatalf("корень журнала не запомнен: %+v", heads)
	}
	// повторный опрос обязан пройти проверку согласованности
	if _, err := set.Fetch(quietLog); err != nil {
		t.Fatalf("повторный опрос отвергнут: %v", err)
	}
}

// Набор узлов в журнале обязан совпадать с тем, что отдали клиенту.
func TestClientRejectsProofForOtherNodes(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"middle"})
	srv, _, _ := logDirectory(t, key, []Node{a})
	defer srv.Close()

	// директория отдаёт лишний узел, не кладя его в журнал
	honest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/consensus" {
			http.Redirect(w, r, srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
			return
		}
		resp, err := http.Get(srv.URL + "/consensus")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]json.RawMessage
		json.NewDecoder(resp.Body).Decode(&doc)
		var body consensusBody
		json.Unmarshal(doc["consensus"], &body)
		body.Nodes = append(body.Nodes, b) // подмена состава без правки журнала
		patched, _ := json.Marshal(body)
		doc["consensus"] = patched
		out, _ := json.Marshal(doc)
		w.Write(out)
	}))
	defer honest.Close()

	set := setFor(t, honest, key)
	if _, err := set.Fetch(quietLog); err == nil {
		t.Fatal("подмена состава мимо журнала не замечена")
	}
}

func TestClientRequiresLog(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	// директория без журнала
	srv := fakeDirectoryNoLog(t, key, []Node{a}, nil, "")
	defer srv.Close()

	set := setFor(t, srv, key)
	if _, err := set.Fetch(quietLog); err == nil {
		t.Fatal("директория без журнала принята по умолчанию")
	}
	set = setFor(t, srv, key)
	set.AllowNoLog = true
	if _, err := set.Fetch(quietLog); err != nil {
		t.Fatalf("с разрешением работать без журнала должно проходить: %v", err)
	}
}

// Пропажа журнала у директории, которая его вела, — повод отказаться.
func TestClientNoticesLogDisappearing(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	withLog, _, _ := logDirectory(t, key, []Node{a})
	defer withLog.Close()
	noLog := fakeDirectoryNoLog(t, key, []Node{a}, nil, "")
	defer noLog.Close()

	set := setFor(t, withLog, key)
	if _, err := set.Fetch(quietLog); err != nil {
		t.Fatal(err)
	}
	heads := set.Heads()

	// та же директория (тот же ключ), но журнала больше нет
	moved, err := NewDirectorySet([]DirectoryRef{{URL: noLog.URL, Key: pubKeyString(key)}}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	moved.AllowNoLog = true
	moved.WithHeads(map[string]SignedTreeHead{noLog.URL: heads[withLog.URL]})
	if _, err := moved.Fetch(quietLog); err == nil {
		t.Fatal("исчезновение журнала не замечено")
	}
}

// Переписанная история обязана всплыть на проверке согласованности.
func TestClientDetectsRewrittenHistory(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srv, ds, _ := logDirectory(t, key, []Node{a})
	defer srv.Close()

	set := setFor(t, srv, key)
	if _, err := set.Fetch(quietLog); err != nil {
		t.Fatal(err)
	}
	heads := set.Heads()

	// директория подменяет журнал другой историей того же размера
	forked := NewTransparencyLog(filepath.Join(t.TempDir(), "forked.json"), key)
	forked.Append([]byte("совсем другой набор"))
	ds.log = forked
	ds.consensus = NewConsensus(ds.store, key, 0).WithLog(forked)

	again := setFor(t, srv, key)
	again.WithHeads(heads)
	if _, err := again.Fetch(quietLog); err == nil {
		t.Fatal("подмена истории журнала не замечена")
	}
}

// Директория, показавшая двум собеседникам разные истории, обязана попасться
// при сверке с чужим свидетельством.
func TestClientDetectsEquivocationViaWitness(t *testing.T) {
	keyA, keyB := detKey(1), detKey(2)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srvA, _, _ := logDirectory(t, keyA, []Node{a})
	defer srvA.Close()
	srvB, dsB, _ := logDirectory(t, keyB, []Node{a})
	defer srvB.Close()

	// вторая история той же директории A, увиденная директорией B
	other := NewTransparencyLog(filepath.Join(t.TempDir(), "other.json"), keyA)
	for i := 0; i < 4; i++ {
		other.Append([]byte{byte('a' + i)})
	}
	otherHead, err := other.Head()
	if err != nil {
		t.Fatal(err)
	}
	w := NewWitness(nil, time.Minute, quietLog)
	w.Observe(otherHead)
	dsB.witness = w

	set, err := NewDirectorySet([]DirectoryRef{
		{URL: srvA.URL, Key: pubKeyString(keyA)},
		{URL: srvB.URL, Key: pubKeyString(keyB)},
	}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := set.Fetch(quietLog)
	if err != nil {
		t.Fatalf("опрос не должен падать целиком: %v", err)
	}
	// B честна и отвечает, поэтому кворум единицы собран; но данные A
	// обязаны быть отброшены
	if res.Answered != 1 {
		t.Fatalf("ответивших директорий %d, ожидали 1: данные раздвоившейся не считаются",
			res.Answered)
	}
}

// Свидетельство о согласованной истории не должно мешать работе.
func TestWitnessOfSameHistoryIsFine(t *testing.T) {
	keyA, keyB := detKey(1), detKey(2)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srvA, _, tlogA := logDirectory(t, keyA, []Node{a})
	defer srvA.Close()
	srvB, dsB, _ := logDirectory(t, keyB, []Node{a})
	defer srvB.Close()

	// прогреваем журнал A и снимаем корень меньшего размера
	if _, err := setFor(t, srvA, keyA).Fetch(quietLog); err != nil {
		t.Fatal(err)
	}
	early, err := tlogA.Head()
	if err != nil {
		t.Fatal(err)
	}
	tlogA.Append([]byte("ещё один набор"))

	w := NewWitness(nil, time.Minute, quietLog)
	w.Observe(early)
	dsB.witness = w

	set, err := NewDirectorySet([]DirectoryRef{
		{URL: srvA.URL, Key: pubKeyString(keyA)},
		{URL: srvB.URL, Key: pubKeyString(keyB)},
	}, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Fetch(quietLog); err != nil {
		t.Fatalf("честная история отвергнута из-за свидетельства: %v", err)
	}
}

func TestWitnessStoresOnlySignedHeads(t *testing.T) {
	w := NewWitness(nil, time.Minute, quietLog)
	good, err := NewTransparencyLog(filepath.Join(t.TempDir(), "l.json"), detKey(1)).Head()
	if err != nil {
		t.Fatal(err)
	}
	w.Observe(good)
	forged := good
	forged.Head.Size = 999 // подпись больше не сходится
	w.Observe(forged)

	seen := w.Seen()
	if len(seen) != 1 {
		t.Fatalf("свидетельств %d, ожидали 1", len(seen))
	}
	if seen[good.PubKey].Head.Size != good.Head.Size {
		t.Fatal("свидетель принял корень с испорченной подписью")
	}
}
