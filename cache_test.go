package main

import (
	"crypto/ed25519"
	"net/http/httptest"
	"testing"
	"time"
)

// mkExpiringNode выпускает дескриптор с коротким сроком годности.
func mkExpiringNode(nick, ip string, roles []string, lifetime time.Duration) Node {
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
	signed, err := SignDescriptor(n, priv, lifetime)
	if err != nil {
		panic(err)
	}
	testKeys[signed.ID] = priv
	return signed
}

func cacheApp(t *testing.T, srv *httptest.Server, key ed25519.PrivateKey) *clientApp {
	t.Helper()
	set, err := NewDirectorySet([]DirectoryRef{{URL: srv.URL, Key: pubKeyString(key)}}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &clientApp{st: &State{}, dirs: set}
}

func TestNodePoolCachesVerifiedSet(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"exit"})
	srv := fakeDirectory(t, key, []Node{a, b}, nil, "")
	defer srv.Close()

	app := cacheApp(t, srv, key)
	public, _, stale, err := app.nodePool()
	if err != nil {
		t.Fatal(err)
	}
	if stale {
		t.Error("свежий набор помечен как кеш")
	}
	if len(public) != 2 {
		t.Fatalf("узлов %d", len(public))
	}
	if app.st.Cached == nil || len(app.st.Cached.Nodes) != 2 {
		t.Fatal("проверенный набор не попал в кеш")
	}
	if app.st.Cached.SavedAt == 0 {
		t.Error("не записано время сохранения кеша")
	}
}

// Директории недоступны: клиент обязан подняться на последнем проверенном
// наборе, а не останавливаться целиком.
func TestNodePoolFallsBackToCache(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	b := mkNode("b", "2.2.0.1", []string{"exit"})
	srv := fakeDirectory(t, key, []Node{a, b}, nil, "")

	app := cacheApp(t, srv, key)
	if _, _, _, err := app.nodePool(); err != nil {
		t.Fatal(err)
	}
	savedAt := app.st.Cached.SavedAt
	srv.Close() // директория пропала

	public, _, stale, err := app.nodePool()
	if err != nil {
		t.Fatalf("клиент не поднялся на кеше: %v", err)
	}
	if !stale {
		t.Error("работа на кеше не помечена")
	}
	if len(public) != 2 {
		t.Fatalf("из кеша поднялось %d узлов", len(public))
	}
	// возраст кеша не должен обновляться от самого факта его использования,
	// иначе он выглядел бы свежим вечно
	if app.st.Cached.SavedAt != savedAt {
		t.Error("время сохранения кеша переписано при работе на нём")
	}
}

// Просроченные дескрипторы в кеше использовать нельзя: кеш обязан протухать
// сам, без отдельного срока.
func TestNodePoolRefusesExpiredCache(t *testing.T) {
	key := detKey(1)
	short := mkExpiringNode("short", "1.1.0.1", []string{"guard"}, time.Second)
	srv := fakeDirectory(t, key, []Node{short}, nil, "")

	app := cacheApp(t, srv, key)
	if _, _, _, err := app.nodePool(); err != nil {
		t.Fatal(err)
	}
	srv.Close()

	// отметки времени в дескрипторе секундные, поэтому ждём с запасом
	time.Sleep(2500 * time.Millisecond)
	if _, _, _, err := app.nodePool(); err == nil {
		t.Fatal("клиент поднялся на просроченном кеше")
	}
}

// Часть кеша протухла, часть жива: работаем на живой части.
func TestNodePoolDropsExpiredFromCache(t *testing.T) {
	key := detKey(1)
	fresh := mkNode("fresh", "1.1.0.1", []string{"guard"})
	short := mkExpiringNode("short", "2.2.0.1", []string{"exit"}, time.Second)
	srv := fakeDirectory(t, key, []Node{fresh, short}, nil, "")

	app := cacheApp(t, srv, key)
	if _, _, _, err := app.nodePool(); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	time.Sleep(2500 * time.Millisecond)

	public, _, stale, err := app.nodePool()
	if err != nil {
		t.Fatalf("живая часть кеша отвергнута: %v", err)
	}
	if !stale || len(public) != 1 || public[0].Nick != "fresh" {
		t.Fatalf("из кеша поднялось %+v", public)
	}
}

// Вернувшиеся директории важнее кеша.
func TestNodePoolPrefersLiveOverCache(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srv := fakeDirectory(t, key, []Node{a}, nil, "")
	defer srv.Close()

	app := cacheApp(t, srv, key)
	if _, _, _, err := app.nodePool(); err != nil {
		t.Fatal(err)
	}
	// подкладываем в кеш узел, которого у директории нет
	ghost := mkNode("ghost", "9.9.0.1", []string{"exit"})
	app.st.Cached.Nodes = append(app.st.Cached.Nodes, ghost)

	public, _, stale, err := app.nodePool()
	if err != nil {
		t.Fatal(err)
	}
	if stale {
		t.Error("живой ответ помечен как кеш")
	}
	for _, n := range public {
		if n.Nick == "ghost" {
			t.Fatal("узел из кеша подмешался к живому ответу")
		}
	}
	if len(app.st.Cached.Nodes) != 1 {
		t.Fatal("кеш не перезаписан свежим набором")
	}
}

// Без кеша поведение прежнее: отказ с исходной причиной.
func TestNodePoolWithoutCacheReturnsError(t *testing.T) {
	key := detKey(1)
	srv := fakeDirectory(t, key, []Node{mkNode("a", "1.1.0.1", []string{"guard"})}, nil, "")
	app := cacheApp(t, srv, key)
	srv.Close()

	if _, _, _, err := app.nodePool(); err == nil {
		t.Fatal("без кеша недоступность директорий должна быть ошибкой")
	}
}

// Кеш обязан переживать перезапуск клиента вместе с остальным состоянием.
func TestCacheSurvivesRestart(t *testing.T) {
	key := detKey(1)
	a := mkNode("a", "1.1.0.1", []string{"guard"})
	srv := fakeDirectory(t, key, []Node{a}, nil, "")

	path := t.TempDir() + "/state.json"
	set, err := NewDirectorySet([]DirectoryRef{{URL: srv.URL, Key: pubKeyString(key)}}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := &clientApp{st: LoadState(path), dirs: set}
	if _, _, _, err := app.nodePool(); err != nil {
		t.Fatal(err)
	}
	if err := app.st.Save(); err != nil {
		t.Fatal(err)
	}
	srv.Close()

	set2, err := NewDirectorySet([]DirectoryRef{{URL: srv.URL, Key: pubKeyString(key)}}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &clientApp{st: LoadState(path), dirs: set2}
	public, _, stale, err := restarted.nodePool()
	if err != nil {
		t.Fatalf("после перезапуска кеш не поднялся: %v", err)
	}
	if !stale || len(public) != 1 {
		t.Fatalf("после перезапуска из кеша поднялось %d узлов", len(public))
	}
}
