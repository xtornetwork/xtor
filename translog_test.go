package main

import (
	"fmt"
	"testing"
)

func testLeaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = leafHash([]byte(fmt.Sprintf("лист %d", i)))
	}
	return out
}

// Доказательство включения обязано сходиться для любого листа любого дерева.
func TestInclusionProofsHoldForAllSizes(t *testing.T) {
	for size := 1; size <= 64; size++ {
		leaves := testLeaves(size)
		root := treeHash(leaves)
		for i := 0; i < size; i++ {
			proof := inclusionPath(i, leaves)
			if !VerifyInclusion(leaves[i], i, size, proof, root) {
				t.Fatalf("включение не сошлось: лист %d из %d", i, size)
			}
			// чужой лист под тем же доказательством проходить не должен
			if VerifyInclusion(leafHash([]byte("подмена")), i, size, proof, root) {
				t.Fatalf("подменённый лист принят: индекс %d, размер %d", i, size)
			}
			// как и правильный лист под чужим индексом
			if i+1 < size && VerifyInclusion(leaves[i], i+1, size, proof, root) {
				t.Fatalf("лист принят под чужим индексом: %d из %d", i, size)
			}
		}
	}
}

// Доказательство согласованности обязано сходиться для любой пары размеров.
func TestConsistencyProofsHoldForAllSizes(t *testing.T) {
	for second := 1; second <= 48; second++ {
		leaves := testLeaves(second)
		secondRoot := treeHash(leaves)
		for first := 1; first <= second; first++ {
			firstRoot := treeHash(leaves[:first])
			proof := consistencyPath(first, leaves)
			if !VerifyConsistency(first, second, proof, firstRoot, secondRoot) {
				t.Fatalf("согласованность не сошлась: %d → %d", first, second)
			}
		}
	}
}

// Переписанная история обязана быть замечена: это и есть раздвоение журнала.
func TestRewrittenHistoryIsCaught(t *testing.T) {
	honest := testLeaves(8)
	forked := append([]Hash{}, honest...)
	forked[3] = leafHash([]byte("другой набор узлов"))

	oldRoot := treeHash(honest[:4]) // что клиент видел раньше
	newRoot := treeHash(forked)     // что директория показывает теперь
	proof := consistencyPath(4, forked)

	if VerifyConsistency(4, len(forked), proof, oldRoot, newRoot) {
		t.Fatal("подмена прошлого листа не замечена")
	}
	// а честное продолжение той же истории проходит
	if !VerifyConsistency(4, len(honest), consistencyPath(4, honest),
		oldRoot, treeHash(honest)) {
		t.Fatal("честное дополнение журнала отвергнуто")
	}
}

// Усечение журнала тоже подмена: дерево обязано только расти.
func TestTruncatedLogIsCaught(t *testing.T) {
	leaves := testLeaves(10)
	bigRoot := treeHash(leaves)
	smallRoot := treeHash(leaves[:6])
	// директория пытается выдать меньшее дерево за продолжение большего
	if VerifyConsistency(10, 6, consistencyPath(6, leaves), bigRoot, smallRoot) {
		t.Fatal("усечение журнала не замечено")
	}
}

func TestEmptyProofRejected(t *testing.T) {
	leaves := testLeaves(4)
	if VerifyConsistency(2, 4, nil, treeHash(leaves[:2]), treeHash(leaves)) {
		t.Fatal("пустое доказательство согласованности принято")
	}
	if VerifyInclusion(leaves[0], 0, 4, nil, treeHash(leaves)) {
		t.Fatal("пустое доказательство включения принято")
	}
	// до первого наблюдения доказывать нечего
	if !VerifyConsistency(0, 4, nil, Hash{}, treeHash(leaves)) {
		t.Fatal("первое обращение не должно требовать доказательства")
	}
}

func TestLogAppendAndProve(t *testing.T) {
	key := detKey(1)
	log := NewTransparencyLog(t.TempDir()+"/log.json", key)

	var leaves []Hash
	for i := 0; i < 12; i++ {
		data := []byte(fmt.Sprintf("набор %d", i))
		h, idx := log.Append(data)
		if idx != i {
			t.Fatalf("индекс %d, ожидали %d", idx, i)
		}
		leaves = append(leaves, h)
	}
	// повторный набор не растит журнал
	if _, idx := log.Append([]byte("набор 3")); idx != 3 || log.Size() != 12 {
		t.Fatalf("повтор набора создал новый лист: индекс %d, размер %d", idx, log.Size())
	}

	sth, err := log.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := sth.Verify(pubKeyString(key)); err != nil {
		t.Fatalf("корень не проверяется: %v", err)
	}
	if err := sth.Verify(pubKeyString(detKey(2))); err == nil {
		t.Fatal("корень принят с чужим ключом")
	}
	root, _ := hashFromHex(sth.Head.Root)

	proof, err := log.InclusionProof(5)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaves[5], 5, sth.Head.Size, proof, root) {
		t.Fatal("включение из журнала не проверяется")
	}

	cons, err := log.ConsistencyProof(7)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConsistency(7, sth.Head.Size, cons, treeHash(leaves[:7]), root) {
		t.Fatal("согласованность из журнала не проверяется")
	}
}

func TestLogSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/log.json"
	key := detKey(1)
	log := NewTransparencyLog(path, key)
	for i := 0; i < 5; i++ {
		log.Append([]byte(fmt.Sprintf("набор %d", i)))
	}
	first, _ := log.Head()

	reopened := NewTransparencyLog(path, key)
	again, _ := reopened.Head()
	if again.Head.Size != first.Head.Size || again.Head.Root != first.Head.Root {
		t.Fatalf("журнал не пережил перезапуск: было %d/%s, стало %d/%s",
			first.Head.Size, first.Head.Root[:8], again.Head.Size, again.Head.Root[:8])
	}
}
