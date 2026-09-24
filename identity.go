package main

// Личность узла и подпись дескриптора.
//
// Директория раздаёт клиентам ключи Reality, которыми те аутентифицируют хопы.
// Пока дескриптор подписан только директорией, она может подменить ключ узла
// на свой и законно встать посередине цепочки, и клиент этого не заметит.
//
// Поэтому у узла есть вторая, долговременная пара Ed25519 — его личность.
// Имя личности выводится из её открытого ключа, а дескриптор узел подписывает
// сам. Директория хранит и отдаёт подписанное побайтово и не имеет права это
// трогать: подменить ключ Reality она больше не может, у неё остаётся лишь
// право умолчать об узле.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Длина имени личности в символах base32: 26 символов это 130 бит,
// с запасом против подбора ключа под чужое имя.
const identityLen = 26

var identityRE = regexp.MustCompile(`^[a-z2-7]{26}$`)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint выводит имя личности из её открытого ключа.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return strings.ToLower(b32.EncodeToString(sum[:]))[:identityLen]
}

// NewIdentity выпускает долговременную пару ключей узла.
func NewIdentity() (priv ed25519.PrivateKey, id string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, "", err
	}
	return priv, Fingerprint(pub), nil
}

// EncodeIdentity кодирует приватный ключ личности для хранения в описании узла.
func EncodeIdentity(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

// DecodeIdentity читает приватный ключ личности из описания узла.
func DecodeIdentity(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("ключ личности повреждён")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// LoadOrCreateIdentity читает ключ личности из файла или заводит новый.
func LoadOrCreateIdentity(path string) (ed25519.PrivateKey, string, error) {
	if data, err := os.ReadFile(path); err == nil {
		priv, err := DecodeIdentity(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", path, err)
		}
		return priv, Fingerprint(priv.Public().(ed25519.PublicKey)), nil
	}
	priv, id, err := NewIdentity()
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, []byte(EncodeIdentity(priv)), 0o600); err != nil {
		return nil, "", err
	}
	return priv, id, nil
}

// signingCopy — дескриптор в том виде, в каком он подписывается: без самой
// подписи и без полей, которые не путешествуют по проводу.
func signingCopy(n Node) Node {
	n.Sig = ""
	n.Bridge = false
	return n
}

// SignDescriptor подписывает дескриптор ключом личности узла.
//
// Узел обязан подготовить поля заранее (роли отсортированы, порты приведены к
// канону): директория и клиент проверяют подпись над тем, что получили, и
// ничего не переписывают, иначе подпись перестала бы сходиться.
func SignDescriptor(n Node, priv ed25519.PrivateKey, lifetime time.Duration) (Node, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Node{}, fmt.Errorf("негодный ключ личности")
	}
	n.ID = Fingerprint(pub)
	n.IDKey = base64.StdEncoding.EncodeToString(pub)
	n.Published = time.Now().Unix()
	n.Expires = n.Published + int64(lifetime.Seconds())

	raw, err := canonicalMarshal(signingCopy(n))
	if err != nil {
		return Node{}, err
	}
	n.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	return n, nil
}

// VerifyDescriptor проверяет, что дескриптор выпущен владельцем личности,
// что имя личности выведено из её ключа и что срок годности не вышел.
func VerifyDescriptor(n Node, now time.Time) error {
	if !identityRE.MatchString(n.ID) {
		return fmt.Errorf("негодное имя личности %q", n.ID)
	}
	pub, err := base64.StdEncoding.DecodeString(n.IDKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("узел %s: негодный ключ личности", n.ID)
	}
	// имя обязано быть выведено из ключа, иначе подпись можно было бы
	// принести от чужой личности
	if got := Fingerprint(pub); got != n.ID {
		return fmt.Errorf("имя %s не соответствует ключу личности (ожидалось %s)", n.ID, got)
	}
	sig, err := base64.StdEncoding.DecodeString(n.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("узел %s: негодная подпись дескриптора", n.ID)
	}
	raw, err := canonicalMarshal(signingCopy(n))
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return fmt.Errorf("узел %s: подпись дескриптора неверна", n.ID)
	}
	if n.Published <= 0 || n.Expires <= n.Published {
		return fmt.Errorf("узел %s: негодные отметки времени", n.ID)
	}
	if now.Unix() > n.Expires {
		return fmt.Errorf("узел %s: дескриптор просрочен", n.ID)
	}
	// защита от дескриптора, выписанного далеко вперёд
	if n.Published > now.Add(2*time.Hour).Unix() {
		return fmt.Errorf("узел %s: дескриптор из будущего", n.ID)
	}
	return nil
}

// Short возвращает короткое читаемое обозначение узла для логов.
func (n Node) Short() string {
	id := n.ID
	if len(id) > 8 {
		id = id[:8]
	}
	if n.Nick == "" {
		return id
	}
	return n.Nick + "/" + id
}
