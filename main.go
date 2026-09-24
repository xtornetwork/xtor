// xray-onion — «луковая» сеть на туннелях Xray (VLESS + Reality) в одном
// бинарнике. Ядро Xray встроено библиотекой: отдельный процесс и файл его
// конфигурации не нужны.
//
//	xray-onion install node       развернуть узел и поставить его службой
//	xray-onion install directory  развернуть директорию и поставить её службой
//	xray-onion node               запустить узел
//	xray-onion directory          запустить директорию
//	xray-onion client             запустить клиент (SOCKS5 + HTTP)
//	xray-onion keygen             выпустить ключи Reality и UUID
//	xray-onion mint <имя>         выпустить индивидуальный токен узла
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	// Сайт-прикрытие: Reality проксирует на него рукопожатие, поэтому он обязан
	// быть доступен с узла и подходить по параметрам TLS. Проверено, что
	// www.microsoft.com с этой версией Reality не годится, а cloudflare, google
	// и apple годятся. Для обхода блокировок выбирайте из целевой страны.
	defaultSNI       = "www.cloudflare.com"
	directoryKeyless = "" // ключ директории неизвестен: режим доверия при первом обращении
)

func logf(format string, args ...any) { log.Printf(format, args...) }

var signalOnce struct {
	sync.Once
	ch chan struct{}
}

// waitForSignal отдаёт канал, который закрывается по Ctrl+C или SIGTERM.
func waitForSignal() <-chan struct{} {
	signalOnce.Do(func() {
		signalOnce.ch = make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sig
			close(signalOnce.ch)
		}()
	})
	return signalOnce.ch
}

func defaultNodeConfigPath() string {
	if runtime.GOOS == "windows" {
		return "node.json"
	}
	return "/etc/xray-onion/node.json"
}

func defaultClientStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "state.json"
	}
	return home + string(os.PathSeparator) + ".xray-onion" + string(os.PathSeparator) + "state.json"
}

// ── ключи ────────────────────────────────────────────────────────────────

// x25519Pair выпускает пару ключей Reality в том виде, в каком их ждёт ядро:
// base64 URL без выравнивания, 32 байта.
func x25519Pair() (priv, pub string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newUUID выпускает UUID версии 4.
func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func runKeygen(args []string) error {
	priv, pub, err := x25519Pair()
	if err != nil {
		return err
	}
	sid, err := randomHex(8)
	if err != nil {
		return err
	}
	u1, err := newUUID()
	if err != nil {
		return err
	}
	u2, err := newUUID()
	if err != nil {
		return err
	}
	identity, id, err := NewIdentity()
	if err != nil {
		return err
	}
	fmt.Printf("identity    : %s\nidentityKey : %s\nprivateKey  : %s\npublicKey   : %s\n"+
		"shortId     : %s\nuuidVision  : %s\nuuidPlain   : %s\n",
		id, EncodeIdentity(identity), priv, pub, sid, u1, u2)
	return nil
}

// ── ввод ─────────────────────────────────────────────────────────────────

type prompter struct {
	in          *bufio.Reader
	interactive bool
}

func newPrompter() *prompter {
	st, err := os.Stdin.Stat()
	interactive := err == nil && (st.Mode()&os.ModeCharDevice) != 0
	return &prompter{in: bufio.NewReader(os.Stdin), interactive: interactive}
}

// ask возвращает значение флага, а если оно пустое — спрашивает у человека.
func (p *prompter) ask(value, question, fallback string) (string, error) {
	if value != "" {
		return value, nil
	}
	if !p.interactive {
		if fallback != "" {
			return fallback, nil
		}
		return "", fmt.Errorf("не задано: %s", question)
	}
	label := question
	if fallback != "" {
		label += " [" + fallback + "]"
	}
	for {
		fmt.Printf("%s: ", label)
		line, err := p.in.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			if fallback != "" {
				return fallback, nil
			}
			return "", fmt.Errorf("ввод прерван")
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
		if fallback != "" {
			return fallback, nil
		}
		fmt.Println("  значение не может быть пустым")
	}
}

func (p *prompter) confirm(question string, def bool) bool {
	if !p.interactive {
		return def
	}
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Printf("%s [%s]: ", question, hint)
	line, _ := p.in.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return strings.HasPrefix(line, "y") || strings.HasPrefix(line, "д")
}

// ── точка входа ──────────────────────────────────────────────────────────

func usage() {
	fmt.Print(`xray-onion — «луковая» сеть на туннелях Xray, всё в одном бинарнике

Команды:
  install node        развернуть узел: ключи, описание, служба systemd, запуск
  install directory   развернуть директорию: ключ, токены, служба systemd, запуск
  node                запустить узел
  directory           запустить директорию
  client              запустить клиент (SOCKS5 и HTTP-прокси)
  keygen              выпустить ключи Reality и UUID
  mint <файл> <метка> выпустить индивидуальный токен регистрации

Справка по команде:
  xray-onion <команда> -h
`)
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "node":
		err = runNode(os.Args[2:])
	case "directory":
		err = runDirectory(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "install":
		err = runInstall(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "mint":
		if len(os.Args) < 4 {
			err = fmt.Errorf("использование: xray-onion mint <файл-токенов> <метка>")
		} else {
			err = MintToken(os.Args[2], os.Args[3])
		}
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		logf("ошибка: %v", err)
		os.Exit(1)
	}
}
