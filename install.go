package main

// Самоустановка: один бинарник копирует себя в систему, выпускает ключи,
// пишет описание и поднимает службу systemd. Отдельный Xray ставить не нужно —
// ядро встроено.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	installDir  = "/usr/local/bin"
	confDir     = "/etc/xray-onion"
	stateDir    = "/var/lib/xray-onion"
	binName     = "xray-onion"
	nodeUnit    = "xray-onion-node"
	dirUnit     = "xray-onion-directory"
	dirUser     = "xrayonion"
)

func runInstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("использование: xray-onion install node|directory [флаги]")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("установка службы поддерживается только на Linux; "+
			"на %s запускайте команды node/directory/client напрямую", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("нужны права root")
	}
	switch args[0] {
	case "node":
		return installNode(args[1:])
	case "directory":
		return installDirectory(args[1:])
	default:
		return fmt.Errorf("неизвестно что ставить: %q (ожидается node или directory)", args[0])
	}
}

// copySelf кладёт текущий бинарник в /usr/local/bin.
func copySelf() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	target := filepath.Join(installDir, binName)
	if same, _ := sameFile(self, target); same {
		return target, nil
	}
	src, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer src.Close()
	tmp := target + ".new"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", err
	}
	return target, nil
}

func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

func writeUnit(name, body string) error {
	path := filepath.Join("/etc/systemd/system", name+".service")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return err
	}
	return nil
}

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// hardening — общие ограничения для служб.
const hardening = `NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
`

// ── узел ─────────────────────────────────────────────────────────────────

func installNode(args []string) error {
	fs := flag.NewFlagSet("install node", flag.ExitOnError)
	nick := fs.String("nick", "", "имя узла")
	port := fs.Int("port", 443, "порт Reality")
	listen := fs.String("listen", "0.0.0.0", "адрес прослушивания")
	sni := fs.String("sni", "", "SNI и dest для Reality")
	roles := fs.String("roles", "", "роли через запятую: guard,middle,exit")
	family := fs.String("family", "",
		"имена личностей родственных узлов через запятую (родство засчитывается только взаимное)")
	directory := fs.String("directory", "", "адреса директорий через запятую")
	token := fs.String("token", "", "токены регистрации через запятую, в том же порядке")
	readToken := fs.String("read-token", "", "токены чтения консенсуса через запятую")
	dirKey := fs.String("dir-key", "", "публичные ключи директорий через запятую")
	quorum := fs.Int("quorum", 0, "сколько директорий должны подтвердить узел (0 — большинство)")
	private := fs.Bool("private", false, "непубличный узел (мост)")
	reject := fs.String("reject-ports", "25,465,587", "порты, которые выход не пропускает")
	allowPrivate := fs.Bool("allow-private", false, "разрешить выход в приватные сети (только стенд)")
	force := fs.Bool("force", false, "перезаписать существующее описание узла")
	_ = fs.Parse(args)

	p := newPrompter()
	confPath := filepath.Join(confDir, "node.json")
	if _, err := os.Stat(confPath); err == nil && !*force {
		return fmt.Errorf("%s уже существует, добавьте -force для перезаписи", confPath)
	}

	host, _ := os.Hostname()
	defNick := sanitizeNick(host)
	var err error
	if *nick, err = p.ask(*nick, "Имя узла (латиница, цифры, - _)", defNick); err != nil {
		return err
	}
	if !nickRE.MatchString(*nick) {
		return fmt.Errorf("недопустимое имя узла %q", *nick)
	}
	if *sni, err = p.ask(*sni, "SNI для Reality (проверьте доступность из целевой страны)",
		defaultSNI); err != nil {
		return err
	}
	if *roles, err = p.ask(*roles, "Роли через запятую (guard,middle,exit)", "guard,middle"); err != nil {
		return err
	}
	if *family == "" && p.interactive {
		*family, _ = p.ask("", "Имена личностей ваших других узлов через запятую "+
			"(Enter — нет)", " ")
		*family = strings.TrimSpace(*family)
	}
	if *directory, err = p.ask(*directory,
		"Адреса директорий через запятую", ""); err != nil {
		return err
	}
	if *token, err = p.ask(*token,
		"Токены регистрации через запятую, по одному на директорию", ""); err != nil {
		return err
	}
	if *dirKey == "" && p.interactive {
		*dirKey, _ = p.ask("", "Публичные ключи директорий через запятую "+
			"(Enter — довериться первому ответу)", " ")
		*dirKey = strings.TrimSpace(*dirKey)
	}
	refs, err := buildDirectoryRefs(*directory, *dirKey, *token, *readToken, "")
	if err != nil {
		return err
	}

	roleList := splitClean(*roles)
	for _, r := range roleList {
		if !knownRoles[r] {
			return fmt.Errorf("неизвестная роль %q", r)
		}
	}
	rejectPorts, err := NormalizePorts(splitClean(*reject))
	if err != nil {
		return err
	}

	identity, nodeID, err := NewIdentity()
	if err != nil {
		return err
	}
	familyList := splitClean(*family)
	for _, f := range familyList {
		if !identityRE.MatchString(f) {
			return fmt.Errorf("негодное имя родственника %q", f)
		}
	}
	priv, pub, err := x25519Pair()
	if err != nil {
		return err
	}
	sid, err := randomHex(8)
	if err != nil {
		return err
	}
	uv, err := newUUID()
	if err != nil {
		return err
	}
	up, err := newUUID()
	if err != nil {
		return err
	}

	cfg := &NodeConfig{
		IdentityKey: EncodeIdentity(identity),
		Nick:        *nick, Listen: *listen, Port: *port, Roles: roleList,
		Family:  familyList,
		Private: *private, SNI: *sni, Dest: *sni + ":443",
		PrivateKey: priv, PublicKey: pub, ShortID: sid,
		UUIDVision: uv, UUIDPlain: up,
		Directories: refs, Quorum: *quorum,
		RejectPorts: rejectPorts, DNSServers: []string{"localhost"},
		AllowPrivate: *allowPrivate, LogLevel: "warning",
	}
	// проверяем то, что уйдёт в директорию, до записи на диск
	probe, err := cfg.Descriptor(0, identity)
	if err != nil {
		return fmt.Errorf("описание узла негодное: %w", err)
	}
	if err := ValidateDescriptor(probe); err != nil {
		return fmt.Errorf("описание узла негодное: %w", err)
	}

	for _, d := range []string{confDir, stateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := writeJSONAtomic(confPath, cfg, 0o600); err != nil {
		return err
	}
	bin, err := copySelf()
	if err != nil {
		return err
	}

	unit := fmt.Sprintf(`[Unit]
Description=xray-onion node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s node -config %s
Restart=always
RestartSec=10
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
%sReadWritePaths=%s %s

[Install]
WantedBy=multi-user.target
`, bin, confPath, hardening, stateDir, confDir)
	if err := writeUnit(nodeUnit, unit); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", nodeUnit); err != nil {
		return err
	}
	// при повторной установке служба уже работает, и enable --now её не тронет:
	// новый бинарник и новое описание подхватит только перезапуск
	_ = systemctl("restart", nodeUnit)

	fmt.Printf("\nУзел %s развёрнут.\n", *nick)
	fmt.Printf("  личность : %s\n  описание : %s\n  служба   : %s\n  ключ     : %s\n",
		nodeID, confPath, nodeUnit, pub)
	fmt.Println("  дескриптор подписан этой личностью: директория не может подменить")
	fmt.Println("  ключ Reality, она вправе лишь умолчать об узле")
	fmt.Println("  сообщите это имя операторам ваших других узлов, чтобы объявить родство")
	if *private {
		fmt.Println("  узел непубличный: попадёт только в выдачу мостов")
	}
	fmt.Printf("\nДиректория включит узел в консенсус после успешной проверки порта %d снаружи.\n", *port)
	fmt.Printf("Лог: journalctl -u %s -f\n", nodeUnit)
	if err := openFirewall(*port); err != nil {
		fmt.Printf("Откройте порт %d/tcp вручную: %v\n", *port, err)
	}
	return nil
}

func sanitizeNick(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "relay1"
	}
	return b.String()
}

func splitClean(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func openFirewall(port int) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return nil // межсетевого экрана нет — открывать нечего
	}
	out, err := exec.Command("ufw", "status").Output()
	if err != nil || !strings.Contains(string(out), "Status: active") {
		return nil
	}
	return exec.Command("ufw", "allow", strconv.Itoa(port)+"/tcp").Run()
}

// ── директория ───────────────────────────────────────────────────────────

func installDirectory(args []string) error {
	fs := flag.NewFlagSet("install directory", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1", "адрес прослушивания")
	port := fs.Int("port", 8500, "порт")
	sharedToken := fs.String("token", "", "общий токен регистрации (пусто = только индивидуальные)")
	readToken := fs.String("read-token", "", "токен чтения консенсуса (пусто = открытая сеть)")
	bridgeToken := fs.String("bridge-token", "", "токен выдачи мостов (пусто = не выдавать)")
	stale := fs.String("stale", "20m", "без heartbeat дольше — узел выбывает")
	maxNodes := fs.Int("max-nodes", 500, "предел числа узлов")
	maxPerIP := fs.Int("max-per-ip", 4, "предел числа узлов с одного адреса")
	behindProxy := fs.Bool("behind-proxy", false, "адрес узла из X-Forwarded-For")
	noProbe := fs.Bool("no-probe", false, "не проверять порты узлов")
	_ = fs.Parse(args)

	p := newPrompter()
	if *bridgeToken == "" && p.confirm("Включить выдачу непубличных входных узлов (мостов)?", false) {
		*bridgeToken, _ = randomHex(16)
	}

	if err := exec.Command("id", dirUser).Run(); err != nil {
		if err := exec.Command("useradd", "--system", "--no-create-home",
			"--shell", "/usr/sbin/nologin", dirUser).Run(); err != nil {
			return fmt.Errorf("не удалось создать пользователя %s: %w", dirUser, err)
		}
	}
	for _, d := range []string{confDir, stateDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
		_ = exec.Command("chown", dirUser+":"+dirUser, d).Run()
	}
	tokensPath := filepath.Join(confDir, "tokens.json")
	if _, err := os.Stat(tokensPath); err != nil {
		if err := writeJSONAtomic(tokensPath, map[string]string{}, 0o600); err != nil {
			return err
		}
	}
	_ = exec.Command("chown", dirUser+":"+dirUser, tokensPath).Run()

	bin, err := copySelf()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(confDir, "dir.key")
	statePath := filepath.Join(stateDir, "nodes.json")

	cmd := fmt.Sprintf("%s directory -listen %s -port %d -key %s -state %s "+
		"-tokens-file %s -stale %s -max-nodes %d -max-per-ip %d",
		bin, *listen, *port, keyPath, statePath, tokensPath, *stale, *maxNodes, *maxPerIP)
	if *sharedToken != "" {
		cmd += " -token " + *sharedToken
	}
	if *readToken != "" {
		cmd += " -read-token " + *readToken
	}
	if *bridgeToken != "" {
		cmd += " -bridge-token " + *bridgeToken
	}
	if *behindProxy {
		cmd += " -behind-proxy"
	}
	if *noProbe {
		cmd += " -no-probe"
	}

	unit := fmt.Sprintf(`[Unit]
Description=xray-onion directory
After=network-online.target
Wants=network-online.target

[Service]
User=%s
Group=%s
ExecStart=%s
Restart=always
RestartSec=5
%sRestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=%s %s

[Install]
WantedBy=multi-user.target
`, dirUser, dirUser, cmd, hardening, stateDir, confDir)
	if err := writeUnit(dirUnit, unit); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", dirUnit); err != nil {
		return err
	}
	_ = systemctl("restart", dirUnit)

	// ключ создаётся службой при первом запуске; читаем его, чтобы показать
	pub := "(смотрите journalctl -u " + dirUnit + " | grep ключ)"
	if key, err := loadOrCreateDirKey(keyPath); err == nil {
		pub = pubKeyString(key)
		_ = exec.Command("chown", dirUser+":"+dirUser, keyPath).Run()
	}

	fmt.Printf("\nДиректория развёрнута на %s:%d.\n", *listen, *port)
	fmt.Printf("  публичный ключ (клиентам и узлам): %s\n", pub)
	if *sharedToken != "" {
		fmt.Printf("  общий токен регистрации          : %s\n", *sharedToken)
	}
	if *readToken != "" {
		fmt.Printf("  токен чтения консенсуса          : %s\n", *readToken)
	}
	if *bridgeToken != "" {
		fmt.Printf("  токен выдачи мостов              : %s\n", *bridgeToken)
	}
	fmt.Printf("\nТокен для узла:\n  %s mint %s <имя-узла>\n", bin, tokensPath)
	fmt.Printf("\nНаружу публикуйте через nginx или Cloudflare:\n"+
		"  location / { proxy_pass http://%s:%d; proxy_set_header X-Forwarded-For $remote_addr; }\n"+
		"и запускайте директорию с -behind-proxy.\n", *listen, *port)
	return nil
}
