#!/bin/sh
# Стенд: генерирует описание узла из переменных окружения и запускает его.
set -e
KEYS="$(xray-onion keygen)"
val() { echo "$KEYS" | awk -v k="$1" '$1==k {print $3}'; }
cat > /etc/node.json <<JSON
{
  "identity_key": "$(val identityKey)",
  "nick": "${NICK}",
  "listen": "0.0.0.0",
  "port": ${PORT:-443},
  "roles": [$(echo "${ROLES:-guard,middle}" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?",":""), $i}}')],
  "family": [],
  "public_ip": "",
  "private": ${PRIVATE:-false},
  "sni": "${SNI:-www.cloudflare.com}",
  "dest": "${SNI:-www.cloudflare.com}:443",
  "private_key": "$(val privateKey)",
  "public_key": "$(val publicKey)",
  "short_id": "$(val shortId)",
  "uuid_vision": "$(val uuidVision)",
  "uuid_plain": "$(val uuidPlain)",
  "directories": [$(echo "${DIRECTORY:-http://directory1:8500}" | awk -F, -v t="${TOKEN:-labtoken}" '{for(i=1;i<=NF;i++){printf "%s{\"url\": \"%s\", \"token\": \"%s\"}", (i>1?", ":""), $i, t}}')],
  "quorum": 0,
  "reject_ports": [$(echo "${REJECT_PORTS:-25}" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?",":""), $i}}')],
  "dns_servers": ["localhost"],
  "allow_private": true,
  "loglevel": "${LOGLEVEL:-warning}"
}
JSON
exec xray-onion node -config /etc/node.json -interval "${INTERVAL:-20s}" -peer-grace "${PEER_GRACE:-10m}"
