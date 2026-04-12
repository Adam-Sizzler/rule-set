#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRS_DIR="$ROOT_DIR/rules/srs"
JSON_DIR="$ROOT_DIR/rules/json"
PROVIDER_DIR="$ROOT_DIR/rules/providers"
SING_BOX_BIN="${SING_BOX_BIN:-/home/docker/singbox/sing-box}"

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -x "$SING_BOX_BIN" ] || { echo "sing-box binary not found: $SING_BOX_BIN" >&2; exit 1; }

mkdir -p "$SRS_DIR" "$JSON_DIR" "$PROVIDER_DIR"

fetch_srs() {
  local name="$1"
  local url="$2"
  curl -fsSL "$url" -o "$SRS_DIR/$name.srs"
  "$SING_BOX_BIN" rule-set decompile "$SRS_DIR/$name.srs" -o "$JSON_DIR/$name.json"
}

fetch_srs "encrypted-dns" "https://cdn.jsdelivr.net/gh/FPPweb3/sb-rule-sets@main/encrypted-dns.srs"
fetch_srs "bypass-domains" "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs"
fetch_srs "bypass-ips" "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs"
fetch_srs "itdog-russia-inside" "https://cdn.jsdelivr.net/gh/legiz-ru/sb-rule-sets@main/itdoginfo-inside-russia.srs"
fetch_srs "android-fcm" "https://cdn.jsdelivr.net/gh/FPPweb3/sb-rule-sets@main/android-fcm.srs"
fetch_srs "bypass-apps" "https://cdn.jsdelivr.net/gh/legiz-ru/sb-rule-sets@main/ru-app-list.srs"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  [ .rules[] | (.domain|toarr)[]? | "DOMAIN,\(.)" ]
  | unique[]
' "$JSON_DIR/android-fcm.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/android-fcm.yaml"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  [ .. | objects | .package_name? | select(.) | toarr[] | "PROCESS-NAME,\(.)" ]
  | unique[]
' "$JSON_DIR/bypass-apps.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/bypass-apps.yaml"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  def normsuffix: ltrimstr(".");
  (
    [ .rules[] | (.domain|toarr)[]? | "DOMAIN,\(.)" ] +
    [ .rules[] | (.domain_suffix|toarr)[]? | "DOMAIN-SUFFIX,\(.|normsuffix)" ]
  )
  | unique[]
' "$JSON_DIR/bypass-domains.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/bypass-domains.yaml"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  [ .rules[] | (.ip_cidr|toarr)[]? | "IP-CIDR,\(.)" ]
  | unique[]
' "$JSON_DIR/bypass-ips.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/bypass-ips.yaml"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  def normsuffix: ltrimstr(".");
  [ .rules[] | (.domain_suffix|toarr)[]? | "DOMAIN-SUFFIX,\(.|normsuffix)" ]
  | unique[]
' "$JSON_DIR/itdog-russia-inside.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/itdog-russia-inside.yaml"

jq -r '
  def toarr: if . == null then [] elif (type=="array") then . else [.] end;
  def normsuffix: ltrimstr(".");
  (
    [ "DST-PORT,853" ] +
    [ .. | objects | .domain? | select(.) | toarr[] | "AND,((DOMAIN,\(.)),(NOT,((DST-PORT,53))))" ] +
    [ .. | objects | .domain_suffix? | select(.) | toarr[] | "AND,((DOMAIN-SUFFIX,\(.|normsuffix)),(NOT,((DST-PORT,53))))" ] +
    [ .. | objects | .domain_regex? | select(.) | toarr[] | "AND,((DOMAIN-REGEX,\(.)),(NOT,((DST-PORT,53))))" ] +
    [ .. | objects | .ip_cidr? | select(.) | toarr[] | "AND,((IP-CIDR,\(.)),(NOT,((DST-PORT,53))))" ]
  )
  | unique[]
' "$JSON_DIR/encrypted-dns.json" | { echo 'payload:'; sed 's/^/- /'; } > "$PROVIDER_DIR/encrypted-dns.yaml"

for file in "$PROVIDER_DIR"/*.yaml; do
  echo "$(basename "$file"): $(( $(wc -l < "$file") - 1 ))"
done
