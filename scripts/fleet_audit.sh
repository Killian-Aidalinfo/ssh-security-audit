#!/usr/bin/env bash
# fleet_audit.sh — lance ssh_audit.sh en parallèle sur un parc et sort du JSONL
# (une ligne par machine, ou une ligne {"target":..,"error":..} si injoignable).
#
# Usage :
#   fleet_audit.sh -f hosts.txt [--since "24 hours ago"] [-i ~/.ssh/cle] > audit.jsonl
#   fleet_audit.sh root@1.2.3.4 admin@5.6.7.8 --since "2026-10-09 00:00"
#
# hosts.txt : une cible par ligne (user@host), lignes vides et # ignorées.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SINCE="24 hours ago"
KEY=""
TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    -i) KEY="$2"; shift 2 ;;
    -f) while read -r l; do l="${l%%#*}"; l="$(echo "$l" | xargs)"; [ -n "$l" ] && TARGETS+=("$l"); done < "$2"; shift 2 ;;
    -h|--help) sed -n 2,10p "$0"; exit 0 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done
[ ${#TARGETS[@]} -eq 0 ] && { echo "aucune cible (voir --help)" >&2; exit 2; }

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
[ -n "$KEY" ] && SSH_OPTS+=(-i "$KEY")

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
for i in "${!TARGETS[@]}"; do
  t="${TARGETS[$i]}"
  (
    out=$(ssh "${SSH_OPTS[@]}" "$t" "bash -s -- --since '$SINCE'" < "$DIR/ssh_audit.sh" 2>"$TMP/$i.err")
    if [ $? -eq 0 ] && [ "${out:0:1}" = "{" ]; then
      # Ajoute la cible utilisée (le hostname seul ne donne pas l'IP).
      printf '{"target":"%s",%s\n' "$t" "${out:1}" > "$TMP/$i.json"
    else
      err=$(tr -cd '[:print:]' < "$TMP/$i.err" | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-300)
      printf '{"target":"%s","error":"%s"}\n' "$t" "${err:-sortie invalide}" > "$TMP/$i.json"
    fi
  ) &
done
wait
cat "$TMP"/*.json
