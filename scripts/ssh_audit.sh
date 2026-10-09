#!/usr/bin/env bash
# ssh_audit.sh — compte les événements SSH d'UNE machine et sort UNE ligne JSON.
# À exécuter sur la machine cible (root, ou membre du groupe systemd-journal) :
#   ssh root@host 'bash -s' -- --since "24 hours ago" < ssh_audit.sh
# Les chiffres viennent uniquement de grep/awk : le modèle ne doit jamais recompter.
set -uo pipefail
export LC_ALL=C

SINCE="24 hours ago"
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done

# --- Source des logs --------------------------------------------------------
# OpenSSH >= 9.8 écrit les échecs d'authentification sous l'identifiant
# « sshd-session » ; le démon (penalties, timeouts) écrit sous « sshd ».
# On interroge les deux identifiants dans UNE seule requête : additionner
# « -u ssh » et « _COMM=sshd-session » compterait chaque ligne deux fois.
SOURCE="journald"
WINDOW_APPLIED=true
LOG=""
if command -v journalctl >/dev/null 2>&1; then
  LOG=$(journalctl -t sshd -t sshd-session --since "$SINCE" --no-pager -o short-iso 2>/dev/null | grep -v '^-- ' || true)
fi
if [ -z "$LOG" ]; then
  for f in /var/log/auth.log /var/log/secure; do
    if [ -r "$f" ]; then
      LOG=$(grep -E 'sshd(-session)?\[' "$f" || true)
      SOURCE="$f"; WINDOW_APPLIED=false
      break
    fi
  done
fi

# --- Helpers ----------------------------------------------------------------
count() { [ -z "$LOG" ] && { echo 0; return; }; printf '%s\n' "$LOG" | grep -cE "$1" || true; }
# Échappe une chaîne pour JSON et retire les caractères non imprimables
# (les noms d'utilisateurs tentés par les attaquants peuvent en contenir).
jstr() { printf '%s' "$1" | tr -cd '[:print:]' | sed 's/\\/\\\\/g; s/"/\\"/g' | sed 's/^/"/; s/$/"/'; }
sample() {
  local l=""
  [ -n "$LOG" ] && l=$(printf '%s\n' "$LOG" | grep -m1 -E "$1" | cut -c1-300 || true)
  if [ -n "$l" ]; then jstr "$l"; else echo null; fi
}

# --- Motifs (un motif = un compteur, documentés dans SKILL.md) --------------
P_INVALID='Invalid user '
P_FAILED_PW='Failed password '
P_FAILED_PK='Failed publickey '
P_PREAUTH_CLOSED='(Connection closed by|Disconnected from) (authenticating|invalid) user '
P_PENALTY='penalty: '
P_TIMEOUT='Timeout before authentication'
P_KEX='kex_exchange_identification|banner exchange|kex_protocol_error|error in libcrypto'
P_ACCEPTED='Accepted (publickey|password|keyboard-interactive)'
P_FAILURE="$P_INVALID|$P_FAILED_PW|$P_FAILED_PK|$P_PREAUTH_CLOSED|$P_PENALTY|$P_TIMEOUT|$P_KEX"

# Sessions distinctes : une tentative produit souvent plusieurs lignes
# (Invalid user + Connection closed) sous le même PID sshd-session.
SESSIONS=0
if [ -n "$LOG" ]; then
  SESSIONS=$(printf '%s\n' "$LOG" | grep -E "$P_INVALID|$P_FAILED_PW|$P_FAILED_PK|$P_PREAUTH_CLOSED" \
    | grep -oE 'sshd(-session)?\[[0-9]+\]' | sort -u | wc -l | tr -d ' ')
fi

# --- IP sources des échecs : nombre de lignes, première et dernière vue -----
IPS_JSON="[]"
IP_COUNT=0
if [ -n "$LOG" ]; then
  IP_ROWS=$(printf '%s\n' "$LOG" | grep -E "$P_FAILURE" | awk '
    match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {   # pas de {n,m} : mawk (Debian) ne les gère pas
      ip = substr($0, RSTART, RLENGTH); ts = substr($1, 1, 19)
      n[ip]++; if (!(ip in first)) first[ip] = ts; last[ip] = ts
    }
    END { for (ip in n) printf "%d %s %s %s\n", n[ip], ip, first[ip], last[ip] }' | sort -rn)
  if [ -n "$IP_ROWS" ]; then
    IP_COUNT=$(printf '%s\n' "$IP_ROWS" | wc -l | tr -d ' ')
    IPS_JSON="[$(printf '%s\n' "$IP_ROWS" | head -200 | awk '{printf "%s{\"ip\":\"%s\",\"lines\":%d,\"first\":\"%s\",\"last\":\"%s\"}", (NR>1?",":""), $2, $1, $3, $4}')]"
  fi
fi

# --- Période réellement couverte --------------------------------------------
FIRST_TS=null; LAST_TS=null
if [ -n "$LOG" ]; then
  FIRST_TS=$(jstr "$(printf '%s\n' "$LOG" | head -1 | cut -c1-25)")
  LAST_TS=$(jstr "$(printf '%s\n' "$LOG" | tail -1 | cut -c1-25)")
fi
JOURNAL_START=null
if command -v journalctl >/dev/null 2>&1; then
  # Début du journal complet : si la machine a démarré (ou été créée) après
  # « --since », un compteur à 0 ne prouve pas l'absence d'attaque.
  js=$(journalctl -q --no-pager -o short-iso 2>/dev/null | head -n 1 | cut -c1-25)
  [ -n "$js" ] && JOURNAL_START=$(jstr "$js")
fi

# --- Configuration SSH effective et fail2ban -----------------------------------
cfg() { sshd -T 2>/dev/null | awk -v k="$1" '$1==k {print $2; exit}'; }
CFG_PW=$(cfg passwordauthentication); CFG_ROOT=$(cfg permitrootlogin)
CFG_KBD=$(cfg kbdinteractiveauthentication); CFG_PORT=$(cfg port)
F2B=null
if command -v fail2ban-client >/dev/null 2>&1; then
  b=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/ {gsub(/ /,"",$2); print $2}')
  F2B=$(jstr "${b:-inactif}")
else
  F2B='"absent"'
fi
cfgj() { if [ -n "$1" ]; then jstr "$1"; else echo null; fi; }

# --- Sortie ---------------------------------------------------------------------
SINCE_UTC=$(date -u -d "$SINCE" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
printf '{"host":%s,"source":%s,"since":%s,"since_utc":%s,"window_applied":%s,' \
  "$(jstr "$(hostname)")" "$(jstr "$SOURCE")" "$(jstr "$SINCE")" "$(cfgj "$SINCE_UTC")" "$WINDOW_APPLIED"
printf '"generated_at":%s,"journal_start":%s,"first_ssh_line":%s,"last_ssh_line":%s,' \
  "$(jstr "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$JOURNAL_START" "$FIRST_TS" "$LAST_TS"
printf '"counts":{"invalid_user":%d,"failed_password":%d,"failed_publickey":%d,"preauth_closed":%d,"penalty":%d,"timeout_before_auth":%d,"kex_errors":%d,"accepted":%d,"failed_sessions":%d,"failing_ips":%d},' \
  "$(count "$P_INVALID")" "$(count "$P_FAILED_PW")" "$(count "$P_FAILED_PK")" "$(count "$P_PREAUTH_CLOSED")" \
  "$(count "$P_PENALTY")" "$(count "$P_TIMEOUT")" "$(count "$P_KEX")" "$(count "$P_ACCEPTED")" "$SESSIONS" "$IP_COUNT"
printf '"samples":{"invalid_user":%s,"failed_password":%s,"penalty":%s,"timeout_before_auth":%s,"kex_errors":%s,"accepted":%s},' \
  "$(sample "$P_INVALID")" "$(sample "$P_FAILED_PW")" "$(sample "$P_PENALTY")" "$(sample "$P_TIMEOUT")" "$(sample "$P_KEX")" "$(sample "$P_ACCEPTED")"
printf '"sshd_config":{"passwordauthentication":%s,"permitrootlogin":%s,"kbdinteractiveauthentication":%s,"port":%s},"fail2ban_banned":%s,' \
  "$(cfgj "$CFG_PW")" "$(cfgj "$CFG_ROOT")" "$(cfgj "$CFG_KBD")" "$(cfgj "$CFG_PORT")" "$F2B"
printf '"failing_ips":%s}\n' "$IPS_JSON"
