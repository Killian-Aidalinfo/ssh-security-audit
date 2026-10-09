#!/usr/bin/env python3
"""report.py — transforme le JSONL de fleet_audit.sh en rapport Markdown.

Usage : fleet_audit.sh -f hosts.txt | python3 report.py
        python3 report.py audit.jsonl

Tous les chiffres et toutes les alertes sont calculés ici, de façon
déterministe. Le modèle recopie ce rapport ; il ne recompte rien.
"""
import json
import sys
from datetime import datetime, timezone


def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    if len(s) >= 24 and s[-5] in "+-" and s[-3] != ":":  # +0000 -> +00:00
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def short(s):
    dt = parse_ts(s)
    return dt.astimezone(timezone.utc).strftime("%d/%m %H:%M") if dt else "?"


def main():
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    rows, errors = [], []
    for line in src:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(("?", f"JSON invalide : {e}"))
            continue
        (errors.append((r.get("target", "?"), r["error"])) if "error" in r else rows.append(r))

    out = []
    p = out.append
    p("# Audit SSH du parc\n")
    p(f"Généré le {datetime.now(timezone.utc):%d/%m/%Y %H:%M} UTC. "
      "Tous les chiffres viennent de `ssh_audit.sh` (grep sur journald) ; aucun n'est estimé.\n")

    # --- Période couverte -------------------------------------------------
    p("## Période couverte\n")
    p("| Machine | Fenêtre demandée (depuis, UTC) | Début du journal | 1re ligne SSH | Couverture |")
    p("|---|---|---|---|---|")
    warnings = []
    for r in rows:
        since = parse_ts(r.get("since_utc"))
        jstart = parse_ts(r.get("journal_start"))
        if not r.get("window_applied", True):
            cov = "⚠️ fenêtre non appliquée"
            warnings.append(f"**{r['host']}** : logs lus dans `{r['source']}`, la fenêtre `--since` n'est pas appliquée ; "
                            "ses chiffres ne sont pas comparables aux autres.")
        elif since and jstart and jstart > since:
            cov = "⚠️ partielle"
            warnings.append(f"**{r['host']}** : le journal commence le {short(r['journal_start'])} UTC, après le début de la "
                            f"fenêtre ({short(r['since_utc'])}). Les événements antérieurs ne sont pas visibles : "
                            "un compteur à 0 ne prouve pas l'absence d'attaque sur cette période.")
        else:
            cov = "complète"
        p(f"| {r['host']} (`{r['target']}`) | {r.get('since', '?')} ({short(r.get('since_utc'))}) | "
          f"{short(r.get('journal_start'))} | {short(r.get('first_ssh_line'))} | {cov} |")
    p("")

    # --- Compteurs ------------------------------------------------------------
    p("## Compteurs\n")
    p("| Machine | Sessions échouées | IP sources | Invalid user | Failed password | Failed publickey "
      "| Penalties | Timeouts pré-auth | Erreurs KEX | Connexions acceptées |")
    p("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        c = r["counts"]
        p(f"| {r['host']} | {c['failed_sessions']} | {c['failing_ips']} | {c['invalid_user']} | {c['failed_password']} "
          f"| {c['failed_publickey']} | {c['penalty']} | {c['timeout_before_auth']} | {c['kex_errors']} | {c['accepted']} |")
    p("")
    p("_Sessions échouées_ = PID `sshd-session` distincts ayant un échec d'authentification "
      "(une tentative écrit souvent 2 lignes). _Penalties_ = connexions coupées par `PerSourcePenalties` "
      "(scanner qui se connecte sans tenter de s'authentifier).\n")

    # --- Configuration --------------------------------------------------------
    p("## Configuration SSH effective\n")
    p("| Machine | PasswordAuthentication | KbdInteractiveAuthentication | PermitRootLogin | Port | fail2ban (IP bannies) |")
    p("|---|---|---|---|---|---|")
    for r in rows:
        k = r.get("sshd_config", {})
        p(f"| {r['host']} | {k.get('passwordauthentication') or '?'} | {k.get('kbdinteractiveauthentication') or '?'} "
          f"| {k.get('permitrootlogin') or '?'} | {k.get('port') or '?'} | {r.get('fail2ban_banned')} |")
        if (k.get("passwordauthentication") or "").lower() == "yes":
            warnings.append(f"**{r['host']}** : l'authentification par mot de passe est ACTIVÉE "
                            f"({r['counts']['failed_password']} échecs de mot de passe dans la fenêtre).")
        if r["counts"]["failed_password"] and (k.get("passwordauthentication") or "").lower() == "no":
            warnings.append(f"**{r['host']}** : {r['counts']['failed_password']} « Failed password » alors que "
                            "PasswordAuthentication vaut no — vérifier KbdInteractiveAuthentication/PAM.")
    p("")

    # --- Principales IP --------------------------------------------------------
    p("## Principales IP sources par machine\n")
    for r in rows:
        ips = r.get("failing_ips", [])[:5]
        if not ips:
            p(f"- **{r['host']}** : aucune IP en échec dans la fenêtre.")
            continue
        lst = ", ".join(f"`{i['ip']}` ({i['lines']} lignes, {short(i['first'])} → {short(i['last'])})" for i in ips)
        p(f"- **{r['host']}** : {lst}")
    p("")

    # --- IP vues sur plusieurs machines (seule base admise pour une corrélation)
    p("## IP vues sur plusieurs machines\n")
    seen = {}
    for r in rows:
        for i in r.get("failing_ips", []):
            seen.setdefault(i["ip"], []).append((r["host"], i))
    shared = sorted(((ip, hs) for ip, hs in seen.items() if len(hs) > 1), key=lambda x: (-len(x[1]), x[0]))
    if not shared:
        p("Aucune IP commune : rien ne permet d'affirmer une attaque coordonnée.\n")
    else:
        p("| IP | Machines | Détail (lignes, première → dernière vue UTC) |")
        p("|---|---|---|")
        for ip, hs in shared:
            det = "<br>".join(f"{h} : {i['lines']}, {short(i['first'])} → {short(i['last'])}" for h, i in hs)
            p(f"| `{ip}` | {len(hs)} | {det} |")
        p("")
        p("Une même IP sur plusieurs machines **à des heures proches** indique un balayage de la plage d'adresses ; "
          "à des heures éloignées, ce sont des passages indépendants du même scanner.\n")

    # --- Alertes et erreurs ----------------------------------------------------
    p("## Points d'attention\n")
    if not warnings and not errors:
        p("Aucun.\n")
    for w in warnings:
        p(f"- {w}")
    for t, e in errors:
        p(f"- **{t}** : audit impossible — {e}")
    p("")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
