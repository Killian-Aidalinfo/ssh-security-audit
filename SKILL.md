---
name: ssh-security-audit
description: "Audit fiable des tentatives de connexion SSH sur un ou plusieurs serveurs : comptage par script, période couverte, corrélation par IP."
version: 1.0.0
author: Killian (Aidalinfo), Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [SSH, Security, Audit, Logs, journald, DevOps, Sysadmin]
    related_skills: []
prerequisites:
  commands: [ssh, python3]
---

# Audit de sécurité SSH

## Quand l'utiliser

Dès que l'utilisateur demande combien de tentatives de connexion SSH ont échoué, si un serveur est attaqué ou scanné, quelles IP le visent, si plusieurs machines subissent la même attaque, ou un état de la sécurité SSH d'un parc.

## Règle d'or : tu ne comptes jamais toi-même

Tous les chiffres viennent des scripts de cette skill. Tu n'écris pas tes propres `grep -c`, tu n'additionnes pas, tu n'estimes pas, tu ne complètes pas un chiffre manquant. Si un chiffre n'est pas dans la sortie du script, tu dis qu'il n'est pas disponible.

## Procédure

1. **Lister les cibles** (`user@host`, une par ligne) dans un fichier, par exemple `/tmp/hosts.txt`. Si l'utilisateur ne précise pas la fenêtre, utilise `24 hours ago` et dis-le.
2. **Lancer l'audit** depuis le dossier de la skill :
   ```bash
   scripts/fleet_audit.sh -f /tmp/hosts.txt --since "24 hours ago" [-i ~/.ssh/cle] > /tmp/ssh_audit.jsonl
   python3 scripts/report.py /tmp/ssh_audit.jsonl
   ```
   Pour une seule machine : `scripts/fleet_audit.sh root@1.2.3.4 | python3 scripts/report.py`.
3. **Présenter le rapport** : recopie les tableaux de `report.py` tels quels, sans arrondir ni reformuler les chiffres, y compris la section « Points d'attention ».
4. **Interpréter**, dans une section séparée et intitulée « Analyse », en respectant les règles ci-dessous.

## Règles d'interprétation

- **Période d'abord.** Indique toujours la période réellement couverte par chaque machine. Ne compare deux machines que si `report.py` marque leur couverture « complète » ; sinon, dis explicitement que la comparaison est biaisée et pourquoi.
- **Un zéro se justifie.** Un compteur à 0 sur une machine à couverture « partielle » ne prouve rien : dis que le journal commence après le début de la fenêtre (machine récente ou redémarrée), pas que la machine a été épargnée.
- **Corrélation = même IP, mêmes heures.** N'affirme un « scan coordonné » ou un « balayage » que si la section « IP vues sur plusieurs machines » montre la même IP sur plusieurs machines avec des horaires proches. Cite l'IP et les heures. Des chiffres identiques sans IP commune ne sont qu'une coïncidence possible.
- **Faits et hypothèses séparés.** Un fait cite un chiffre ou une ligne du rapport. Une hypothèse est formulée comme telle (« probablement », « à vérifier »).
- **Contradiction = correction.** Si un chiffre contredit ce que tu as dit plus tôt dans la conversation, corrige explicitement l'ancienne affirmation au lieu d'ajouter une note à côté.
- **Échec d'audit visible.** Si une machine apparaît en erreur (injoignable, droits insuffisants), dis-le ; ne la traite pas comme une machine à 0.

## Évaluer le risque

| Constat dans le rapport | Lecture |
|---|---|
| `PasswordAuthentication no` et `KbdInteractiveAuthentication no` | Les tentatives par mot de passe ne peuvent pas aboutir : bruit de fond d'Internet, risque faible. |
| `PasswordAuthentication yes` avec des « Failed password » | Risque réel de force brute : recommander l'authentification par clé et fail2ban. |
| Connexions acceptées depuis une IP inconnue de l'utilisateur | À signaler en priorité : demander à l'utilisateur s'il reconnaît l'IP (cite la ligne d'exemple). |
| fail2ban absent sur une machine exposée | Recommandation, pas une urgence si l'authentification par mot de passe est désactivée. |

## Ce que mesure chaque compteur

| Compteur | Motif journald | Signification |
|---|---|---|
| Invalid user | `Invalid user ` | Tentative avec un compte qui n'existe pas. |
| Failed password / publickey | `Failed password ` / `Failed publickey ` | Échec d'authentification sur un compte existant. |
| Connexions coupées en pré-auth | `Connection closed by` / `Disconnected from` + `authenticating\|invalid user` | Le client abandonne pendant l'authentification ; souvent la 2ᵉ ligne d'une même tentative. |
| Sessions échouées | PID `sshd-session` distincts des lignes ci-dessus | Le chiffre à retenir pour « nombre de tentatives » : une tentative = une session, même si elle écrit 2 lignes. |
| Penalties | `penalty: ` | `PerSourcePenalties` (OpenSSH ≥ 9.8) coupe une IP qui se connecte sans tenter de s'authentifier : signature d'un scanner. |
| Timeouts pré-auth | `Timeout before authentication` | Connexion ouverte puis laissée sans réponse (`LoginGraceTime`). |
| Erreurs KEX | `kex_exchange_identification`, `banner exchange`… | Connexion coupée avant l'échange de clés : scan de port ou client non SSH. |
| Connexions acceptées | `Accepted publickey\|password\|…` | Connexions réussies, y compris celles de l'audit lui-même. |

## Pièges connus (déjà rencontrés)

- Depuis OpenSSH 9.8, les échecs d'authentification sont écrits par `sshd-session`, plus par `sshd`. Filtrer uniquement `_COMM=sshd` donne 0 partout.
- `journalctl -u ssh` et `journalctl _COMM=sshd-session` renvoient les **mêmes lignes** : les additionner double tous les compteurs. Le script fait une seule requête `-t sshd -t sshd-session`.
- Sur Debian, `awk` est `mawk`, qui ne gère pas les quantificateurs `{1,3}` dans les regex : ils tronquent les IP.
- Debian 12+ n'a plus `/var/log/auth.log` par défaut (pas de rsyslog) : tout est dans journald.

## Droits nécessaires

Sur chaque cible : `root`, ou un utilisateur membre du groupe `systemd-journal` (lecture des logs). Sans root, `sshd -T` peut échouer : la configuration s'affiche alors `?` et tu dois le signaler.
