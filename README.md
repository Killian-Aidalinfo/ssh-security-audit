# ssh-security-audit — skill Hermes Agent

Skill pour [Hermes Agent](https://hermes-agent.nousresearch.com) qui fiabilise l'audit des tentatives de connexion SSH sur un parc de serveurs.

Le modèle ne compte rien lui-même : des scripts lisent journald sur chaque machine, sortent du JSON, et un générateur de rapport calcule tableaux, période couverte, corrélations par IP et points d'attention. Le `SKILL.md` impose ensuite des règles d'interprétation (période commune, zéros justifiés, corrélation prouvée par IP et horaires).

## Contenu

| Fichier | Rôle |
|---|---|
| `SKILL.md` | Procédure et règles d'interprétation pour l'agent |
| `scripts/ssh_audit.sh` | Exécuté sur une machine cible : compteurs, IP, période, `sshd -T`, fail2ban → une ligne JSON |
| `scripts/fleet_audit.sh` | Lance `ssh_audit.sh` en parallèle sur plusieurs machines via SSH → JSONL |
| `scripts/report.py` | JSONL → rapport Markdown (aucune dépendance hors bibliothèque standard) |

## Installation dans Hermes (Docker)

```bash
git clone https://github.com/Killian-Aidalinfo/ssh-security-audit.git
docker cp ssh-security-audit hermes:/opt/data/skills/devops/ssh-security-audit
docker exec -u root hermes chown -R hermes:hermes /opt/data/skills/devops/ssh-security-audit
docker restart hermes
```

L'agent doit pouvoir se connecter en SSH aux machines auditées depuis le conteneur (clé dans `/opt/data/home/.ssh` ou passée avec `-i`).

## Utilisation manuelle

```bash
printf 'root@203.0.113.10\nroot@203.0.113.11\n' > hosts.txt
scripts/fleet_audit.sh -f hosts.txt --since "24 hours ago" -i ~/.ssh/ma_cle > audit.jsonl
python3 scripts/report.py audit.jsonl
```

Droits requis sur les cibles : `root`, ou un utilisateur du groupe `systemd-journal` (la configuration `sshd -T` sera alors peut-être indisponible).

Testé sur Debian 13 (OpenSSH ≥ 9.8, journald, mawk).
