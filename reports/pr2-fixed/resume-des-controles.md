# PR #2 (corrigée) : résumé des contrôles

Résumés générés par `scripts/security_report.py` à partir des rapports JSON des scanners de ce dossier (le même contenu que l'onglet *Summary* du run GitHub Actions).

### SAST - Bandit

2 constatation(s) dans le code applicatif

| Niveau | Nombre |
|---|---|
| High | 0 |
| Medium | 0 |
| Low | 2 |

**Gate : OK** (seuil de blocage : High et plus, 0 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Severite | Confiance | Regle | Emplacement | Description |
|---|---|---|---|---|
| Low | High | B404 blacklist | app/app.py:16 | Consider possible security implications associated with the subprocess module. |
| Low | High | B603 subprocess_without_shell_equals_true | app/app.py:243 | subprocess call - check for execution of untrusted input. |

</details>


### SCA - pip-audit

14 dependance(s) analysee(s) (base PyPA / OSV)

| Niveau | Nombre |
|---|---|
| High | 0 |

**Gate : OK** (seuil de blocage : High et plus, 0 constatation(s) bloquante(s))


### SCA - OWASP Dependency-Check

14 fichier(s) analyse(s) (base NVD)

| Niveau | Nombre |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

**Gate : OK** (seuil de blocage : High et plus, 0 constatation(s) bloquante(s))


### DAST - OWASP ZAP

cible analysee : https://app:5000, http://app:5000

| Niveau | Nombre |
|---|---|
| High | 0 |
| Medium | 4 |
| Low | 0 |
| Informational | 3 |

**Gate : OK** (seuil de blocage : High et plus, 0 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Risque | Alerte | CWE | Instances | Exemple |
|---|---|---|---|---|
| Medium | Absence of Anti-CSRF Tokens | CWE-352 | 5 | http://app:5000 |
| Medium | CSP: Failure to Define Directive with No Fallback | CWE-693 | 5 | http://app:5000 (param. Content-Security-Policy) |
| Medium | CSP: style-src unsafe-inline | CWE-693 | 5 | http://app:5000 (param. Content-Security-Policy) |
| Medium | HTTP Only Site | CWE-311 | 1 | http://app:5000/ |
| Informational | Authentication Request Identified | - | 1 | http://app:5000/login (param. username) |
| Informational | Session Management Response Identified | - | 2 | http://app:5000/login (param. session) |
| Informational | User Agent Fuzzer | - | 3 | http://app:5000/ (param. Header User-Agent) |

</details>


