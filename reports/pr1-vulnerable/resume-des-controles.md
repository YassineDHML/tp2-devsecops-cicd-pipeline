# PR #1 (volontairement vulnérable) : résumé des contrôles

Résumés générés par `scripts/security_report.py` à partir des rapports JSON des scanners de ce dossier (le même contenu que l'onglet *Summary* du run GitHub Actions).

### SAST - Bandit

3 constatation(s) dans le code applicatif

| Niveau | Nombre |
|---|---|
| High | 1 |
| Medium | 0 |
| Low | 2 |

**Gate : BLOQUANT** (seuil de blocage : High et plus, 1 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Severite | Confiance | Regle | Emplacement | Description |
|---|---|---|---|---|
| High | High | B602 subprocess_popen_with_shell_equals_true | app/app.py:287 | subprocess call with shell=True identified, security issue. |
| Low | High | B404 blacklist | app/app.py:15 | Consider possible security implications associated with the subprocess module. |
| Low | High | B603 subprocess_without_shell_equals_true | app/app.py:242 | subprocess call - check for execution of untrusted input. |

</details>


### SCA - pip-audit

14 dependance(s) analysee(s) (base PyPA / OSV)

| Niveau | Nombre |
|---|---|
| High | 3 |

**Gate : BLOQUANT** (seuil de blocage : High et plus, 3 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Paquet | Identifiant | Alias | Versions corrigees |
|---|---|---|---|
| certifi 2023.5.7 | PYSEC-2023-135 | GHSA-xqr8-7jwr-rhp7, CVE-2023-37920 | 2023.7.22 |
| certifi 2023.5.7 | PYSEC-2024-230 | GHSA-248v-346w-9cwc, CVE-2024-39689 | 2024.7.4 |
| certifi 2023.5.7 | PYSEC-2026-4320 | GHSA-6q48-6c7w-9gw2 | 2026.10.18, 2026.10.19 |

</details>


### SCA - OWASP Dependency-Check

14 fichier(s) analyse(s) (base NVD)

| Niveau | Nombre |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |

**Gate : BLOQUANT** (seuil de blocage : High et plus, 2 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Severite | CVSS | Vulnerabilite | Composant | Description |
|---|---|---|---|---|
| Critical | 9.8 | CVE-2023-37920 | certifi:2023.5.7 | Certifi is a curated collection of Root Certificates for validating the trustworthiness... |
| High | 7.5 | CVE-2024-39689 | certifi:2023.5.7 | Certifi is a curated collection of Root Certificates for validating the trustworthiness... |

</details>


### DAST - OWASP ZAP

cible analysee : https://app:5000, http://app:5000

| Niveau | Nombre |
|---|---|
| High | 2 |
| Medium | 4 |
| Low | 0 |
| Informational | 3 |

**Gate : BLOQUANT** (seuil de blocage : High et plus, 2 constatation(s) bloquante(s))

<details><summary>Detail des constatations</summary>

| Risque | Alerte | CWE | Instances | Exemple |
|---|---|---|---|---|
| High | Cross Site Scripting (Reflected) | CWE-79 | 1 | http://app:5000/diagnostic?host=%3C%2Fh1%3E%3CscrIpt%3Ealert%281%29%3B%3C%2Fs... |
| High | Remote OS Command Injection | CWE-78 | 1 | http://app:5000/diagnostic?host=localhost%26cat+%2Fetc%2Fpasswd%26 (param. host) |
| Medium | Absence of Anti-CSRF Tokens | CWE-352 | 5 | http://app:5000 |
| Medium | CSP: Failure to Define Directive with No Fallback | CWE-693 | 5 | http://app:5000 (param. Content-Security-Policy) |
| Medium | CSP: style-src unsafe-inline | CWE-693 | 5 | http://app:5000 (param. Content-Security-Policy) |
| Medium | HTTP Only Site | CWE-311 | 1 | http://app:5000/ |
| Informational | Authentication Request Identified | - | 1 | http://app:5000/login (param. username) |
| Informational | Session Management Response Identified | - | 2 | http://app:5000/login (param. session) |
| Informational | User Agent Fuzzer | - | 3 | http://app:5000/ (param. Header User-Agent) |

</details>


