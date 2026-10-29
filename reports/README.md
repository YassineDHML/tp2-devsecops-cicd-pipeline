# Preuves d'exécution

Rapports et journaux produits par le pipeline lors de la validation du TP2 (voir [RAPPORT.md, §7](../RAPPORT.md#7-validation--pull-request-vulnérable-puis-corrigée)). Ce sont les artefacts des runs GitHub Actions, copiés ici parce que les artefacts expirent après 90 jours.

| Dossier | Run | Contenu |
|---|---|---|
| `pr1-vulnerable/` | [40794743364](https://github.com/YassineDHML/tp2-devsecops-cicd-pipeline/actions/runs/40794743364) : pull request n° 1, commit `0285a71` | pipeline **en échec** : Bandit, pip-audit, Dependency-Check et ZAP détectent les failles ; Security gate en échec |
| `pr2-fixed/` | [40794746678](https://github.com/YassineDHML/tp2-devsecops-cicd-pipeline/actions/runs/40794746678) : pull request n° 2, commit `c93889e` | pipeline **vert** : aucune alerte bloquante |
| `pr2-faux-positif/` | [40796652999](https://github.com/YassineDHML/tp2-devsecops-cicd-pipeline/actions/runs/40796652999) : pull request n° 2, commit `fe474eb` | DAST **bloqué par un faux positif** de ZAP (injection SQL signalée sur `/preferences`, paramètre `theme`) : preuves du triage décrit au [§5.6 du rapport](../RAPPORT.md#56-un-faux-positif-rencontré--triage-et-filtre-ciblé) |
| `main-release/` | [40793697905](https://github.com/YassineDHML/tp2-devsecops-cicd-pipeline/actions/runs/40793697905) : *push* sur `main`, commit `2b88fac` | publication de l'image sur GHCR après un Security gate vert |

Dans `pr1-vulnerable/` et `pr2-fixed/` :

| Fichier ou dossier | Contenu |
|---|---|
| `checks-de-la-pr.txt` | sortie de `gh pr checks` : résultat et durée de chaque job |
| `resume-des-controles.md` | résumés générés par `scripts/security_report.py` (le contenu de l'onglet *Summary*) |
| `journaux-etapes-en-echec.txt` | *(PR n° 1 seulement)* journaux des étapes en échec |
| `rapport-sast-bandit/` | `bandit.json`, `bandit.html` |
| `rapport-sca-pip-audit/` | `pip-audit.json` |
| `rapport-sca-dependency-check/dependency-check/` | `dependency-check-report.json`, `dependency-check-report.html` |
| `rapport-dast-zap/` | `zap-report.json`, `zap-report.html`, `zap-run.log` (journal du plan ZAP), `app.log` (journal de l'application) |
| `rapport-tests/` | `junit.xml`, `coverage.xml` |

Les rapports HTML s'ouvrent directement dans un navigateur.
