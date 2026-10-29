#!/usr/bin/env python3
"""Resume et gate des rapports de securite du pipeline CI/CD.

Usage :
    security_report.py bandit           ci-reports/bandit.json
    security_report.py pip-audit        ci-reports/pip-audit.json
    security_report.py dependency-check ci-reports/dependency-check/dependency-check-report.json
    security_report.py zap              zap-out/zap-report.json --fail-on high

Chaque commande affiche un resume (ajoute aussi a $GITHUB_STEP_SUMMARY quand la
variable existe, ce qui alimente l'onglet "Summary" du run GitHub Actions).

L'option --fail-on rend la commande bloquante : code de sortie 1 si une
constatation atteint ce niveau. Pour Bandit, pip-audit et Dependency-Check, le
blocage est porte par les options natives des outils (voir .github/workflows/ci.yml) ;
ce script ne sert alors qu'a rendre le resultat lisible. Pour ZAP, qui n'a pas
d'option equivalente, c'est ce script qui applique la regle de blocage.

Codes de sortie : 0 = ok, 1 = seuil de blocage atteint, 2 = rapport absent ou
illisible (le gate echoue "ferme" : pas de rapport = pas de feu vert).
"""
import argparse
import json
import os
import sys
from collections import Counter

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LABELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


class ReportError(Exception):
    """Rapport introuvable ou invalide."""


def load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ReportError(f"rapport illisible : {path} ({exc})") from exc


def md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in row) + " |")
    return "\n".join(lines)


def cut(text, size=110):
    text = " ".join(str(text).split())
    return text if len(text) <= size else text[: size - 3] + "..."


# --------------------------------------------------------------------------
# Un analyseur par outil : chacun renvoie (titre, rows, blocking, details)
#   counts   : Counter {niveau numerique: nombre}
#   blocking : liste des lignes qui atteignent le seuil --fail-on
# --------------------------------------------------------------------------
def analyse_bandit(data, threshold):
    findings = []
    for item in data.get("results", []):
        level = LEVELS[item["issue_severity"].lower()]
        findings.append(
            (
                level,
                [
                    item["issue_severity"].title(),
                    item["issue_confidence"].title(),
                    f'{item["test_id"]} {item["test_name"]}',
                    f'{item["filename"]}:{item["line_number"]}',
                    cut(item["issue_text"]),
                ],
            )
        )
    headers = ["Severite", "Confiance", "Regle", "Emplacement", "Description"]
    return "SAST - Bandit", headers, findings, f"{len(data.get('results', []))} constatation(s) dans le code applicatif"


def analyse_pip_audit(data, threshold):
    merged = {}
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            # pip-audit repete parfois une meme alerte (une ligne par version corrigee) : on les fusionne
            entry = merged.setdefault(
                (dep["name"], dep["version"], vuln["id"]), {"aliases": vuln.get("aliases", []), "fixes": []}
            )
            entry["fixes"] += [fix for fix in vuln.get("fix_versions", []) if fix not in entry["fixes"]]
    # pip-audit n'expose pas de score CVSS : toute vulnerabilite connue compte comme "high"
    findings = [
        (
            LEVELS["high"],
            [f"{name} {version}", vuln_id, ", ".join(entry["aliases"]), ", ".join(entry["fixes"]) or "aucun correctif connu"],
        )
        for (name, version, vuln_id), entry in merged.items()
    ]
    headers = ["Paquet", "Identifiant", "Alias", "Versions corrigees"]
    n_deps = len(data.get("dependencies", []))
    return "SCA - pip-audit", headers, findings, f"{n_deps} dependance(s) analysee(s) (base PyPA / OSV)"


def analyse_dependency_check(data, threshold):
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            score = 0.0
            for key, field in (("cvssv4", "cvssScore"), ("cvssv3", "baseScore"), ("cvssv2", "score")):
                block = vuln.get(key) or {}
                if block.get(field) is not None:
                    score = max(score, float(block[field]))
            severity = str(vuln.get("severity", "")).lower()
            # echelle CVSS : >= 9 critique, >= 7 haute, >= 4 moyenne
            level = 4 if score >= 9 else 3 if score >= 7 else 2 if score >= 4 else 1 if score > 0 else LEVELS.get(severity, 1)
            findings.append(
                (
                    level,
                    [
                        LABELS[level],
                        score or "n/a",
                        vuln.get("name", "?"),
                        dep.get("fileName", "?"),
                        cut(vuln.get("description", ""), 90),
                    ],
                )
            )
    headers = ["Severite", "CVSS", "Vulnerabilite", "Composant", "Description"]
    n_deps = len(data.get("dependencies", []))
    return "SCA - OWASP Dependency-Check", headers, findings, f"{n_deps} fichier(s) analyse(s) (base NVD)"


def analyse_zap(data, threshold):
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            level = int(alert["riskcode"])
            instances = alert.get("instances", [])
            sample = instances[0] if instances else {}
            where = sample.get("uri", "")
            if sample.get("param"):
                where += f' (param. {sample["param"]})'
            findings.append(
                (
                    level,
                    [
                        LABELS[level],
                        alert.get("name") or alert.get("alert", "?"),
                        f'CWE-{alert["cweid"]}' if alert.get("cweid", "-1") not in ("", "-1", "0") else "-",
                        alert.get("count", len(instances)),
                        cut(where, 80),
                    ],
                )
            )
    headers = ["Risque", "Alerte", "CWE", "Instances", "Exemple"]
    sites = ", ".join(site.get("@name", "?") for site in data.get("site", [])) or "aucun site"
    if not data.get("site"):
        raise ReportError("rapport ZAP vide : aucun site analyse")
    return "DAST - OWASP ZAP", headers, findings, f"cible analysee : {sites}"


ANALYSERS = {
    "bandit": analyse_bandit,
    "pip-audit": analyse_pip_audit,
    "dependency-check": analyse_dependency_check,
    "zap": analyse_zap,
}

# Niveaux affiches dans le tableau de synthese (du plus grave au moins grave)
DISPLAYED_LEVELS = {
    "bandit": [3, 2, 1],
    "pip-audit": [3],
    "dependency-check": [4, 3, 2, 1],
    "zap": [3, 2, 1, 0],
}


def report(kind, path, fail_on):
    data = load_json(path)
    threshold = LEVELS[fail_on] if fail_on else None
    title, headers, findings, scope = ANALYSERS[kind](data, threshold)

    counts = Counter(level for level, _ in findings)
    levels = DISPLAYED_LEVELS[kind]
    summary = md_table(["Niveau", "Nombre"], [[LABELS[lvl], counts.get(lvl, 0)] for lvl in levels])

    blocking = [row for level, row in findings if threshold is not None and level >= threshold]
    ordered = [row for _, row in sorted(findings, key=lambda item: -item[0])]

    out = [f"### {title}", "", scope, "", summary, ""]
    if threshold is not None:
        verdict = "BLOQUANT" if blocking else "OK"
        out.append(f"**Gate : {verdict}** (seuil de blocage : {LABELS[threshold]} et plus, {len(blocking)} constatation(s) bloquante(s))")
        out.append("")
    if ordered:
        out += ["<details><summary>Detail des constatations</summary>", "", md_table(headers, ordered), "", "</details>", ""]
    return "\n".join(out), blocking, headers, ordered


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("kind", choices=sorted(ANALYSERS))
    parser.add_argument("report", help="chemin du rapport JSON de l'outil")
    parser.add_argument("--fail-on", choices=sorted(LEVELS, key=LEVELS.get), help="niveau a partir duquel le gate echoue")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        text, blocking, headers, ordered = report(args.kind, args.report, args.fail_on)
    except ReportError as exc:
        print(f"ERREUR : {exc}", file=sys.stderr)
        print("Le gate echoue : sans rapport exploitable, la verification ne peut pas etre validee.", file=sys.stderr)
        return 2

    print(text)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    if blocking:
        print(f"\nECHEC : {len(blocking)} constatation(s) atteignent le seuil '{args.fail_on}'.", file=sys.stderr)
        for row in blocking[:15]:
            print("  - " + " | ".join(str(cell) for cell in row), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
