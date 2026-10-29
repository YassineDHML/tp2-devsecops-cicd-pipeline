"""Tests de scripts/security_report.py : la logique du gate est elle-meme du code de securite."""
import json

import pytest
import security_report as sr


def write_report(tmp_path, data, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def zap_report(*risks):
    alerts = [
        {
            "riskcode": str(risk),
            "name": f"Alerte {i}",
            "cweid": "78",
            "count": "1",
            "instances": [{"uri": f"http://app:5000/p{i}", "param": "host"}],
        }
        for i, risk in enumerate(risks)
    ]
    return {"site": [{"@name": "http://app:5000", "alerts": alerts}]}


# --------------------------------------------------------------------------
# ZAP : c'est ce script qui applique la regle de blocage du DAST
# --------------------------------------------------------------------------
def test_zap_gate_fails_on_high_alert(tmp_path, capsys):
    path = write_report(tmp_path, zap_report(3, 2, 1))
    assert sr.main(["zap", path, "--fail-on", "high"]) == 1
    captured = capsys.readouterr()
    assert "BLOQUANT" in captured.out
    assert "Alerte 0" in captured.err


def test_zap_gate_passes_with_only_medium_and_below(tmp_path, capsys):
    path = write_report(tmp_path, zap_report(2, 2, 1, 0))
    assert sr.main(["zap", path, "--fail-on", "high"]) == 0
    assert "Gate : OK" in capsys.readouterr().out


def test_zap_gate_can_be_made_stricter(tmp_path):
    path = write_report(tmp_path, zap_report(2))
    assert sr.main(["zap", path, "--fail-on", "medium"]) == 1


def test_zap_without_fail_on_only_reports(tmp_path):
    assert sr.main(["zap", write_report(tmp_path, zap_report(3))]) == 0


@pytest.mark.parametrize("content", [None, "pas du json", json.dumps({"site": []})])
def test_gate_fails_closed_when_report_is_missing_or_empty(tmp_path, content):
    path = tmp_path / "zap.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert sr.main(["zap", str(path), "--fail-on", "high"]) == 2


# --------------------------------------------------------------------------
# Resumes des autres outils
# --------------------------------------------------------------------------
def test_bandit_summary_counts_by_severity(tmp_path, capsys):
    results = [
        {"issue_severity": sev, "issue_confidence": "HIGH", "test_id": "B602", "test_name": "x",
         "filename": "app/app.py", "line_number": n, "issue_text": "texte"}
        for n, sev in enumerate(["HIGH", "LOW", "LOW"], start=1)
    ]
    path = write_report(tmp_path, {"results": results})
    assert sr.main(["bandit", path]) == 0
    out = capsys.readouterr().out
    assert "| High | 1 |" in out and "| Low | 2 |" in out
    assert sr.main(["bandit", path, "--fail-on", "high"]) == 1


def test_pip_audit_merges_duplicate_advisories(tmp_path, capsys):
    vuln = {"id": "PYSEC-1", "aliases": ["CVE-1"], "fix_versions": ["2.0"]}
    data = {"dependencies": [
        {"name": "certifi", "version": "1.0", "vulns": [vuln, {**vuln, "fix_versions": ["2.1"]}]},
        {"name": "flask", "version": "3.0", "vulns": []},
    ]}
    path = write_report(tmp_path, data)
    assert sr.main(["pip-audit", path, "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "| High | 1 |" in out
    assert "2.0, 2.1" in out


@pytest.mark.parametrize("score, expected_exit", [(9.8, 1), (7.0, 1), (6.9, 0), (3.1, 0)])
def test_dependency_check_uses_cvss_threshold(tmp_path, score, expected_exit):
    data = {"dependencies": [{
        "fileName": "certifi:1.0",
        "vulnerabilities": [{"name": "CVE-2099-0001", "severity": "HIGH", "cvssv3": {"baseScore": score}}],
    }]}
    assert sr.main(["dependency-check", write_report(tmp_path, data), "--fail-on", "high"]) == expected_exit


def test_summary_is_appended_to_github_step_summary(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    sr.main(["zap", write_report(tmp_path, zap_report(2)), "--fail-on", "high"])
    assert "### DAST - OWASP ZAP" in summary.read_text(encoding="utf-8")
