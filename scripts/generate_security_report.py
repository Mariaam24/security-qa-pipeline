#!/usr/bin/env python3
"""
Génère un rapport de sécurité structuré (Markdown + JSON) en consolidant :
- Les résultats des tests pytest de sécurité (auth, IDOR, injections)
- Les résultats du scan OWASP ZAP (baseline et/ou full scan)

Mapping automatique vers l'OWASP Top 10 (2021) selon le fichier de test
ou l'identifiant d'alerte ZAP (pluginId).

Usage :
    python scripts/generate_security_report.py
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

# Mapping pluginId ZAP -> OWASP Top 10 2021 (sous-ensemble courant, à enrichir)
ZAP_OWASP_MAPPING = {
    "40018": "A03:2021 - Injection (SQLi)",
    "40012": "A03:2021 - Injection (XSS réfléchi)",
    "40014": "A03:2021 - Injection (XSS persistant)",
    "10202": "A07:2021 - Identification and Authentication Failures",
    "10035": "A02:2021 - Cryptographic Failures",
    "10098": "A05:2021 - Security Misconfiguration",
    "90033": "A08:2021 - Software and Data Integrity Failures",
    "10063": "A05:2021 - Security Misconfiguration (en-têtes manquants)",
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def run_pytest_and_collect(junit_path: str) -> dict:
    """Exécute pytest avec sortie JUnit XML puis parse les résultats."""
    subprocess.run(
        ["pytest", "tests/", f"--junitxml={junit_path}", "-q"],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )
    return parse_junit(junit_path)


def parse_junit(path: str) -> dict:
    import xml.etree.ElementTree as ET

    if not os.path.exists(path):
        return {"total": 0, "failed": 0, "cases": []}

    tree = ET.parse(path)
    root = tree.getroot()
    cases = []
    failed = 0
    for testcase in root.iter("testcase"):
        name = testcase.get("name")
        classname = testcase.get("classname", "")
        failure = testcase.find("failure")
        status = "FAIL" if failure is not None else "PASS"
        if failure is not None:
            failed += 1
        cases.append(
            {
                "name": name,
                "file": classname,
                "status": status,
                "message": failure.get("message") if failure is not None else "",
                "owasp": map_test_to_owasp(classname),
            }
        )
    return {"total": len(cases), "failed": failed, "cases": cases}


def map_test_to_owasp(classname: str) -> str:
    if "auth" in classname:
        return "A07:2021 - Identification and Authentication Failures"
    if "idor" in classname:
        return "A01:2021 - Broken Access Control"
    if "injection" in classname:
        return "A03:2021 - Injection"
    return "Non mappé"


def load_zap_json(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            findings.append(
                {
                    "name": alert.get("name"),
                    "risk": alert.get("riskdesc", "").split(" ")[0],
                    "pluginid": alert.get("pluginid"),
                    "owasp": ZAP_OWASP_MAPPING.get(
                        alert.get("pluginid"), "Voir OWASP Top 10 - à classer manuellement"
                    ),
                    "desc": (alert.get("desc", "") or "").replace("\n", " ")[:200],
                    "solution": (alert.get("solution", "") or "").replace("\n", " ")[:200],
                    "instances": len(alert.get("instances", [])),
                }
            )
    findings.sort(key=lambda a: SEVERITY_ORDER.get(a["risk"], 0), reverse=True)
    return findings


def build_markdown_report(pytest_results: dict, zap_findings: list) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# 🛡️ Rapport de sécurité — Security QA Pipeline",
        f"\nGénéré le {now}\n",
        "## 1. Résumé exécutif",
        f"- Tests de sécurité exécutés : **{pytest_results['total']}**",
        f"- Tests échoués (vulnérabilités confirmées) : **{pytest_results['failed']}**",
        f"- Alertes ZAP détectées : **{len(zap_findings)}**",
    ]

    critical_or_high = [f for f in zap_findings if f["risk"] in ("Critical", "High")]
    lines.append(f"- Alertes ZAP critiques/élevées : **{len(critical_or_high)}**\n")

    lines.append("## 2. Résultats des tests pytest (auth / IDOR / injections)\n")
    lines.append("| Test | Fichier | Statut | OWASP Top 10 | Détail |")
    lines.append("|---|---|---|---|---|")
    for case in pytest_results["cases"]:
        status_icon = "❌ FAIL" if case["status"] == "FAIL" else "✅ PASS"
        detail = (case["message"] or "").replace("|", "/")[:120]
        lines.append(
            f"| {case['name']} | {case['file']} | {status_icon} | {case['owasp']} | {detail} |"
        )

    lines.append("\n## 3. Résultats du scan OWASP ZAP\n")
    if zap_findings:
        lines.append("| Vulnérabilité | Gravité | OWASP Top 10 | Instances | Preuve | Correction recommandée |")
        lines.append("|---|---|---|---|---|---|")
        for f in zap_findings:
            lines.append(
                f"| {f['name']} | {f['risk']} | {f['owasp']} | {f['instances']} | {f['desc']} | {f['solution']} |"
            )
    else:
        lines.append("_Aucun rapport ZAP JSON trouvé — exécuter `docker compose run zap-baseline` d'abord._")

    lines.append("\n## 4. Verdict du pipeline\n")
    has_critical = pytest_results["failed"] > 0 or len(critical_or_high) > 0
    if has_critical:
        lines.append("🔴 **BUILD EN ÉCHEC** : au moins une vulnérabilité critique/élevée détectée.")
    else:
        lines.append("🟢 **BUILD OK** : aucune vulnérabilité critique/élevée détectée.")

    return "\n".join(lines)


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    junit_path = os.path.join(REPORTS_DIR, "pytest-results.xml")

    if "--skip-pytest" not in sys.argv:
        pytest_results = run_pytest_and_collect(junit_path)
    else:
        pytest_results = parse_junit(junit_path)

    zap_json_candidates = [
        os.path.join(REPORTS_DIR, "zap-full-report.json"),
        os.path.join(REPORTS_DIR, "zap-baseline-report.json"),
    ]
    zap_findings = []
    for candidate in zap_json_candidates:
        if os.path.exists(candidate):
            zap_findings = load_zap_json(candidate)
            break

    report_md = build_markdown_report(pytest_results, zap_findings)
    out_path = os.path.join(REPORTS_DIR, "security-report.md")
    with open(out_path, "w") as f:
        f.write(report_md)

    print(f"Rapport généré : {out_path}")

    # Code de sortie non-zéro si vulnérabilité critique -> utilisé comme gate CI
    critical_or_high = [f for f in zap_findings if f["risk"] in ("Critical", "High")]
    if pytest_results["failed"] > 0 or critical_or_high:
        print("::error:: Vulnérabilités critiques détectées — build en échec.")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
