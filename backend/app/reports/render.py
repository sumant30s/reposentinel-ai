import csv
import html
import io
import json
from urllib.parse import quote


def csv_safe(value: object) -> str:
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def render_report(data: dict, format: str) -> tuple[str, str]:
    findings = data.get("findings", [])
    if format == "json":
        return json.dumps(data, indent=2), "application/json"
    if format == "csv":
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        fields = [
            "rule_id",
            "file",
            "line",
            "severity",
            "priority",
            "confidence",
            "title",
            "remediation",
            "suppressed",
        ]
        writer.writerow(fields)
        for f in findings:
            writer.writerow([csv_safe(f.get(k)) for k in fields])
        return buffer.getvalue(), "text/csv"
    if format == "html":
        rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(f.get(k, '')))}</td>"
                for k in ["severity", "priority", "file", "line", "title", "remediation"]
            )
            + "</tr>"
            for f in findings
        )
        return (
            f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RepoSentinel security report</title><style>body{{font:16px system-ui;margin:2rem;color:#172d38}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d6e0e3;padding:12px;text-align:left}}h1{{color:#087b68}}tr:nth-child(even){{background:#f3f7f6}}</style><h1>RepoSentinel AI · Security report</h1><p>Potential findings require human review. A clean scan does not prove security.</p><pre>{html.escape(json.dumps(data.get("summary", {}), indent=2))}</pre><table><thead><tr><th>Severity</th><th>Priority</th><th>File</th><th>Line</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table></html>""",
            "text/html",
        )
    if format == "sarif":
        rules = {
            f["rule_id"]: {
                "id": f["rule_id"],
                "shortDescription": {"text": f["title"]},
                "help": {"text": f["remediation"]},
            }
            for f in findings
        }
        results = []
        for f in findings:
            location = {"artifactLocation": {"uri": quote(f["file"], safe="/")}}
            if f.get("line"):
                location["region"] = {"startLine": f["line"]}
            result = {
                "ruleId": f["rule_id"],
                "level": "error"
                if f["priority"] in {"critical", "high"}
                else "warning"
                if f["priority"] == "medium"
                else "note",
                "message": {"text": f["description"]},
                "locations": [{"physicalLocation": location}],
                "partialFingerprints": {"reposentinel/v1": f["fingerprint"]},
                "properties": {"confidence": f["confidence"], "priorityScore": f["priority_score"]},
            }
            if f.get("suppressed"):
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": "Suppressed by reviewed baseline or recorded decision",
                    }
                ]
            results.append(result)
        report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RepoSentinel AI",
                            "version": "0.1.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {"executionSuccessful": data.get("summary", {}).get("coverage") != "failed"}
                    ],
                }
            ],
        }
        return json.dumps(report, indent=2), "application/sarif+json"
    raise ValueError("Unsupported report format")
