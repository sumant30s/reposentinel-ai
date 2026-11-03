import time
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.rules.catalog import ORDER
from app.scanners.dependencies import parse_dependencies
from app.scanners.external import external_scan
from app.scanners.python_ast import analyze_python
from app.scanners.secrets import analyze_secrets
from app.services.intake import source_files
from app.services.osv import OSVClient, advisory_finding, merge_advisories
from app.services.risk import deduplicate, prioritize


def scan_tree(
    root: Path,
    settings: Settings,
    session: Session,
    options: dict | None = None,
    baseline: set[str] | None = None,
) -> dict:
    options = options or {}
    started = time.monotonic()
    files, warnings = source_files(root, settings, options.get("exclusions", []))
    findings = []
    if not files:
        warnings.append("No supported UTF-8 source files were discovered")
    for path, source in files:
        if path.endswith(".py"):
            found, errors = analyze_python(source, path)
            findings.extend(found)
            warnings.extend(errors)
        findings.extend(analyze_secrets(source, path))
    dependencies, dep_warnings = parse_dependencies(files)
    warnings.extend(dep_warnings)
    osv = OSVClient(session, settings.osv_cache_hours)
    try:
        for dependency in dependencies:
            if dependency["lookup_status"] == "unsupported-range":
                warnings.append(f"Unresolved version: {dependency['name']} in {dependency['file']}")
                continue
            if not settings.osv_enabled or time.monotonic() - started > settings.scan_timeout * 0.6:
                dependency["lookup_status"] = (
                    "disabled" if not settings.osv_enabled else "deadline-skipped"
                )
                continue
            advisories, status = osv.query(
                dependency["name"], dependency["version"], dependency["ecosystem"]
            )
            dependency["lookup_status"] = status
            # Store bounded normalized metadata, not arbitrary advisory HTML or full external content.
            advisories = merge_advisories(advisories)
            for advisory in advisories[:100]:
                if advisory.get("withdrawn"):
                    continue
                finding = advisory_finding(dependency, advisory)
                findings.append(finding)
                dependency["advisories"].append(
                    {
                        "id": finding.advisory_id,
                        "aliases": advisory.get("aliases", [])[:20],
                        "source_severity": finding.source_severity,
                        "cvss": finding.cvss,
                        "references": finding.references,
                    }
                )
            if len(advisories) > 100:
                dependency["lookup_status"] = "partial"
    finally:
        osv.close()
    extra, engines = external_scan(root, settings, dependencies)
    findings.extend(extra)
    items = deduplicate(findings)
    for item in items:
        prioritize(
            item,
            options.get("exposure", settings.exposure),
            options.get("critical_asset", settings.critical_asset),
        )
        item.suppressed = item.fingerprint in (baseline or set())
    items.sort(key=lambda f: (-f.priority_score, f.file, f.line or 0))
    incomplete = (
        bool(warnings)
        or any(e["status"] in {"failed", "unavailable"} for e in engines.values())
        or any(
            d["lookup_status"]
            in {
                "failed",
                "stale-cache",
                "disabled",
                "partial",
                "deadline-skipped",
                "unsupported-range",
            }
            for d in dependencies
        )
    )
    return {
        "findings": [f.model_dump() for f in items],
        "dependencies": dependencies,
        "summary": {
            "total": len(items),
            "active": sum(not f.suppressed for f in items),
            "suppressed": sum(f.suppressed for f in items),
            "severities": {
                s: sum(f.severity == s and not f.suppressed for f in items)
                for s in ["critical", "high", "medium", "low"]
            },
            "files_scanned": len(files),
            "lines_scanned": sum(len(s.splitlines()) for _, s in files),
            "duration_seconds": round(time.monotonic() - started, 3),
            "warnings": warnings,
            "engines": engines,
            "coverage": "partial" if incomplete else "completed",
            "dependency_count": len(dependencies),
            "policy": {
                "threshold": options.get("fail_on", "high"),
                "violated": any(
                    not f.suppressed and ORDER[f.priority] >= ORDER[options.get("fail_on", "high")]
                    for f in items
                ),
            },
            "notice": "A clean scan does not prove security. This scan has bounded language/rule coverage; manual review remains necessary.",
        },
    }
