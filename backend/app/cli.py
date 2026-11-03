import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.database import Base, make_engine
from app.reports.render import render_report
from app.rules.catalog import ORDER
from app.services.intake import download_repository, extract_archive, snapshot_local
from app.services.pipeline import scan_tree


def policy_exit(result: dict, threshold: str) -> int:
    engines = result["summary"]["engines"]
    if any(e["status"] in {"failed", "unavailable"} for e in engines.values()) or any(
        d["lookup_status"] in {"failed", "partial", "deadline-skipped", "stale-cache"}
        for d in result["dependencies"]
    ):
        return 2
    return (
        1
        if any(
            not f["suppressed"] and ORDER[f["priority"]] >= ORDER[threshold]
            for f in result["findings"]
        )
        else 0
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reposentinel", description="Scan authorized source without executing it"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("source")
    scan.add_argument(
        "--format", choices=["console", "json", "html", "sarif", "csv"], default="console"
    )
    scan.add_argument("--output", type=Path)
    scan.add_argument("--fail-on", choices=list(ORDER), default="high")
    scan.add_argument("--baseline", type=Path)
    scan.add_argument(
        "--offline",
        action="store_true",
        help="Disable advisory network requests; coverage is explicitly partial when dependencies exist",
    )
    scan.add_argument("--engines", default="bandit,detect-secrets,semgrep,pip-audit")
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--exposure", choices=["internal", "internet"], default="internal")
    scan.add_argument("--critical-asset", action="store_true")
    args = parser.parse_args(argv)
    try:
        settings = Settings(osv_enabled=not args.offline, engines=args.engines)
        baseline: set[str] = set()
        if args.baseline:
            document = json.loads(args.baseline.read_text(encoding="utf-8"))
            if (
                document.get("version") != 1
                or not isinstance(document.get("fingerprints"), list)
                or not all(
                    isinstance(f, str) and re.fullmatch(r"[a-f0-9]{64}", f)
                    for f in document["fingerprints"]
                )
            ):
                raise ValueError("Invalid baseline format")
            baseline = set(document["fingerprints"])
        with tempfile.TemporaryDirectory(prefix="reposentinel-") as folder:
            root = Path(folder) / "source"
            root.mkdir()
            warnings = []
            if args.source.startswith("https://"):
                extract_archive(download_repository(args.source, settings), root, settings)
            else:
                warnings = snapshot_local(Path(args.source), root, settings, args.exclude)
            engine = make_engine("sqlite://")
            Base.metadata.create_all(
                engine
            )  # Ephemeral CLI cache only; hosted databases use Alembic.
            with Session(engine) as session:
                result = scan_tree(
                    root,
                    settings,
                    session,
                    {
                        "exposure": args.exposure,
                        "critical_asset": args.critical_asset,
                        "fail_on": args.fail_on,
                    },
                    baseline,
                )
            result["summary"]["warnings"].extend(warnings)
            if warnings:
                result["summary"]["coverage"] = "partial"
            if args.format == "console":
                content = (
                    json.dumps(result["summary"], indent=2)
                    + "\n"
                    + "\n".join(
                        f"{f['priority'].upper():8} {f['rule_id']:12} {f['file']}:{f['line'] or '-'} {f['title']}"
                        for f in result["findings"]
                    )
                )
            else:
                content, _ = render_report(result, args.format)
            if args.output:
                args.output.write_text(content, encoding="utf-8")
            else:
                print(content)
            return policy_exit(result, args.fail_on)
    except Exception as exc:
        print(
            f"Scan could not complete ({type(exc).__name__}). Verify source, limits, baseline and configuration.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
