import shutil
from datetime import timedelta

from sqlalchemy import select, update

from app.core.config import Settings
from app.models.database import Dependency, Finding, Scan, Suppression, now, sessions
from app.services.intake import download_repository, extract_archive, snapshot_local
from app.services.pipeline import scan_tree


def claim_job(session, timeout: int) -> str | None:
    candidate = session.scalar(
        select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)
    )
    if not candidate:
        return None
    result = session.execute(
        update(Scan)
        .where(Scan.id == candidate, Scan.status == "queued")
        .values(
            status="running",
            started_at=now(),
            lease_until=now() + timedelta(seconds=timeout + 30),
            attempts=Scan.attempts + 1,
        )
    )
    session.commit()
    return candidate if result.rowcount == 1 else None


def fail_job(settings: Settings, scan_id: str, message: str) -> None:
    with sessions(settings.database_url)() as session:
        scan = session.get(Scan, scan_id)
        if scan and scan.status == "running":
            scan.status, scan.error, scan.finished_at = "failed", message, now()
            session.commit()
    shutil.rmtree(settings.data_dir / "jobs" / scan_id, ignore_errors=True)


def recover_jobs(settings: Settings) -> int:
    with sessions(settings.database_url)() as session:
        stale = list(
            session.scalars(
                select(Scan.id).where(Scan.status == "running", Scan.lease_until < now())
            )
        )
    for scan_id in stale:
        fail_job(
            settings,
            scan_id,
            "Worker lease expired. Start a fresh scan; partial findings were not committed.",
        )
    return len(stale)


def execute_job(settings: Settings, scan_id: str) -> None:
    job = (settings.data_dir / "jobs" / scan_id).resolve()
    tree = job / "source"
    tree.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with sessions(settings.database_url)() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status != "running":
                return
            source = scan.options["source"]
            initial_warnings = []
            if source == "demo":
                initial_warnings = snapshot_local(
                    settings.sample_dir, tree, settings, scan.options.get("exclusions", [])
                )
            elif source == "upload":
                extract_archive((job / "input.zip").read_bytes(), tree, settings)
            else:
                extract_archive(download_repository(scan.options["url"], settings), tree, settings)
                children = list(tree.iterdir())
                if len(children) == 1 and children[0].is_dir():
                    tree = children[0]
            # Normalize filtered source into another tree so every external engine sees the same scope.
            normalized = job / "normalized"
            normalized.mkdir(mode=0o700)
            initial_warnings.extend(
                snapshot_local(tree, normalized, settings, scan.options.get("exclusions", []))
            )
            baseline = set(
                session.scalars(
                    select(Suppression.fingerprint).where(
                        Suppression.repository_id == scan.repository_id
                    )
                )
            )
            result = scan_tree(normalized, settings, session, scan.options, baseline)
            result["summary"]["warnings"].extend(initial_warnings)
            if initial_warnings:
                result["summary"]["coverage"] = "partial"
            for item in result["findings"]:
                session.add(
                    Finding(
                        scan_id=scan_id,
                        fingerprint=item["fingerprint"],
                        rule_id=item["rule_id"],
                        severity=item["severity"],
                        priority=item["priority"],
                        file=item["file"],
                        line=item["line"],
                        payload=item,
                        suppressed=item["suppressed"],
                    )
                )
            for dependency in result["dependencies"]:
                session.add(Dependency(scan_id=scan_id, payload=dependency))
            scan.summary = result["summary"]
            scan.status = result["summary"]["coverage"]
            scan.finished_at = now()
            session.commit()
    except Exception as exc:
        # Exception text can contain source, file paths, secrets or remote responses. Store only its type.
        fail_job(
            settings,
            scan_id,
            f"Scan failed ({type(exc).__name__}). Check bounded inputs and engine configuration.",
        )
    finally:
        shutil.rmtree(job, ignore_errors=True)
