import hashlib
import json
import shutil
import time
from collections import deque
from secrets import compare_digest
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.service import explain
from app.core.config import Settings
from app.models.database import Dependency, Finding, Preference, Repository, Scan, Suppression, uid
from app.reports.render import render_report
from app.rules.catalog import ORDER
from app.schemas.contracts import (
    ExplainRequest,
    Explanation,
    FindingData,
    Preferences,
    ScanRequest,
    ScanView,
    SuppressRequest,
)
from app.services.intake import IntakeError, extract_archive, repository_slug


def config(request: Request) -> Settings:
    return request.app.state.settings


def database(request: Request):
    with request.app.state.sessions() as session:
        yield session


DB = Annotated[Session, Depends(database)]
CONFIG = Annotated[Settings, Depends(config)]


def authenticated(
    request: Request, settings: CONFIG, authorization: Annotated[str | None, Header()] = None
) -> None:
    configured = settings.api_token.get_secret_value()
    if len(configured) < 32:
        raise HTTPException(503, "Set RS_API_TOKEN to a random value of at least 32 characters")
    supplied = (
        authorization.removeprefix("Bearer ")
        if authorization and authorization.startswith("Bearer ")
        else ""
    )
    if not compare_digest(supplied.encode(), configured.encode()):
        raise HTTPException(
            401, "Invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"}
        )
    if request.method in {"POST", "PUT", "DELETE"}:
        events: deque = request.app.state.rate_events
        current = time.monotonic()
        while events and current - events[0] > 60:
            events.popleft()
        if len(events) >= settings.rate_limit_per_minute:
            raise HTTPException(
                429,
                "Mutation rate limit reached; try again in one minute",
                headers={"Retry-After": "60"},
            )
        events.append(current)


router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(authenticated)],
    responses={
        401: {"description": "Bearer token required"},
        404: {"description": "Resource not found"},
        429: {"description": "Rate limit reached"},
    },
)


def get_scan(session: Session, scan_id: str) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def scan_view(session: Session, scan: Scan) -> dict:
    repo = session.get(Repository, scan.repository_id)
    return {
        "id": scan.id,
        "repository_id": scan.repository_id,
        "name": repo.name if repo else "Repository",
        "status": scan.status,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "summary": scan.summary,
        "error": scan.error,
    }


def finding_view(finding: Finding) -> dict:
    return {
        **finding.payload,
        "id": finding.id,
        "scan_id": finding.scan_id,
        "suppressed": finding.suppressed,
    }


def preferences(session: Session, settings: Settings) -> dict:
    row = session.get(Preference, 1)
    return (
        row.payload
        if row
        else Preferences(
            exposure=settings.exposure,
            critical_asset=settings.critical_asset,
            exclusions=settings.exclusions,
        ).model_dump()
    )


def enqueue(
    session: Session,
    settings: Settings,
    source: str,
    name: str,
    options: dict,
    scan_id: str | None = None,
) -> Scan:
    pending = (
        session.scalar(
            select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"]))
        )
        or 0
    )
    if pending >= settings.max_pending:
        raise HTTPException(429, "Scan queue is full")
    repo = session.scalar(select(Repository).where(Repository.source == source))
    if repo is None:
        repo = Repository(name=name, source=source)
        session.add(repo)
        session.flush()
    scan = Scan(
        id=scan_id or uid(),
        repository_id=repo.id,
        options={**preferences(session, settings), **options},
    )
    session.add(scan)
    session.commit()
    return scan


@router.post("/scans", status_code=202, response_model=ScanView)
def create_scan(body: ScanRequest, session: DB, settings: CONFIG):
    if body.source == "git":
        if not body.authorized:
            raise HTTPException(422, "Confirm you are authorized to scan this repository")
        try:
            slug = repository_slug(body.url or "")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        allowed = {s.strip().lower() for s in settings.allowed_repos.split(",") if s.strip()}
        if slug.lower() not in allowed:
            raise HTTPException(
                403, "Repository is not in the administrator's RS_ALLOWED_REPOS allowlist"
            )
        scan = enqueue(
            session,
            settings,
            f"https://github.com/{slug}",
            slug,
            {"source": "git", "url": f"https://github.com/{slug}"},
        )
    else:
        scan = enqueue(
            session, settings, "builtin:demo", "Demo · intentionally vulnerable", {"source": "demo"}
        )
    return scan_view(session, scan)


@router.post("/scans/upload", status_code=202, response_model=ScanView)
async def upload_scan(request: Request, session: DB, settings: CONFIG, authorized: bool = False):
    """Send raw application/zip bytes. The body is bounded before extraction; multipart is not used."""
    if not authorized:
        raise HTTPException(422, "Confirm authorization using ?authorized=true")
    if request.headers.get("content-type", "").split(";")[0] != "application/zip":
        raise HTTPException(415, "Send raw application/zip bytes")
    blob = bytearray()
    async for chunk in request.stream():
        blob.extend(chunk)
        if len(blob) > settings.max_archive_bytes:
            raise HTTPException(413, "Archive exceeds compressed size limit")
    scan_id = uid()
    job = settings.data_dir / "jobs" / scan_id
    job.mkdir(parents=True, mode=0o700)
    try:
        # Validate before queueing. Extraction does not import or execute repository code.
        extract_archive(bytes(blob), job / "validation", settings)
        shutil.rmtree(job / "validation")
        (job / "input.zip").write_bytes(blob)
        (job / "input.zip").chmod(0o600)
        identity = hashlib.sha256(blob).hexdigest()
        scan = enqueue(
            session,
            settings,
            f"upload:{identity}",
            "Uploaded source archive",
            {"source": "upload"},
            scan_id,
        )
        return scan_view(session, scan)
    except (IntakeError, OSError) as exc:
        shutil.rmtree(job, ignore_errors=True)
        raise HTTPException(
            422, "Invalid archive: unsafe path, special file, size limit or ZIP format"
        ) from exc
    except HTTPException:
        shutil.rmtree(job, ignore_errors=True)
        raise


@router.get("/scans", response_model=list[ScanView])
def list_scans(session: DB, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    return [
        scan_view(session, s)
        for s in session.scalars(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        )
    ]


@router.get("/scans/{scan_id}", response_model=ScanView)
def read_scan(scan_id: str, session: DB):
    return scan_view(session, get_scan(session, scan_id))


@router.get("/scans/{scan_id}/findings", response_model=list[dict])
def read_findings(
    scan_id: str,
    session: DB,
    severity: str | None = None,
    rule: str | None = None,
    language: str | None = None,
    q: str = Query("", max_length=200),
    include_suppressed: bool = True,
):
    get_scan(session, scan_id)
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if rule:
        query = query.where(Finding.rule_id == rule)
    if not include_suppressed:
        query = query.where(Finding.suppressed.is_(False))
    results = [finding_view(f) for f in session.scalars(query)]
    return sorted(
        [
            f
            for f in results
            if (not language or f["language"] == language)
            and q.lower() in f"{f['file']} {f['title']} {f['rule_id']}".lower()
        ],
        key=lambda f: -f["priority_score"],
    )


@router.get("/scans/{scan_id}/dependencies", response_model=list[dict])
def read_dependencies(scan_id: str, session: DB):
    get_scan(session, scan_id)
    return [
        d.payload for d in session.scalars(select(Dependency).where(Dependency.scan_id == scan_id))
    ]


@router.get("/scans/{scan_id}/summary", response_model=dict)
def read_summary(scan_id: str, session: DB):
    return get_scan(session, scan_id).summary


@router.get("/scans/{scan_id}/report")
def download_report(
    scan_id: str, session: DB, format: str = Query("json", pattern="^(json|html|sarif|csv)$")
):
    scan = get_scan(session, scan_id)
    if scan.status not in {"completed", "partial"}:
        raise HTTPException(409, "Report is available after a scan finishes")
    data = {
        "scan": scan_view(session, scan),
        "summary": scan.summary,
        "findings": read_findings(scan_id, session, q=""),
        "dependencies": read_dependencies(scan_id, session),
    }
    content, mime = render_report(data, format)
    return Response(
        content,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="reposentinel-{scan_id}.{format}"'},
    )


@router.get("/scans/{scan_id}/compare/{other_id}", response_model=dict)
def compare_scans(scan_id: str, other_id: str, session: DB):
    current, previous = get_scan(session, scan_id), get_scan(session, other_id)
    if current.repository_id != previous.repository_id:
        raise HTTPException(422, "Compare scans of the same repository")
    if any(s.status not in {"completed", "partial"} for s in [current, previous]):
        raise HTTPException(409, "Both scans must be finished")
    new = {
        f.fingerprint for f in session.scalars(select(Finding).where(Finding.scan_id == scan_id))
    }
    old = {
        f.fingerprint for f in session.scalars(select(Finding).where(Finding.scan_id == other_id))
    }
    return {
        "new": sorted(new - old),
        "resolved": sorted(old - new),
        "unchanged": len(new & old),
        "notice": "Line-based fingerprints can change when code moves; differences require review.",
    }


@router.post("/findings/{finding_id}/explain", response_model=Explanation)
def explain_finding(finding_id: str, body: ExplainRequest, session: DB, settings: CONFIG):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    try:
        return explain(
            FindingData.model_validate(finding.payload),
            settings,
            body.use_ai,
            body.consent_external,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


@router.post("/findings/{finding_id}/suppress", response_model=dict)
def suppress_finding(finding_id: str, body: SuppressRequest, session: DB):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    scan = get_scan(session, finding.scan_id)
    session.add(
        Suppression(
            repository_id=scan.repository_id, fingerprint=finding.fingerprint, reason=body.reason
        )
    )
    finding.suppressed = True
    # Keep the current scan's dashboard counters consistent with its finding state.
    session.flush()
    rows = list(session.scalars(select(Finding).where(Finding.scan_id == scan.id)))
    scan.summary = {
        **scan.summary,
        "active": sum(not f.suppressed for f in rows),
        "suppressed": sum(f.suppressed for f in rows),
        "severities": {
            s: sum(f.severity == s and not f.suppressed for f in rows)
            for s in ["critical", "high", "medium", "low"]
        },
    }
    threshold = scan.options.get("fail_on", "high")
    scan.summary = {
        **scan.summary,
        "policy": {
            "threshold": threshold,
            "violated": any(
                not f.suppressed and ORDER[f.priority] >= ORDER[threshold] for f in rows
            ),
        },
    }
    session.commit()
    return {"suppressed": True, "fingerprint": finding.fingerprint}


@router.get("/scans/{scan_id}/baseline")
def baseline(scan_id: str, session: DB):
    get_scan(session, scan_id)
    rows = session.scalars(
        select(Finding).where(Finding.scan_id == scan_id, Finding.suppressed.is_(True))
    )
    return Response(
        json.dumps({"version": 1, "fingerprints": [f.fingerprint for f in rows]}, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="reposentinel-baseline.json"'},
    )


@router.get("/settings", response_model=dict)
def read_settings(session: DB, settings: CONFIG):
    return {
        **preferences(session, settings),
        "ai_provider": settings.ai_provider,
        "ai_model": settings.ai_model,
        "ai_external": settings.ai_provider == "openai-compatible",
        "allowed_repos": settings.allowed_repos,
        "max_archive_mb": settings.max_archive_bytes // (1024 * 1024),
        "engines": settings.engines,
        "deployment_mode": "single-owner",
        "ai_payload": "Rule catalog metadata only. Source, filenames and evidence are never transmitted.",
    }


@router.put("/settings", response_model=Preferences)
def update_settings(body: Preferences, session: DB):
    row = session.get(Preference, 1)
    if row:
        row.payload = body.model_dump()
    else:
        session.add(Preference(id=1, payload=body.model_dump()))
    session.commit()
    return body
