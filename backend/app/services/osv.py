import time
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from app.models.database import Advisory
from app.scanners.python_ast import make_finding
from app.schemas.contracts import FindingData, Severity


def safe_references(values: list[dict]) -> list[str]:
    references = []
    for value in values:
        url = value.get("url") if isinstance(value, dict) else None
        if not isinstance(url, str) or len(url) > 2048:
            continue
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme == "https"
                and parsed.hostname
                and not parsed.username
                and not parsed.password
            ):
                references.append(url)
        except ValueError:
            continue
    return references[:10]


def merge_advisories(advisories: list[dict]) -> list[dict]:
    """Collapse OSV records connected by IDs/aliases; retain authoritative metadata."""
    groups: list[tuple[set[str], list[dict]]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict) or not advisory.get("id") or advisory.get("withdrawn"):
            continue
        identifiers = {str(advisory["id"]), *[str(a) for a in advisory.get("aliases", [])]}
        rows = [advisory]
        remaining = []
        for old_ids, old_rows in groups:
            if identifiers & old_ids:
                identifiers |= old_ids
                rows.extend(old_rows)
            else:
                remaining.append((old_ids, old_rows))
        groups = [*remaining, (identifiers, rows)]
    merged = []
    for identifiers, rows in groups:
        rows.sort(key=lambda row: (not str(row["id"]).startswith("GHSA-"), str(row["id"])))
        preferred = dict(rows[0])
        preferred["aliases"] = sorted(identifiers - {preferred["id"]})
        preferred["references"] = [
            {"url": url}
            for url in sorted(
                {url for row in rows for url in safe_references(row.get("references", []))}
            )
        ]
        preferred["severity"] = list(
            {
                (s["type"], s["score"]): s
                for row in rows
                for s in row.get("severity", [])
                if isinstance(s, dict) and "type" in s and "score" in s
            }.values()
        )
        merged.append(preferred)
    return merged


class OSVClient:
    def __init__(self, session: Session, ttl_hours: int = 24, client: httpx.Client | None = None):
        self.session = session
        self.ttl = timedelta(hours=ttl_hours)
        self.client = client or httpx.Client(timeout=8, follow_redirects=False)
        self.owns_client = client is None

    def close(self) -> None:
        if self.owns_client:
            self.client.close()

    def query(self, name: str, version: str, ecosystem: str) -> tuple[list[dict], str]:
        key = f"{ecosystem}:{name}:{version}"
        cached = self.session.get(Advisory, key)
        if cached and datetime.now(UTC) - cached.fetched_at.replace(tzinfo=UTC) < self.ttl:
            return cached.payload.get("vulns", []), "cached"
        for attempt in range(2):
            try:
                with self.client.stream(
                    "POST",
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
                ) as response:
                    response.raise_for_status()
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 4 * 1024 * 1024:
                            raise ValueError("OSV response too large")
                import json

                payload = json.loads(raw)
                if not isinstance(payload.get("vulns", []), list):
                    raise ValueError("Invalid advisory response")
                partial = bool(payload.get("next_page_token"))
                if not partial:
                    if cached:
                        cached.payload = payload
                        cached.fetched_at = datetime.now(UTC)
                    else:
                        self.session.add(Advisory(key=key, payload=payload))
                    self.session.commit()
                return payload.get("vulns", []), "partial" if partial else "live"
            except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                if attempt == 0:
                    time.sleep(0.1)
        if cached:
            return cached.payload.get("vulns", []), "stale-cache"
        return [], "failed"


def advisory_finding(dependency: dict, advisory: dict) -> FindingData:
    item = make_finding("RS009", dependency["file"], None, "osv", "high")
    item.advisory_id = str(advisory.get("id", "unknown"))
    item.advisory_aliases = advisory.get("aliases", [])[:20]
    item.title = f"{dependency['name']} {dependency['version']}: {item.advisory_id}"
    item.description = str(
        advisory.get("summary")
        or "An advisory matches this declared version; verify the deployed dependency and affected code paths."
    )[:3000]
    item.language = dependency["ecosystem"]
    source = advisory.get("database_specific", {}).get("severity")
    item.source_severity = str(source) if source else None
    normalized = str(source).lower()
    item.severity = cast(
        Severity, normalized if normalized in {"critical", "high", "medium", "low"} else "medium"
    )
    item.cvss = [
        s
        for s in advisory.get("severity", [])
        if isinstance(s, dict) and "type" in s and "score" in s
    ]
    item.references = safe_references(advisory.get("references", []))
    item.cwe = [
        c
        for c in advisory.get("database_specific", {}).get("cwe_ids", [])
        if isinstance(c, str) and c.startswith("CWE-")
    ]
    item.evidence = f"Declared dependency: {dependency['name']}=={dependency['version']}; not proof of installation or reachability."
    # Distinguish packages affected by the same advisory in the same manifest.
    item.rule_id = f"RS009/{dependency['ecosystem']}/{dependency['name']}"
    return item.identify()
