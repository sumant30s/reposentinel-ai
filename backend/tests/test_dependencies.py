from datetime import timedelta

import httpx
from app.models.database import Advisory, now
from app.scanners.dependencies import parse_dependencies
from app.services.osv import OSVClient, advisory_finding


def test_manifest_parsing():
    files = [
        (
            "requirements.txt",
            "# header\nJinja2==2.11.2\nrequests>=2\n-r nested.txt\nfoo==1.0; python_version>'3.8'",
        ),
        (
            "pyproject.toml",
            '[project]\ndependencies=["httpx==0.28.1"]\n[project.optional-dependencies]\ndev=["pytest>=8"]',
        ),
        ("package.json", '{"dependencies":{"left-pad":"1.3.0","react":"^19.0.0"}}'),
        (
            "pom.xml",
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency></dependencies></project>',
        ),
        ("package-lock.json", "{}"),
    ]
    deps, warnings = parse_dependencies(files)
    assert len(deps) == 8
    assert any(d["ecosystem"] == "Maven" and d["name"] == "a:b" for d in deps)
    assert sum(d["version_kind"] == "unresolved" for d in deps) == 3
    assert len(warnings) == 3


def test_invalid_manifest_and_xml_entities():
    _, warnings = parse_dependencies(
        [
            ("package.json", "{oops"),
            ("pyproject.toml", "bad = ["),
            ("pom.xml", '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'),
        ]
    )
    assert len(warnings) == 3


def test_advisory_severity_and_unknown():
    dep = {"name": "sample", "version": "1.0", "file": "requirements.txt", "ecosystem": "PyPI"}
    finding = advisory_finding(
        dep,
        {
            "id": "GHSA-fixture",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "references": [
                {"url": "javascript:alert(1)"},
                {"url": "https://osv.dev/vulnerability/GHSA-fixture"},
            ],
        },
    )
    assert finding.source_severity is None and finding.severity == "medium"
    assert len(finding.references) == 1 and len(finding.cvss) == 1
    assert (
        advisory_finding(
            dep, {"database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-89"]}}
        ).severity
        == "critical"
    )


def test_osv_caching_empty_and_stale(session):
    requests = []

    def ok(request):
        requests.append(request)
        return httpx.Response(200, json={"vulns": [{"id": "TEST-1"}]})

    with httpx.Client(transport=httpx.MockTransport(ok)) as client:
        osv = OSVClient(session, client=client)
        assert osv.query("demo", "1.0", "PyPI")[1] == "live"
        assert osv.query("demo", "1.0", "PyPI")[1] == "cached"
        assert len(requests) == 1
    row = session.get(Advisory, "PyPI:demo:1.0")
    row.fetched_at = now() - timedelta(days=2)
    session.commit()
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        osv = OSVClient(session, client=client)
        assert osv.query("demo", "1.0", "PyPI")[1] == "stale-cache"
        assert osv.query("other", "1.0", "PyPI") == ([], "failed")
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    ) as client:
        assert OSVClient(session, client=client).query("clean", "1.0", "npm") == ([], "live")


def test_osv_invalid_and_pagination(session):
    for payload in [{"vulns": "bad"}, []]:
        with httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
        ) as client:
            assert OSVClient(session, client=client).query("bad", "1.0", "PyPI")[1] == "failed"
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"next_page_token": "next", "vulns": []})
        )
    ) as client:
        assert OSVClient(session, client=client).query("partial", "1.0", "PyPI")[1] == "partial"


def test_advisory_aliases_are_one_finding():
    from app.services.osv import merge_advisories

    rows = [
        {"id": "PYSEC-1", "aliases": ["CVE-2026-0000"]},
        {
            "id": "GHSA-fixture",
            "aliases": ["CVE-2026-0000"],
            "database_specific": {"severity": "HIGH"},
        },
        {"id": "WITHDRAWN", "withdrawn": "2026-01-01"},
    ]
    merged = merge_advisories(rows)
    assert len(merged) == 1
    assert merged[0]["id"] == "GHSA-fixture"
    assert merged[0]["aliases"] == ["CVE-2026-0000", "PYSEC-1"]
