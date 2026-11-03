import pytest
from app.scanners.python_ast import analyze_python, make_finding
from app.scanners.secrets import analyze_secrets
from app.services.risk import deduplicate, prioritize


@pytest.mark.parametrize(
    "source,rule",
    [
        ('cursor.execute("SELECT " + user)', "RS001"),
        ('cursor.execute(f"SELECT {user}")', "RS001"),
        ('q="SELECT {}".format(user)\ncursor.execute(q)', "RS001"),
        ('PASSWORD="fictional-secret-value"', "RS002"),
        ('api_key: str = "fictional-key-value"', "RS002"),
        ("eval(user)", "RS003"),
        ("exec(user)", "RS003"),
        ("import pickle as p\np.loads(data)", "RS004"),
        ("from pickle import loads as read\nread(data)", "RS004"),
        ("import subprocess\nsubprocess.run(user,shell=True)", "RS005"),
        ("import hashlib\nhashlib.md5(data)", "RS006"),
        ("requests.get(url,verify=False)", "RS007"),
        ("DEBUG=True", "RS008"),
        ("app.run(debug=True)", "RS008"),
    ],
)
def test_positive_patterns(source, rule):
    findings, warnings = analyze_python(source, "fixture.py")
    assert rule in {f.rule_id for f in findings}
    assert not warnings
    assert all("fictional-secret" not in f.model_dump_json() for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        'cursor.execute("SELECT * FROM t WHERE id = ?", (user,))',
        'cursor.execute("SELECT * FROM t WHERE id = %s", (user,))',
        'password=os.environ["PASSWORD"]',
        'token="example"',
        "json.loads(payload)",
        'subprocess.run(["echo", user],shell=False)',
        "hashlib.md5(data,usedforsecurity=False)",
        "hashlib.sha256(data)",
        "requests.get(url,verify=True)",
        "DEBUG=False",
        'print("eval(user)")',
        "app.run(debug=False)",
    ],
)
def test_negative_patterns(source):
    findings, warnings = analyze_python(source, "safe.py")
    assert findings == []
    assert warnings == []


def test_scope_and_syntax():
    source = 'def a(user):\n q=f"{user}"\n cursor.execute(q)\ndef b(q):\n cursor.execute(q)\nasync def c(q):\n cursor.execute(q)'
    findings, _ = analyze_python(source, "scope.py")
    assert len(findings) == 1
    assert analyze_python("def broken(", "broken.py")[1]


def test_secret_values_never_stored():
    source = 'password = "invented-security-fixture"\n-----BEGIN PRIVATE KEY-----\napi_key="${ENV}"\ntoken="example"'
    findings = analyze_secrets(source, "config.txt")
    assert len(findings) == 2
    assert "invented-security-fixture" not in str([f.model_dump() for f in findings])


def test_dedup_and_priority():
    a = make_finding("RS001", "x.py", 4)
    b = make_finding("RS001", "x.py", 4, "bandit")
    merged = deduplicate([a, b])
    assert len(merged) == 1 and merged[0].engines == ["ast", "bandit"]
    assert prioritize(a, "internet", True).priority == "critical"
    assert a.severity == "high" and "not CVSS" in a.priority_reason
    low = a.model_copy(update={"severity": "low", "confidence": "low"})
    assert prioritize(low).priority == "low"
