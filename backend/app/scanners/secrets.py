import re

from app.scanners.python_ast import PLACEHOLDERS, make_finding
from app.schemas.contracts import FindingData

ASSIGNMENT = re.compile(
    r"""(?ix)(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*["']([^"'\r\n]{4,})["']"""
)
PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
TOKEN = re.compile(r"(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{24,})")


def analyze_secrets(source: str, file: str) -> list[FindingData]:
    findings = []
    for number, line in enumerate(source.splitlines(), 1):
        match = ASSIGNMENT.search(line)
        assigned = (
            match
            and match.group(1).lower() not in PLACEHOLDERS
            and not match.group(1).startswith(("${", "{{", "<"))
        )
        if assigned or PRIVATE.search(line) or TOKEN.search(line):
            item = make_finding("RS002", file, number, "secret-pattern", "medium")
            item.language = "Python" if file.endswith(".py") else "Text"
            findings.append(item)
    return findings
