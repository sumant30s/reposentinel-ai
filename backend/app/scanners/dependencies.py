import json
import re
import tomllib
from pathlib import PurePosixPath

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from packaging.requirements import InvalidRequirement, Requirement


def parse_dependencies(files: list[tuple[str, str]]) -> tuple[list[dict], list[str]]:
    dependencies: list[dict] = []
    warnings: list[str] = []

    def add(name: str, version: str, ecosystem: str, file: str, resolved: bool = False) -> None:
        exact = bool(re.fullmatch(r"[0-9][A-Za-z0-9_.+!-]*", version))
        dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "file": file,
                "version_kind": "resolved"
                if resolved
                else "declared-exact"
                if exact
                else "unresolved",
                "lookup_status": "pending" if exact else "unsupported-range",
                "advisories": [],
            }
        )

    def python_requirement(raw: str, file: str) -> None:
        if not raw or raw.startswith("#"):
            return
        try:
            req = Requirement(raw)
            spec = list(req.specifier)
            exact = (
                len(spec) == 1
                and spec[0].operator == "=="
                and "*" not in spec[0].version
                and req.url is None
            )
            add(
                req.name,
                spec[0].version if exact else str(req.specifier) or "unresolved",
                "PyPI",
                file,
            )
            if req.marker or req.extras:
                warnings.append(
                    f"Declared dependency environment/extras not evaluated: {file}:{req.name}"
                )
        except InvalidRequirement:
            warnings.append(f"Unsupported requirement directive or syntax in {file}")

    for file, source in files:
        name = PurePosixPath(file).name
        try:
            if name == "requirements.txt":
                for line in source.splitlines():
                    python_requirement(line.strip(), file)
            elif name == "pyproject.toml":
                document = tomllib.loads(source)
                project = document.get("project", {})
                for raw in project.get("dependencies", []):
                    python_requirement(raw, file)
                for extra in project.get("optional-dependencies", {}).values():
                    for raw in extra:
                        python_requirement(raw, file)
                if document.get("tool", {}).get("poetry") or project.get("dynamic"):
                    warnings.append(f"Poetry/dynamic metadata unsupported: {file}")
            elif name == "package.json":
                document = json.loads(source)
                for group in ("dependencies", "devDependencies", "optionalDependencies"):
                    for package, version in document.get(group, {}).items():
                        add(package, str(version), "npm", file)
            elif name == "pom.xml":
                root = ElementTree.fromstring(source)
                for element in root.iter():
                    if element.tag.split("}")[-1] == "dependency":
                        fields = {e.tag.split("}")[-1]: e.text or "" for e in element}
                        if fields.get("groupId") and fields.get("artifactId"):
                            add(
                                f"{fields['groupId']}:{fields['artifactId']}",
                                fields.get("version", "unresolved"),
                                "Maven",
                                file,
                            )
            elif name in {
                "package-lock.json",
                "poetry.lock",
                "uv.lock",
                "yarn.lock",
                "pnpm-lock.yaml",
            }:
                warnings.append(
                    f"Lockfile resolution is not implemented: {file}; manifest versions are declarations only"
                )
        except (
            ValueError,
            TypeError,
            AttributeError,
            ElementTree.ParseError,
            DefusedXmlException,
        ) as exc:
            warnings.append(f"Cannot safely parse manifest {file}: {type(exc).__name__}")
    unique = {(d["file"], d["ecosystem"], d["name"], d["version"]): d for d in dependencies}
    if len(unique) > 100:
        warnings.append(
            "Dependency lookup limit: only the first 100 distinct declarations are analyzed"
        )
    return list(unique.values())[:100], warnings
