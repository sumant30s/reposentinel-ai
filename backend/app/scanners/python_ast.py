import ast
import re
from typing import Literal, cast

from app.rules.catalog import RULES
from app.schemas.contracts import FindingData, Severity

SENSITIVE = re.compile(r"(?:password|passwd|secret|token|api_?key|private_?key)", re.I)
PLACEHOLDERS = {"", "changeme", "password", "example", "redacted", "your-key", "test"}


def make_finding(
    rule: str, file: str, line: int | None, engine: str = "ast", confidence: str = "medium"
) -> FindingData:
    title, severity, cwe, owasp, remediation = RULES[rule]
    return FindingData(
        rule_id=rule,
        title=title,
        severity=cast(Severity, severity),
        confidence=cast(Literal["high", "medium", "low"], confidence),
        file=file,
        line=line,
        description=f"Potential {title.lower()}; review data flow and deployment context before treating it as exploitable.",
        remediation=remediation,
        cwe=[cwe],
        owasp=owasp,
        engines=[engine],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
    ).identify()


def name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{name_of(node.value)}.{node.attr}"
    return ""


def dynamic_sql(node: ast.AST) -> bool:
    return isinstance(node, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(node, ast.Call) and name_of(node.func).endswith(".format")
    )


class Analyzer(ast.NodeVisitor):
    def __init__(self, file: str):
        self.file = file
        self.findings: list[FindingData] = []
        self.bindings: dict[str, ast.AST] = {}
        self.aliases: dict[str, str] = {}

    def emit(self, rule: str, node: ast.AST, confidence: str = "medium") -> None:
        self.findings.append(
            make_finding(rule, self.file, getattr(node, "lineno", None), confidence=confidence)
        )

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.aliases[item.asname or item.name] = item.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        old = self.bindings.copy()
        self.bindings = {}  # Intentionally intraprocedural, no cross-function taint claims.
        self.generic_visit(node)
        self.bindings = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            label = name_of(target)
            self.bindings[label] = node.value
            if (
                SENSITIVE.search(label)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value.lower() not in PLACEHOLDERS
            ):
                self.emit("RS002", node, "high")
            if (
                label.upper().endswith("DEBUG")
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
            ):
                self.emit("RS008", node, "high")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            proxy = ast.Assign(targets=[node.target], value=node.value)
            ast.copy_location(proxy, node)
            self.visit_Assign(proxy)

    def visit_Call(self, node: ast.Call) -> None:
        name = name_of(node.func)
        first, *rest = name.split(".")
        name = ".".join([self.aliases.get(first, first), *rest])
        argument: ast.AST | None = node.args[0] if node.args else None
        if isinstance(argument, ast.Name):
            argument = self.bindings.get(argument.id, argument)
        if (
            name.split(".")[-1] in {"execute", "executemany", "executescript"}
            and argument is not None
            and dynamic_sql(argument)
        ):
            self.emit("RS001", node)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.emit("RS003", node, "high")
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self.emit("RS004", node)
        if name.startswith("subprocess.") and any(
            k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in node.keywords
        ):
            self.emit("RS005", node, "medium" if not isinstance(argument, ast.Constant) else "low")
        if name in {"hashlib.md5", "hashlib.sha1"}:
            nonsecurity = any(
                k.arg == "usedforsecurity"
                and isinstance(k.value, ast.Constant)
                and k.value.value is False
                for k in node.keywords
            )
            if not nonsecurity:
                self.emit("RS006", node, "low")
        if any(
            k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in node.keywords
        ):
            self.emit("RS007", node)
        if any(
            k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in node.keywords
        ):
            self.emit("RS008", node, "high")
        self.generic_visit(node)


def analyze_python(source: str, file: str) -> tuple[list[FindingData], list[str]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [f"Python parse failed: {file}"]
    scanner = Analyzer(file)
    try:
        scanner.visit(tree)
    except RecursionError:
        return scanner.findings, [f"Python AST depth exceeded: {file}"]
    return scanner.findings, []
