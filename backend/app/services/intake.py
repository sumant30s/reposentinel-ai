import fnmatch
import io
import os
import re
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings

SKIP = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".tox",
    "vendor",
}
EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".json",
    ".toml",
    ".xml",
    ".txt",
    ".yaml",
    ".yml",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
}


class IntakeError(ValueError):
    pass


def repository_slug(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.netloc.lower() != "github.com"
        or parts.query
        or parts.fragment
    ):
        raise IntakeError("Only public https://github.com/owner/repository URLs are supported")
    path = parts.path.rstrip("/").removesuffix(".git").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9_.-]{1,100}", path) or any(
        p in {".", ".."} for p in path.split("/")
    ):
        raise IntakeError("Invalid GitHub repository path")
    return path


def ignored(relative: str, patterns: list[str]) -> bool:
    path = PurePosixPath(relative)
    return bool(set(path.parts) & SKIP) or any(
        fnmatch.fnmatch(relative, pattern) for pattern in patterns
    )


def source_files(
    root: Path, settings: Settings, patterns: list[str] | None = None
) -> tuple[list[tuple[str, str]], list[str]]:
    root = root.resolve(strict=True)
    files: list[tuple[str, str]] = []
    warnings: list[str] = []
    total = 0
    seen = 0
    started = time.monotonic()
    for folder, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not Path(folder, d).is_symlink())
        for name in sorted(names):
            seen += 1
            if seen > settings.max_files * 10 or time.monotonic() - started > settings.scan_timeout:
                raise IntakeError("Discovery limit exceeded")
            path = Path(folder, name)
            rel = path.relative_to(root).as_posix()
            if ignored(rel, patterns or []):
                continue
            if len(rel) > 240 or any(ord(c) < 32 for c in rel):
                warnings.append("Skipped unsafe or excessively long filename")
                continue
            if path.is_symlink() or not path.is_file():
                warnings.append(f"Skipped special file: {rel}")
                continue
            if root not in path.resolve().parents:
                raise IntakeError("File escapes repository root")
            if path.suffix.lower() not in EXTENSIONS and name not in {"Dockerfile", ".env"}:
                continue
            if path.stat().st_size > settings.max_file_bytes:
                warnings.append(f"Skipped oversized file: {rel}")
                continue
            # O_NOFOLLOW closes the final-component symlink race on Unix.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(settings.max_file_bytes + 1)
            if len(data) > settings.max_file_bytes:
                raise IntakeError("File grew beyond limit")
            if b"\x00" in data:
                warnings.append(f"Skipped binary file: {rel}")
                continue
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                warnings.append(f"Skipped non-UTF-8 file: {rel}")
                continue
            total += len(data)
            if total > settings.max_total_bytes or len(files) >= settings.max_files:
                raise IntakeError("Repository size or file-count limit exceeded")
            files.append((rel, text))
    return files, warnings


def extract_archive(blob: bytes, target: Path, settings: Settings) -> None:
    if len(blob) > settings.max_archive_bytes:
        raise IntakeError("Compressed archive limit exceeded")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            members = archive.infolist()
            if len(members) > settings.max_files * 2:
                raise IntakeError("Archive entry-count limit exceeded")
            total = 0
            seen = set()
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (
                    not name
                    or len(name) > 240
                    or "\\" in name
                    or ":" in name
                    or path.is_absolute()
                    or ".." in path.parts
                    or any(ord(c) < 32 for c in name)
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                ):
                    raise IntakeError("Unsafe archive path or special file")
                key = str(path).casefold()
                if key in seen:
                    raise IntakeError("Duplicate archive path")
                seen.add(key)
                total += member.file_size
                if total > settings.max_total_bytes or member.file_size > settings.max_file_bytes:
                    raise IntakeError("Expanded archive limit exceeded")
                if member.file_size > 100 * max(member.compress_size, 1):
                    raise IntakeError("Suspicious archive compression ratio")
                if member.flag_bits & 1:
                    raise IntakeError("Encrypted archives are unsupported")
                dest = target.joinpath(*path.parts)
                if target.resolve() not in dest.resolve().parents:
                    raise IntakeError("Archive path escapes target")
                if member.is_dir():
                    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if ignored(str(path), settings.exclusions):
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.open(member) as stream:
                    data = stream.read(settings.max_file_bytes + 1)
                if len(data) != member.file_size:
                    raise IntakeError("Archive size mismatch")
                dest.write_bytes(data)
                dest.chmod(0o600)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise IntakeError("Invalid or unsupported ZIP archive") from exc


def download_repository(url: str, settings: Settings) -> bytes:
    slug = repository_slug(url)
    # Fixed destination, no user-selected host, credentials, redirects, submodules or hooks.
    endpoint = f"https://codeload.github.com/{slug}/zip/HEAD"
    data = bytearray()
    started = time.monotonic()
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        with client.stream("GET", endpoint) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > settings.max_archive_bytes or time.monotonic() - started > 45:
                    raise IntakeError("Repository download exceeded limits")
    return bytes(data)


def snapshot_local(
    source: Path, target: Path, settings: Settings, patterns: list[str]
) -> list[str]:
    files, warnings = source_files(source, settings, patterns)
    for name, text in files:
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest.write_text(text, encoding="utf-8")
        dest.chmod(0o600)
    return warnings
