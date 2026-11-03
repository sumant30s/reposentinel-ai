import io
import stat
import zipfile

import httpx
import pytest
from app.services.intake import (
    IntakeError,
    download_repository,
    extract_archive,
    repository_slug,
    snapshot_local,
    source_files,
)


def zipped(name="app.py", content=b"print('hello')", mode=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(name)
        if mode:
            info.external_attr = mode << 16
        archive.writestr(info, content)
    return stream.getvalue()


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://127.0.0.1/a/b",
        "https://github.com.evil/a/b",
        "https://user@github.com/a/b",
        "file:///etc/passwd",
        "https://github.com/a/../",
        "https://github.com/a/b?ref=main",
        "https://github.com/a/b/tree/main",
        "https://github.com/a/%2e%2e",
        "https://github.com:443/a/b",
    ],
)
def test_bad_urls(url):
    with pytest.raises(IntakeError):
        repository_slug(url)


def test_good_url():
    assert repository_slug("https://github.com/example/project.git") == "example/project"


@pytest.mark.parametrize(
    "name", ["../escape.py", "/root.py", "a/../../x.py", "C:/escape.py", "a\\b.py", "a\x01.py"]
)
def test_archive_traversal(name, tmp_path, settings):
    with pytest.raises(IntakeError):
        extract_archive(zipped(name), tmp_path / "out", settings)


def test_archive_size_symlink_and_bad_zip(tmp_path, settings):
    for blob in [zipped(mode=stat.S_IFLNK | 0o777), b"not a zip"]:
        with pytest.raises(IntakeError):
            extract_archive(blob, tmp_path / "out", settings)
    with pytest.raises(IntakeError):
        extract_archive(
            zipped(content=b"x" * 20),
            tmp_path / "out",
            settings.model_copy(update={"max_file_bytes": 10}),
        )
    with pytest.raises(IntakeError):
        extract_archive(
            zipped(), tmp_path / "out", settings.model_copy(update={"max_archive_bytes": 10})
        )


def test_duplicate_and_bomb(tmp_path, settings):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.py", "x" * 20000)
    with pytest.raises(IntakeError, match="compression ratio"):
        extract_archive(stream.getvalue(), tmp_path / "out", settings)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("a.py", "x")
        archive.writestr("A.py", "x")
    with pytest.raises(IntakeError, match="Duplicate"):
        extract_archive(stream.getvalue(), tmp_path / "out2", settings)


def test_discovery_and_snapshot(tmp_path, settings):
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.py").write_text("print('safe')")
    (root / "binary.py").write_bytes(b"\x00\x01")
    (root / "latin.py").write_bytes(b"\xff\xff")
    (root / "ignore.py").write_text("eval(user)")
    (root / "large.py").write_bytes(b"x" * 300)
    (root / "picture.png").write_bytes(b"PNG")
    (root / "node_modules").mkdir()
    (root / "node_modules/x.js").write_text("eval(user)")
    (root / "link.py").symlink_to(root / "app.py")
    tuned = settings.model_copy(update={"max_file_bytes": 100})
    files, warnings = source_files(root, tuned, ["ignore.py"])
    assert [f[0] for f in files] == ["app.py"]
    assert len(warnings) == 4
    target = tmp_path / "snapshot"
    snapshot_local(root, target, tuned, ["ignore.py"])
    assert (target / "app.py").exists()
    assert not (target / "link.py").exists()
    with pytest.raises(IntakeError):
        source_files(root, tuned.model_copy(update={"max_files": 0}))


def test_extract_valid_archive(tmp_path, settings):
    root = tmp_path / "out"
    extract_archive(zipped("src/app.py"), root, settings)
    assert (root / "src/app.py").read_text() == "print('hello')"


def test_download_fixed_destination(monkeypatch, settings):
    original = httpx.Client
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, content=b"zip bytes")

    monkeypatch.setattr(
        "app.services.intake.httpx.Client",
        lambda **kw: original(transport=httpx.MockTransport(handler)),
    )
    assert download_repository("https://github.com/a/b", settings) == b"zip bytes"
    assert seen == ["https://codeload.github.com/a/b/zip/HEAD"]
    with pytest.raises(IntakeError):
        download_repository(
            "https://github.com/a/b", settings.model_copy(update={"max_archive_bytes": 2})
        )
