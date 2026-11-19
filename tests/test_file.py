from pathlib import Path

import pytest

from python_multipart.multipart import File


def _keep_config(tmp_path: Path, **overrides: object) -> dict:
    config: dict = {
        "UPLOAD_DIR": bytes(tmp_path),
        "UPLOAD_KEEP_FILENAME": True,
        "UPLOAD_KEEP_EXTENSIONS": True,
        "MAX_MEMORY_FILE_SIZE": 10,
    }
    config.update(overrides)
    return config


def test_upload_dir_with_leading_slash_in_filename(tmp_path: Path) -> None:
    upload_dir = tmp_path / "upload"
    upload_dir.mkdir()

    # When the file_name provided has a leading slash, we should only use the basename.
    # This is to avoid directory traversal.
    to_upload = tmp_path / "foo.txt"

    file = File(
        bytes(to_upload),
        config={
            "UPLOAD_DIR": bytes(upload_dir),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    assert not file.in_memory
    assert Path(upload_dir / "foo.txt").exists()
    assert Path(upload_dir / "foo.txt").read_bytes() == b"123456789012"


def test_str_upload_dir_with_keep_filename(tmp_path: Path) -> None:
    file = File(
        b"foo.txt",
        config={
            "UPLOAD_DIR": str(tmp_path),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    file.close()

    assert not file.in_memory
    assert file.actual_file_name == b"foo.txt"
    assert (tmp_path / "foo.txt").read_bytes() == b"123456789012"


def test_keep_extensions_without_filename() -> None:
    # An application/octet-stream upload has no filename; keeping the
    # extension must not fail when the file moves to disk.
    file = File(None, config={"UPLOAD_KEEP_EXTENSIONS": True, "MAX_MEMORY_FILE_SIZE": 10})
    file.write(b"123456789012")
    assert not file.in_memory
    assert file.actual_file_name is not None


def test_keep_filename_without_filename(tmp_path: Path) -> None:
    # Without a filename to keep, the file goes to a temporary name in UPLOAD_DIR.
    file = File(
        None,
        config={
            "UPLOAD_DIR": bytes(tmp_path),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "UPLOAD_DELETE_TMP": False,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    file.close()
    assert not file.in_memory
    assert file.actual_file_name is not None
    assert Path(file.actual_file_name.decode()).parent == tmp_path
    assert Path(file.actual_file_name.decode()).read_bytes() == b"123456789012"


def test_posix_path_traversal_is_reduced_to_basename(tmp_path: Path) -> None:
    file = File(b"../../../etc/passwd", config=_keep_config(tmp_path))
    file.write(b"123456789012")
    file.close()

    assert file.actual_file_name == b"passwd"
    assert (tmp_path / "passwd").read_bytes() == b"123456789012"


def test_windows_path_traversal_is_reduced_to_basename(tmp_path: Path) -> None:
    # Backslashes are directory separators too, even on POSIX servers.
    file = File(b"..\\..\\evil.txt", config=_keep_config(tmp_path))
    file.write(b"123456789012")
    file.close()

    assert file.actual_file_name == b"evil.txt"
    assert (tmp_path / "evil.txt").read_bytes() == b"123456789012"
    assert not (tmp_path.parent / "evil.txt").exists()


def test_percent_encoded_traversal_stays_literal(tmp_path: Path) -> None:
    # The library does not percent-decode filenames, so the encoded name is
    # also the on-disk identity - it cannot become a traversal sequence.
    file = File(b"..%2f..%2fevil.txt", config=_keep_config(tmp_path))
    file.write(b"123456789012")
    file.close()

    assert file.actual_file_name == b"..%2f..%2fevil.txt"
    assert (tmp_path / "..%2f..%2fevil.txt").read_bytes() == b"123456789012"
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.parametrize("file_name", [b"", b".", b"..", b"../../", b"\\..\\", b"evil\x00.txt"])
def test_unusable_filename_falls_back_to_temporary_name(tmp_path: Path, file_name: bytes) -> None:
    file = File(file_name, config=_keep_config(tmp_path, UPLOAD_DELETE_TMP=False))
    file.write(b"123456789012")
    file.close()

    # The upload still lands inside UPLOAD_DIR, under a random temporary name.
    assert file.actual_file_name is not None
    actual_path = Path(file.actual_file_name.decode())
    assert actual_path.parent == tmp_path
    assert actual_path.read_bytes() == b"123456789012"


def test_kept_file_stays_inside_upload_dir(tmp_path: Path) -> None:
    # End-to-end: after any decoding, the reported identity, the target path
    # and the cleanup transaction all agree, and nothing lands outside.
    upload_dir = tmp_path / "tenant"
    upload_dir.mkdir()
    file = File(b"..\\..\\tenant_escape.txt", config=_keep_config(upload_dir, UPLOAD_DELETE_TMP=False))
    file.write(b"123456789012")
    file.close()

    assert file.actual_file_name == b"tenant_escape.txt"
    assert (upload_dir / "tenant_escape.txt").exists()
    assert not (tmp_path / "tenant_escape.txt").exists()
