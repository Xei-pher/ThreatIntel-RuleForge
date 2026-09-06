from io import BytesIO

import pytest

from app.uploads import sanitize_upload_filename, save_limited_upload


def test_sanitize_upload_filename_removes_posix_path_components():
    assert sanitize_upload_filename("../../client/report.pdf") == "report.pdf"


def test_sanitize_upload_filename_removes_windows_path_components():
    assert sanitize_upload_filename(r"C:\Users\analyst\report.pdf") == "report.pdf"


def test_sanitize_upload_filename_rejects_non_pdf():
    with pytest.raises(ValueError, match="PDF"):
        sanitize_upload_filename("report.txt")


def test_save_limited_upload_removes_partial_file_on_limit_error(tmp_path):
    target = tmp_path / "report.pdf"
    with pytest.raises(ValueError, match="upload limit"):
        save_limited_upload(BytesIO(b"A" * 20), target, limit_bytes=10)
    assert not target.exists()
