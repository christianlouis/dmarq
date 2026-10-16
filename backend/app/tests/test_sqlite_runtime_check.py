"""The image gate accepts versioned package files, but rejects other libraries."""

import runpy
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.parametrize("packaged_runtime_loaded", [True, False])
def test_sqlite_gate_checks_package_owned_real_file(tmp_path, packaged_runtime_loaded):
    script = Path(__file__).resolve().parents[3] / "scripts" / "check_sqlite_runtime.py"
    check = runpy.run_path(str(script))["main"]
    library = tmp_path / "libsqlite3.so.3.54.0"
    library.touch()
    other_library = tmp_path / "unpackaged" / "libsqlite3.so.3.54.0"
    loaded = library if packaged_runtime_loaded else other_library
    maps = f"1234-5678 r-xp 0000 00:00 1 {loaded}\n"
    connection = MagicMock()
    connection.__enter__.return_value.execute.return_value = [("ENABLE_SESSION",)]
    with (
        patch("subprocess.check_output", side_effect=["3.54.0-0dmarq1", library.as_posix()]),
        patch("sqlite3.sqlite_version_info", (3, 54, 0)),
        patch("sqlite3.connect", return_value=connection),
        patch.object(Path, "read_text", return_value=maps),
    ):
        if packaged_runtime_loaded:
            check()
        else:
            with pytest.raises(RuntimeError, match="not using the packaged SQLite runtime"):
                check()
