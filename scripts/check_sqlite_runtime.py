#!/usr/bin/env python3
"""Verify that Python loads the security-fixed SQLite library owned by dpkg."""

import os
import sqlite3
import subprocess
from pathlib import Path


def main() -> None:
    package_version = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Version}", "libsqlite3-0"], text=True
    ).strip()
    if package_version != "3.54.0-0dmarq1":
        raise RuntimeError(f"Unexpected SQLite package: {package_version}")
    if sqlite3.sqlite_version_info < (3, 54, 0):
        raise RuntimeError(f"Unexpected SQLite runtime: {sqlite3.sqlite_version}")
    with sqlite3.connect(":memory:") as db:
        if not any(row[0] == "ENABLE_SESSION" for row in db.execute("pragma compile_options")):
            raise RuntimeError("SQLite session extension is not enabled")

    package_files = subprocess.check_output(
        ["dpkg-query", "-L", "libsqlite3-0"], text=True
    ).splitlines()
    # /proc/self/maps names the real file, not its libsqlite3.so.0 symlink.
    packaged_libraries = {
        os.path.realpath(path)
        for path in package_files
        if "/libsqlite3.so" in path and os.path.isfile(path)
    }
    loaded_paths = {
        fields[5]
        for line in Path("/proc/self/maps").read_text().splitlines()
        if len(fields := line.split(maxsplit=5)) == 6
    }
    loaded_packaged_libraries = packaged_libraries & loaded_paths
    if not loaded_packaged_libraries:
        raise RuntimeError("Python is not using the packaged SQLite runtime")
    print(f"SQLite {sqlite3.sqlite_version}: {', '.join(sorted(loaded_packaged_libraries))}")


if __name__ == "__main__":
    main()
