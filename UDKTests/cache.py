# MIT License
#
# Copyright (c) 2023-2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
import os
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from loguru import logger


@dataclass
class Cache:
    udk_lite_tag: str = ""
    pkg_archive: str = ""
    pkg_archive_extracted_files: list[str] = field(default_factory=list)


def write_cache(file: Path, cache: Cache) -> None:
    logger.info("writing cache file: '{}'", file)
    file.write_text(json.dumps(asdict(cache), indent=2))


def load_cache(path: Path) -> Cache:
    with path.open(encoding="utf-8") as cache_file:
        return Cache(**json.load(cache_file))


def _contained_path(path: str | Path, root: Path, *, allow_leaf_symlink: bool = False) -> Path:
    resolved_root = root.resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = resolved_root / candidate
    candidate = Path(os.path.abspath(candidate))

    try:
        relative = candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path is outside the UDK root: {path}") from exc

    if not relative.parts:
        raise ValueError("the UDK root itself is not a valid managed path")

    current = resolved_root
    for index, part in enumerate(relative.parts):
        current /= part
        is_leaf = index == len(relative.parts) - 1
        if current.is_symlink() and not (is_leaf and allow_leaf_symlink):
            raise ValueError(f"managed path traverses a symlink: {path}")

    return candidate


def resolve_archive_member(member: str, root: Path) -> Path:
    member_path = Path(member)
    if member_path.is_absolute() or member_path.drive or ".." in member_path.parts:
        raise ValueError(f"unsafe archive member path: {member}")
    return _contained_path(member_path, root)


def remove_old_extracted(cache: Cache, root: Path) -> None:
    logger.info("removing old extracted files, if any")

    # Validate the complete manifest before deleting anything.
    paths = {
        _contained_path(path, root, allow_leaf_symlink=True)
        for path in cache.pkg_archive_extracted_files
    }
    directories: list[Path] = []

    for path in paths:
        if path.is_symlink() or path.is_file():
            logger.info("removing '{}'", path)
            path.unlink(missing_ok=True)
        elif path.is_dir():
            directories.append(path)

    for directory in directories:
        if directory.exists() and not any(directory.iterdir()):
            logger.info("removing empty directory '{}'", directory)
            directory.rmdir()
        elif directory.exists():
            logger.info("not removing non-empty directory: '{}'", directory)

    logger.info("remove_old_extracted done")


def already_extracted(archive_file: str, out_dir: Path, cache: Cache) -> bool:
    path = resolve_archive_member(archive_file, out_dir)
    return path.exists() and str(path.resolve()) in cache.pkg_archive_extracted_files
