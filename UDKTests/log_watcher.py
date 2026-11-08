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

import asyncio
import enum
import os
import re
import unicodedata
from pathlib import Path

from hachiko import AIOEventHandler
from loguru import logger
from watchdog.events import FileSystemEvent

LOG_RE = re.compile(r"^\[[\d.]+]\s(\w+):(.*)$")
ARRAY_OOB_ACCESS_RE = re.compile(
    r"^.*ScriptWarning:\sAccessed\sarray\s'\w+'\sout\sof\sbounds\s\([\d/]+\)"
)


class State(enum.StrEnum):
    NONE = enum.auto()
    BUILDING = enum.auto()
    TESTING = enum.auto()


class LogWatcher(AIOEventHandler):
    def __init__(self, log_file: Path):
        super().__init__()
        self._log_file = log_file
        self._log_filename = log_file.name
        self._position = 0
        self._file_identity: tuple[int, int] | None = None
        self._partial_line = b""
        self._read_lock = asyncio.Lock()
        self._state = State.NONE
        self._build_complete = asyncio.Event()
        self._test_complete = asyncio.Event()
        self.warnings: list[str] = []
        self.errors: list[str] = []

    @property
    def state(self) -> State:
        return self._state

    @state.setter
    def state(self, state: State):
        logger.info("setting state: {}", state)
        self._state = state
        if state == State.BUILDING:
            self._build_complete.clear()
        elif state == State.TESTING:
            self._test_complete.clear()

    @property
    def build_complete(self) -> asyncio.Event:
        return self._build_complete

    @property
    def test_complete(self) -> asyncio.Event:
        return self._test_complete

    async def on_created(self, event: FileSystemEvent) -> None:
        await self._handle_event(event.src_path)

    async def on_modified(self, event: FileSystemEvent) -> None:
        await self._handle_event(event.src_path)

    async def on_moved(self, event: FileSystemEvent) -> None:
        await self._handle_event(event.dest_path)
        if self._matches_log(event.src_path):
            self._reset_read_state()

    async def on_deleted(self, event: FileSystemEvent) -> None:
        if self._matches_log(event.src_path):
            self._reset_read_state()

    def _matches_log(self, event_path: str | bytes) -> bool:
        return Path(os.fsdecode(event_path)).name == self._log_filename

    async def _handle_event(self, event_path: str | bytes) -> None:
        if not self._matches_log(event_path):
            return

        async with self._read_lock:
            lines = await asyncio.to_thread(self._read_new_lines)
            for line in lines:
                self._process_line(line)

    def _read_new_lines(self) -> list[str]:
        try:
            stat = self._log_file.stat()
        except FileNotFoundError:
            return []

        identity = (stat.st_dev, stat.st_ino)
        if stat.st_size < self._position or identity != self._file_identity:
            self._position = 0
            self._partial_line = b""
        self._file_identity = identity

        with self._log_file.open("rb") as log_file:
            log_file.seek(self._position)
            data = log_file.read()
            self._position = log_file.tell()

        chunks = (self._partial_line + data).splitlines(keepends=True)
        self._partial_line = b""
        if chunks and not chunks[-1].endswith(b"\n"):
            self._partial_line = chunks.pop()

        return [chunk.decode("utf-8", errors="replace") for chunk in chunks]

    def _reset_read_state(self) -> None:
        self._position = 0
        self._file_identity = None
        self._partial_line = b""

    def _process_line(self, line: str) -> None:
        match = LOG_RE.match(line)
        if match:
            level = match.group(1).lower()
            message = match.group(2)
            if level == "error" and message or "##ERROR##" in message or ARRAY_OOB_ACCESS_RE.match(line):
                self.errors.append(line)
            elif level == "warning" and message:
                self.warnings.append(line)

        if os.getenv("GITHUB_ACTIONS"):
            line = unicodedata.normalize("NFKD", line)
        logger.info(line.strip())

        if self._state == State.BUILDING and "Log file closed" in line:
            self._build_complete.set()
        elif self._state == State.TESTING and "Exit: Exiting" in line:
            self._test_complete.set()
