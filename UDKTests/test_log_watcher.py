import asyncio
import os

import pytest
from hachiko import AIOWatchdog
from log_watcher import LogWatcher
from log_watcher import State
from watchdog.events import FileModifiedEvent


def _modified(path):
    return FileModifiedEvent(os.fsencode(path))


@pytest.mark.asyncio
async def test_log_watcher_parses_warnings_errors_and_build_marker(tmp_path):
    log_file = tmp_path / "Launch.log"
    log_file.write_text(
        "[1.000] Warning: expected warning\n"
        "[2.000] Error: expected error\n"
        "[3.000] ScriptWarning: Accessed array 'Values' out of bounds (1/2)\n"
        "[4.000] Log: Log file closed\n",
        encoding="utf-8",
    )
    watcher = LogWatcher(log_file)
    watcher.state = State.BUILDING

    await watcher.on_modified(_modified(log_file))

    assert len(watcher.warnings) == 1
    assert len(watcher.errors) == 2
    assert watcher.build_complete.is_set()


@pytest.mark.asyncio
async def test_log_watcher_waits_for_partial_line_and_ignores_duplicate_events(tmp_path):
    log_file = tmp_path / "Launch.log"
    log_file.write_bytes(b"[1.000] Warning: partial")
    watcher = LogWatcher(log_file)

    await watcher.on_modified(_modified(log_file))
    assert watcher.warnings == []

    with log_file.open("ab") as output:
        output.write(b" line\n")
    await watcher.on_modified(_modified(log_file))
    await watcher.on_modified(_modified(log_file))

    assert len(watcher.warnings) == 1
    assert "partial line" in watcher.warnings[0]


@pytest.mark.asyncio
async def test_log_watcher_resets_offset_after_truncation(tmp_path):
    log_file = tmp_path / "Launch.log"
    log_file.write_text("[1.000] Log: " + ("old" * 100) + "\n", encoding="utf-8")
    watcher = LogWatcher(log_file)
    watcher.state = State.TESTING
    await watcher.on_modified(_modified(log_file))

    log_file.write_text("[2.000] Log: Exit: Exiting\n", encoding="utf-8")
    await watcher.on_modified(_modified(log_file))

    assert watcher.test_complete.is_set()


@pytest.mark.asyncio
async def test_log_watcher_ignores_other_paths(tmp_path):
    log_file = tmp_path / "Launch.log"
    other_file = tmp_path / "Other.log"
    other_file.write_text("[1.000] Error: should be ignored\n", encoding="utf-8")
    watcher = LogWatcher(log_file)

    await watcher.on_modified(_modified(other_file))

    assert watcher.errors == []


@pytest.mark.asyncio
async def test_hachiko_dispatches_log_modification_events(tmp_path):
    log_file = tmp_path / "Launch.log"
    log_file.write_text("", encoding="utf-8")
    watcher = LogWatcher(log_file)
    watcher.state = State.BUILDING

    async with AIOWatchdog(str(tmp_path), event_handler=watcher):
        with log_file.open("a", encoding="utf-8") as output:
            output.write("[1.000] Log: Log file closed\n")
        await asyncio.wait_for(watcher.build_complete.wait(), timeout=5)

    assert watcher.build_complete.is_set()
