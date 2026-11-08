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

import argparse
import asyncio
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

import defaults
import httpx2
import psutil
import py7zr
import tqdm
from cache import Cache
from cache import already_extracted
from cache import load_cache
from cache import remove_old_extracted
from cache import resolve_archive_member
from cache import write_cache
from hachiko import AIOWatchdog
from log_watcher import LogWatcher
from log_watcher import State
from loguru import logger
from udk_configparser import UDKConfigParser

# TODO: leverage pytest?
# TODO: reduce log spam? More verbose logging to a file,
#       only general info straight to console?


_log_format = "[{time:YYYY-MM-DD HH:mm:ss.SSSZZ}] [{level}] [{function}] {message}"

logger.remove()
logger.add(
    sys.stdout,
    format=_log_format,
    level="DEBUG",
)
logger.add(
    "run_udk_tests.log",
    format=_log_format,
    rotation="50 MB",
    level="DEBUG",
)

SCRIPT_DIR = Path(__file__).parent
REPO_DIR = SCRIPT_DIR.parent
CACHE_DIR = SCRIPT_DIR / ".cache/"
UDK_FW_SCRIPT_PATH = SCRIPT_DIR / "allow_udk_fw.ps1"

UDK_TEST_TIMEOUT = defaults.UDK_TEST_TIMEOUT
def resolve_script_path(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = SCRIPT_DIR / p
    return p.resolve()


def download_file(url: str, out_file: Path, progress_bar: bool = True):
    logger.info("downloading: '{}'", url)
    with out_file.open("wb") as f, httpx2.stream(
            "GET",
            url,
            timeout=120.0,
            follow_redirects=True) as resp:
        resp.raise_for_status()
        total = int(resp.headers["Content-Length"])

        # TODO: refactor this.
        if progress_bar:
            with tqdm.tqdm(total=total, unit_scale=True, unit_divisor=1024,
                           unit="B") as progress:
                num_bytes_downloaded = resp.num_bytes_downloaded
                for data in resp.iter_bytes(chunk_size=4096):
                    f.write(data)
                    progress.update(resp.num_bytes_downloaded - num_bytes_downloaded)
                    num_bytes_downloaded = resp.num_bytes_downloaded

        else:
            for data in resp.iter_bytes(chunk_size=4096):
                f.write(data)

    logger.info("download finished")


def move_file(src: Path, dst: Path):
    logger.info("'{}' -> '{}'", src, dst)
    shutil.move(src, dst)


async def stop_udk_process_tree(proc: asyncio.subprocess.Process) -> int:
    if proc.returncode is None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except TimeoutError:
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/pid",
                    str(proc.pid),
                    "/T",
                    "/F",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                await asyncio.wait_for(killer.wait(), timeout=10)
            except (OSError, TimeoutError) as exc:
                logger.warning("taskkill failed for UDK pid {}: {}", proc.pid, exc)

            if proc.returncode is None:
                proc.kill()

    return await proc.wait()


async def run_udk_build(
        watcher: LogWatcher,
        udk_lite_root: Path,
        timeout: int,
) -> int:
    logger.info("starting UDK build phase")

    udk_exe = (udk_lite_root / "Binaries/Win64/UDK.com").resolve()

    watcher.state = State.BUILDING

    proc = await asyncio.create_subprocess_exec(
        udk_exe,
        *[
            "make",
            "-intermediate",
            "-useunpublished",
            "-log",
            "-UNATTENDED",
            "-FORCELOGFLUSH",
        ],
    )

    logger.info("proc: {}", proc)

    try:
        await asyncio.wait_for(watcher.build_complete.wait(), timeout=timeout)
    except TimeoutError as exc:
        raise RuntimeError("timed out waiting for UDK build completion log event") from exc
    finally:
        ec = await stop_udk_process_tree(proc)

    logger.info("UDK.exe finished")
    logger.info("UDK.exe exited with code: {}", ec)

    if ec != 0:
        raise RuntimeError(f"UDK.exe error: {ec}")

    return ec


async def run_udk_server(
        watcher: LogWatcher,
        udk_lite_root: Path,
    timeout: int,
        udk_args: str,
) -> int:
    logger.info("starting UDK testing phase")

    udk_exe_norunaway = (udk_lite_root / "Binaries/Win64/UDK_norunaway.exe").resolve()
    udk_exe = (udk_lite_root / "Binaries/Win64/UDK.exe").resolve()
    udk_com = (udk_lite_root / "Binaries/Win64/UDK.com").resolve()

    # Use UDK.exe with runaway loop detection patched out.
    if udk_exe_norunaway.exists():
        dst = udk_exe.with_name("UDK.exe.backup")

        if dst.exists():
            logger.info("{} exists, assuming runaway loop detection executable already in use", dst)
        else:
            logger.info("moving original UDK.exe to backup "
                        "and replacing it with runaway loop detection patched variant")
            move_file(udk_exe, dst)
            move_file(udk_exe_norunaway, udk_exe)

    watcher.state = State.TESTING
    test_proc = await asyncio.create_subprocess_exec(
        udk_com,
        *[
            "server",
            udk_args,
            "-UNATTENDED",
            "-log",
            "-FORCELOGFLUSH",
        ],
    )

    logger.info("proc: {}", test_proc)

    try:
        await asyncio.wait_for(watcher.test_complete.wait(), timeout=timeout)
    except TimeoutError as exc:
        raise RuntimeError("timed out waiting for UDK test completion log event") from exc
    finally:
        test_ec = await stop_udk_process_tree(test_proc)

    logger.info("UDK.exe FCrypto test run exited with code: {}", test_ec)

    return test_ec


async def print_udk_processes(event: asyncio.Event) -> None:
    while not event.is_set():
        sleep_time = 0.25
        for proc in psutil.process_iter():
            try:
                if "udk" in proc.name().lower():
                    logger.info("{} {}", '#' * 4, proc)
                    sleep_time = 5.0
            except (psutil.Error, OSError):
                continue

        try:
            await asyncio.wait_for(event.wait(), timeout=sleep_time)
        except TimeoutError:
            pass


async def start_gmp_server(gmp_server_path: Path) -> asyncio.subprocess.Process:
    logger.info("starting GMP server: {}", gmp_server_path)

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(gmp_server_path),
    )
    logger.info("GMP server process: {}", proc)
    return proc


async def stop_gmp_server(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    try:
        ec = await asyncio.wait_for(proc.wait(), timeout=10)
    except TimeoutError:
        proc.kill()
        ec = await proc.wait()
    logger.info("GMP server exited with code: {}", ec)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--no-progress-bar",
        help="disable progress bar",
        action="store_true",
    )
    ap.add_argument(
        "--add-fw-rules",
        help="allow UDK.exe through the windows firewall",
        action="store_true",
    )
    ap.add_argument(
        "--gmp-server-path",
        help="path to gmp_server.py",
        default=str((REPO_DIR / "DevUtils/gmp_server.py").absolute()),
    )
    ap.add_argument(
        "--no-gmp-server",
        help="do not start gmp_server.py, assume already running",
        action="store_true",
    )
    # TODO: is it stupid taking this from both args and env?
    # ap.add_argument(
    #     "--num-test-loops",
    #     help="number of UScript test mutator test loops to run, "
    #          "WARNING: running too many test loops can cause the"
    #          "test mutator to hang forever, default %(default)s",
    #     type=int,
    #     default=defaults.FCRYPTO_NUM_TEST_LOOPS,
    # )

    args = ap.parse_args()
    logger.debug("args: {}", args)
    progress_bar = not args.no_progress_bar
    add_fw_rules = args.add_fw_rules
    gmp_server_path = Path(args.gmp_server_path).resolve()
    no_gmp_server = args.no_gmp_server
    # num_test_loops = args.num_test_loops

    hard_reset = False
    cache = Cache()

    cache_file = Path(CACHE_DIR / ".cache.json").resolve()
    if cache_file.exists():
        try:
            cache = load_cache(cache_file)
        except Exception as e:
            logger.error("error loading cache: {}: {}", type(e).__name__, e)
            logger.info("delete the cache file '{}' "
                        "or cache directory '{}' to force a hard reset",
                        cache_file, CACHE_DIR)
            raise
    else:
        hard_reset = True

    if hard_reset:
        logger.info("hard reset requested")
        logger.info("removing '{}'", CACHE_DIR)
        shutil.rmtree(CACHE_DIR, ignore_errors=True)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        write_cache(cache_file, cache)

    test_timeout = int(os.environ.get("UDK_TEST_TIMEOUT", defaults.UDK_TEST_TIMEOUT))
    udk_lite_tag = os.environ.get("UDK_LITE_TAG", defaults.UDK_LITE_TAG)
    udk_lite_root = Path(os.environ.get("UDK_LITE_ROOT", defaults.UDK_LITE_ROOT))
    udk_lite_release_url = os.environ.get("UDK_LITE_RELEASE_URL", defaults.UDK_LITE_RELEASE_URL)
    fcrypto_classes_files = os.environ.get("FCRYPTO_CLASSES_FILES",
                                           defaults.FCRYPTO_CLASSES_FILES)
    fcrypto_num_test_loops = os.environ.get("FCRYPTO_NUM_TEST_LOOPS",
                                            defaults.FCRYPTO_NUM_TEST_LOOPS)

    if not udk_lite_root.is_absolute():
        udk_lite_root = (SCRIPT_DIR / udk_lite_root).resolve()

    logger.info("UDK_LITE_TAG={}", udk_lite_tag)
    logger.info("UDK_LITE_ROOT={}", udk_lite_root)
    logger.info("UDK_LITE_RELEASE_URL={}", udk_lite_release_url)
    logger.info("FCRYPTO_CLASSES_FILES={}", fcrypto_classes_files)
    logger.info("FCRYPTO_NUM_TEST_LOOPS={}", fcrypto_num_test_loops)

    input_uscript_files = [
        resolve_script_path(path) for path in
        glob.glob(str(fcrypto_classes_files), recursive=True)
    ]

    if not input_uscript_files:
        raise RuntimeError("no input script files found")

    # Check if cache tag, url, etc. match current ones, if not -> reinit.
    # Check if we have all pkg files in place. Compare to cache.

    dl_pkg_archive = False
    pkg_file = CACHE_DIR / Path(udk_lite_release_url).name

    if cache.udk_lite_tag != udk_lite_tag:
        logger.info("cached UDK-Lite tag '{}' does not match '{}'",
                    cache.udk_lite_tag, udk_lite_tag)
        dl_pkg_archive = True

    pkg_file_outdated = cache.pkg_archive != str(pkg_file)
    if pkg_file_outdated:
        dl_pkg_archive = True
        logger.info("cached archive '{}' does not match '{}'",
                    cache.pkg_archive, pkg_file)

    if not pkg_file.exists():
        logger.info("'{}' does not exist", pkg_file)
        dl_pkg_archive = True

    if dl_pkg_archive:
        download_file(udk_lite_release_url, pkg_file, progress_bar=progress_bar)
        cache.udk_lite_tag = udk_lite_tag
        remove_old_extracted(cache, udk_lite_root)
        cache.pkg_archive_extracted_files = []
    else:
        logger.info("using cached archive: '{}'", pkg_file)

    # TODO: make a cache that updates itself automatically
    #   when fields are assigned. Just use diskcache?
    cache.pkg_archive = str(pkg_file)
    write_cache(cache_file, cache)

    logger.info("extracting '{}'...", pkg_file)
    with py7zr.SevenZipFile(pkg_file) as pkg:
        filenames = pkg.getnames()
        targets = [
            fn for fn in filenames
            if not already_extracted(fn, out_dir=udk_lite_root, cache=cache)
        ]
        dirs = [
            t for t in targets
            if resolve_archive_member(t, udk_lite_root).is_dir()
        ]
        targets = [t for t in targets if t not in dirs]

        out_files = [
            str(resolve_archive_member(target, udk_lite_root))
            for target in targets
        ]

        out_dirs = [
            str(resolve_archive_member(d, udk_lite_root))
            for d in dirs
        ]

        for od in out_dirs:
            Path(od).mkdir(parents=True, exist_ok=True)

        if targets:
            logger.info("extracting {} targets to '{}'", len(targets), udk_lite_root)
            pkg.extract(udk_lite_root, targets)

        cache.pkg_archive_extracted_files += out_files + out_dirs
        cache.pkg_archive_extracted_files = list(set(cache.pkg_archive_extracted_files))
        write_cache(cache_file, cache)

    for script_file in input_uscript_files:
        dst_dir = udk_lite_root / "Development/Src/FCrypto/Classes/"
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / script_file.name
        logger.info("'{}' -> '{}'", script_file, dst)
        shutil.copy(script_file, dst)

    log_dir = udk_lite_root / "UDKGame/Logs/"
    log_file = log_dir / "Launch.log"
    if not log_file.exists():
        logger.info("'{}' does not exist yet, touching...", log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch()

    cfg_file = udk_lite_root / "UDKGame/Config/DefaultEngine.ini"
    if not cfg_file.exists():
        raise RuntimeError("required config file '{}' does not exist", cfg_file)

    cfg = UDKConfigParser(comment_prefixes=";")
    cfg.read(cfg_file)

    if not cfg.has_section("UnrealEd.EditorEngine"):
        cfg.add_section("UnrealEd.EditorEngine")

    pkg_name = "FCrypto"
    edit_packages = cfg["UnrealEd.EditorEngine"].getlist("+EditPackages") or []
    if pkg_name not in edit_packages:
        edit_packages.append(pkg_name)
        cfg["UnrealEd.EditorEngine"]["+EditPackages"] = "\n".join(edit_packages)

    if not cfg.has_section("IpDrv.TcpNetDriver"):
        cfg.add_section("IpDrv.TcpNetDriver")
    cfg["IpDrv.TcpNetDriver"]["NetServerMaxTickRate"] = "120"
    cfg["IpDrv.TcpNetDriver"]["LanServerMaxTickRate"] = "120"

    with cfg_file.open("w") as f:
        cfg.write(f, space_around_delimiters=False)

    if add_fw_rules:
        logger.info("adding firewall rules for UDK.exe")
        await (await asyncio.create_subprocess_exec(
            *["powershell.exe", str(UDK_FW_SCRIPT_PATH)]
        )).wait()

    watcher = LogWatcher(log_file)
    monitor_stop = asyncio.Event()
    monitor_task = asyncio.create_task(print_udk_processes(monitor_stop))
    try:
        async with AIOWatchdog(str(log_dir), event_handler=watcher):
            ec = await run_udk_build(
                watcher=watcher,
                udk_lite_root=udk_lite_root,
                timeout=test_timeout,
            )

            gmp_proc = None
            try:
                if not no_gmp_server:
                    gmp_proc = await start_gmp_server(gmp_server_path)

                ec += await run_udk_server(
                    watcher=watcher,
                    udk_lite_root=udk_lite_root,
                    timeout=test_timeout,
                    udk_args=f"Entry?Mutator=FCrypto.FCryptoTestMutator?bIsLanMatch=true?"
                             f"dedicated=true?NumTestLoops={fcrypto_num_test_loops}",
                )
            finally:
                if gmp_proc is not None:
                    await stop_gmp_server(gmp_proc)
    finally:
        monitor_stop.set()
        await monitor_task

    if ec != 0:
        raise RuntimeError(f"UDK.exe error (sum of all exit codes): {ec}")

    logger.info("finished with {} warnings", len(watcher.warnings))
    logger.info("finished with {} errors", len(watcher.errors))

    logger.info("WARNINGS:")
    for warn in watcher.warnings:
        logger.warning(warn.strip())

    for err in watcher.errors:
        logger.error(err.strip())

    if watcher.errors:
        raise RuntimeError("failed, errors detected")

    logger.info("UDK build and FCrypto tests completed successfully")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("exiting by KeyboardInterrupt")
        raise
    except Exception as _e:
        logger.exception("error running main: {}: {}", type(_e).__name__, _e)
        raise
