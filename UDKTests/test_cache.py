import pytest
from cache import Cache
from cache import already_extracted
from cache import load_cache
from cache import remove_old_extracted
from cache import resolve_archive_member
from cache import write_cache


def test_cache_round_trip(tmp_path):
    cache_path = tmp_path / "cache.json"
    cache = Cache("tag", "archive.7z", ["file.uc"])

    write_cache(cache_path, cache)

    assert load_cache(cache_path) == cache


def test_remove_old_extracted_removes_files_and_only_empty_directories(tmp_path):
    root = tmp_path / "udk"
    empty_directory = root / "empty"
    non_empty_directory = root / "non-empty"
    empty_directory.mkdir(parents=True)
    non_empty_directory.mkdir()
    cached_file = root / "cached.uc"
    cached_file.write_text("cached")
    (non_empty_directory / "keep.txt").write_text("keep")
    cache = Cache(pkg_archive_extracted_files=[
        str(empty_directory),
        str(non_empty_directory),
        str(cached_file),
    ])

    remove_old_extracted(cache, root)

    assert not cached_file.exists()
    assert not empty_directory.exists()
    assert non_empty_directory.is_dir()
    assert (non_empty_directory / "keep.txt").exists()


@pytest.mark.parametrize("unsafe_path", ["../outside.txt", "C:/outside.txt"])
def test_remove_old_extracted_rejects_unsafe_manifest_before_deleting(
    tmp_path,
    unsafe_path,
):
    root = tmp_path / "udk"
    root.mkdir()
    safe_file = root / "safe.txt"
    safe_file.write_text("keep until full manifest is validated")
    cache = Cache(pkg_archive_extracted_files=[str(safe_file), unsafe_path])

    with pytest.raises(ValueError):
        remove_old_extracted(cache, root)

    assert safe_file.exists()


def test_remove_old_extracted_unlinks_symlink_without_touching_target(tmp_path):
    root = tmp_path / "udk"
    root.mkdir()
    target_directory = tmp_path / "outside"
    target_directory.mkdir()
    target_file = target_directory / "keep.txt"
    target_file.write_text("keep")
    link = root / "link"
    try:
        link.symlink_to(target_directory, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    cache = Cache(pkg_archive_extracted_files=[str(link)])

    remove_old_extracted(cache, root)

    assert not link.exists()
    assert target_file.exists()


@pytest.mark.parametrize("member", ["../outside.txt", "C:/outside.txt"])
def test_resolve_archive_member_rejects_paths_outside_root(tmp_path, member):
    root = tmp_path / "udk"
    root.mkdir()

    with pytest.raises(ValueError):
        resolve_archive_member(member, root)


def test_already_extracted_checks_cache_and_rejects_traversal(tmp_path):
    root = tmp_path / "udk"
    root.mkdir()
    cached_file = root / "Development" / "Src" / "FCrypto" / "Example.uc"
    cached_file.parent.mkdir(parents=True)
    cached_file.write_text("class Example;")
    cache = Cache(pkg_archive_extracted_files=[str(cached_file.resolve())])

    assert already_extracted("Development/Src/FCrypto/Example.uc", root, cache)
    assert not already_extracted("Development/Src/FCrypto/Missing.uc", root, cache)
    with pytest.raises(ValueError):
        already_extracted("../../outside.uc", root, cache)