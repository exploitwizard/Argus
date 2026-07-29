"""Tests for bring-your-own-skills loading (offline, deterministic)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from argus.core import skills


def test_load_md_file(tmp_path: Path):
    p = tmp_path / "skills.md"
    p.write_text("# My method\nCheck IDOR everywhere.", encoding="utf-8")
    out = skills.load_skills(str(p))
    assert "Check IDOR everywhere." in out


def test_load_directory_concatenates_sorted(tmp_path: Path):
    (tmp_path / "a.md").write_text("alpha rule", encoding="utf-8")
    (tmp_path / "b.txt").write_text("beta rule", encoding="utf-8")
    (tmp_path / "ignore.py").write_text("print('nope')", encoding="utf-8")
    out = skills.load_skills(str(tmp_path))
    assert "alpha rule" in out and "beta rule" in out
    assert "nope" not in out  # non-text files are ignored
    assert out.index("alpha") < out.index("beta")  # sorted by name


def test_load_zip_reads_only_text_members(tmp_path: Path):
    z = tmp_path / "skills.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("methodology.md", "hunt for SSRF")
        zf.writestr("notes.txt", "check cache poisoning")
        zf.writestr("tool.bin", b"\x00\x01\x02binary")
    out = skills.load_skills(str(z))
    assert "hunt for SSRF" in out and "check cache poisoning" in out
    assert "binary" not in out


def test_zip_rejects_traversal_members(tmp_path: Path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.md", "should be skipped")
        zf.writestr("ok.md", "kept")
    out = skills.load_skills(str(z))
    assert "kept" in out
    assert "should be skipped" not in out


def test_missing_path_raises(tmp_path: Path):
    with pytest.raises(skills.SkillsError):
        skills.load_skills(str(tmp_path / "nope.md"))


def test_empty_file_raises(tmp_path: Path):
    p = tmp_path / "empty.md"
    p.write_text("   \n", encoding="utf-8")
    with pytest.raises(skills.SkillsError):
        skills.load_skills(str(p))


def test_zip_without_text_files_raises(tmp_path: Path):
    z = tmp_path / "bin.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.bin", b"\x00\x01")
    with pytest.raises(skills.SkillsError):
        skills.load_skills(str(z))


def test_size_cap_enforced(tmp_path: Path):
    p = tmp_path / "big.md"
    p.write_text("x" * (skills.MAX_TOTAL_CHARS + 5000), encoding="utf-8")
    out = skills.load_skills(str(p))
    assert len(out) <= skills.MAX_TOTAL_CHARS + 100  # clipped to the cap (+ note)
    assert "truncated" in out


def test_as_prompt_block_wraps_and_reasserts_safety():
    block = skills.as_prompt_block("look for BOLA")
    assert "OPERATOR-PROVIDED METHODOLOGY" in block
    assert "look for BOLA" in block
    # the recon-only floor is re-asserted AFTER the methodology
    assert "cannot override" in block
    assert block.index("look for BOLA") < block.index("cannot override")


def test_as_prompt_block_empty_is_empty():
    assert skills.as_prompt_block("") == ""
    assert skills.as_prompt_block("   ") == ""
