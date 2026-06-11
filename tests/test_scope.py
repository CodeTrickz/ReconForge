"""Tests for authorized target scope handling."""

import pytest

from reconforge.core.scope import AuthorizedScope


def test_scope_file_accepts_ipv4_and_cidr_entries(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n192.168.1.0/24\n", encoding="utf-8")

    scope = AuthorizedScope.from_file(scope_file)

    scope.assert_targets_allowed("127.0.0.1", ["127.0.0.1"])
    scope.assert_targets_allowed("192.168.1.0/24", ["192.168.1.10"])


def test_scope_file_rejects_empty_files(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment only\n", encoding="utf-8")

    with pytest.raises(ValueError, match="contains no authorized targets"):
        AuthorizedScope.from_file(scope_file)


def test_scope_rejects_out_of_scope_hosts(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.0.0.0/24\n", encoding="utf-8")

    scope = AuthorizedScope.from_file(scope_file)

    with pytest.raises(ValueError, match="Target outside authorized scope"):
        scope.assert_targets_allowed("127.0.0.1", ["127.0.0.1"])
