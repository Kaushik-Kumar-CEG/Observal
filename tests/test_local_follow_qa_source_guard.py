# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Source-backed QA producer must refuse unrelated 127.0.0.1 services."""

import importlib.util
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE = Path(__file__).resolve().parent / "integration_mobile/local_follow_qa/source_fixture.py"
spec = importlib.util.spec_from_file_location("local_follow_source_fixture_guard", MODULE)
source = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(source)


@pytest.fixture
def owned(monkeypatch, tmp_path):
    qa = tmp_path / "local_follow_qa"
    qa.mkdir()
    monkeypatch.setattr(source, "__file__", str(qa / "source_fixture.py"))
    state = qa / ".runtime"
    state.mkdir()
    (state / "id").write_text("followqa1234567890\n")
    (state / "issuer-port").write_text("18443\n")
    runtime = Path(tempfile.mkdtemp(prefix="observal-follow-qa.", dir="/tmp"))
    (state / "run").write_text(str(runtime) + "\n")
    monkeypatch.setenv("MOBILE_FOLLOW_LOCAL_QA", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://followqa:test@127.0.0.1:15440/followqa")
    monkeypatch.setenv("CLICKHOUSE_URL", "http://followqa:test@127.0.0.1:18123/followqa")
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime)


def test_owned_labeled_pg_and_clickhouse_must_match_published_ports(monkeypatch, owned):
    def docker(args, **kwargs):
        assert kwargs["check"] and kwargs["timeout"] == 8
        if args[1] == "inspect":
            return SimpleNamespace(stdout="followqa1234567890\n")
        assert args[1] == "port"
        return SimpleNamespace(stdout="127.0.0.1:15440\n" if args[2].endswith("pg") else "127.0.0.1:18123\n")

    monkeypatch.setattr(source.subprocess, "run", docker)
    assert source.require_disposable_environment() == owned


@pytest.mark.parametrize("suffix", ("pg", "ch"))
def test_reject_wrong_docker_ownership_or_port(monkeypatch, owned, suffix):
    def docker(args, **_kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(stdout="not-the-session\n" if args[-1].endswith(suffix) else "followqa1234567890\n")
        return SimpleNamespace(stdout="127.0.0.1:15440\n" if args[2].endswith("pg") else "127.0.0.1:18123\n")

    monkeypatch.setattr(source.subprocess, "run", docker)
    with pytest.raises(RuntimeError, match="unrelated loopback"):
        source.require_disposable_environment()


@pytest.mark.parametrize(
    ("state_name", "issuer_port"),
    (
        (".runtime-android-a1b2c3", 18446),
        (".runtime-android-next-a1b2c3", 18448),
        (".runtime-android-diagnostic-a1b2c3", 18449),
        (".runtime-android-verified-a1b2c3", 18450),
    ),
)
def test_android_issuer_is_separate_from_old_states(monkeypatch, owned, state_name, issuer_port):
    qa = Path(source.__file__).resolve().parent
    (qa / ".runtime").rename(qa / state_name)
    state = qa / state_name
    (state / "issuer-port").write_text(f"{issuer_port}\n")
    monkeypatch.setenv("MOBILE_FOLLOW_QA_STATE_NAME", state_name)
    monkeypatch.setenv("MOBILE_FOLLOW_QA_PORT", str(issuer_port))
    monkeypatch.setattr(source, "ISSUER_PORT", issuer_port)

    def docker(args, **_kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(stdout="followqa1234567890\n")
        return SimpleNamespace(stdout="127.0.0.1:15440\n" if args[2].endswith("pg") else "127.0.0.1:18123\n")

    monkeypatch.setattr(source.subprocess, "run", docker)
    assert source.require_disposable_environment() == owned
    (state / "issuer-port").write_text("18443\n")
    with pytest.raises(RuntimeError, match="does not match selected issuer"):
        source.require_disposable_environment()


def test_unmarked_environment_never_contacts_docker(monkeypatch, owned):
    monkeypatch.delenv("MOBILE_FOLLOW_LOCAL_QA")
    monkeypatch.setattr(source.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("docker call"))
    with pytest.raises(RuntimeError, match="disposable loopback"):
        source.require_disposable_environment()
