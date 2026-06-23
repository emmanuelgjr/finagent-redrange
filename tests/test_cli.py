"""Tests for CLI helpers — the no-dependency .env loader.

These verify the documented `cp .env.example .env` flow actually populates the environment,
and (critically) that a real environment variable is never clobbered by the file.
"""

from __future__ import annotations

import os

from finagent_redrange.cli import load_dotenv


def test_load_dotenv_sets_unset_keys(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        '# a comment\nFINAGENT_DOTENV_X="hello"\nexport FINAGENT_DOTENV_Y=world\n\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("FINAGENT_DOTENV_X", raising=False)
    monkeypatch.delenv("FINAGENT_DOTENV_Y", raising=False)
    try:
        load_dotenv()
        assert os.environ["FINAGENT_DOTENV_X"] == "hello"  # quotes stripped
        assert os.environ["FINAGENT_DOTENV_Y"] == "world"  # `export ` prefix handled
    finally:
        os.environ.pop("FINAGENT_DOTENV_X", None)
        os.environ.pop("FINAGENT_DOTENV_Y", None)


def test_load_dotenv_does_not_override_real_env(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("FINAGENT_DOTENV_Z=fromfile\n", encoding="utf-8")
    monkeypatch.setenv("FINAGENT_DOTENV_Z", "fromenv")
    load_dotenv()
    assert os.environ["FINAGENT_DOTENV_Z"] == "fromenv"  # real env var wins
