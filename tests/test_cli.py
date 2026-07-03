"""Tests for the CLI — the no-dependency .env loader and the end-to-end `run --handouts` wiring.

These verify the documented `cp .env.example .env` flow actually populates the environment (and
never clobbers a real env var), and that a single `run --handouts` writes every handout artifact.
"""

from __future__ import annotations

import argparse
import os

from finagent_redrange import cli
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


def test_run_handouts_writes_every_artifact(tmp_path, monkeypatch) -> None:
    """One offline `run --handouts` must emit the scorecard + all five handout artifacts."""
    monkeypatch.setattr(cli, "RESULTS_DIR", tmp_path)
    args = argparse.Namespace(
        model="echo",
        controls="both",
        transcripts=False,
        sigma=False,
        sarif=False,
        assurance=False,
        compliance=False,
        navigator=False,
        handouts=True,
    )
    cli.run(args)

    assert (tmp_path / "scorecard.md").exists()
    assert (tmp_path / "scorecard.json").exists()
    assert len(list((tmp_path / "sigma").glob("*.yml"))) == len(cli.SCENARIOS)
    assert (tmp_path / "sigma" / "precision_report.md").exists()
    assert (tmp_path / "findings.sarif").exists()
    assert (tmp_path / "assurance" / "assurance-case.json").exists()
    assert (tmp_path / "compliance" / "crosswalk.json").exists()
    assert (tmp_path / "navigator" / "atlas-coverage.json").exists()
