"""Profile create/delete helpers."""

from pathlib import Path

import pytest

from mail_janitor.config import create_profile, delete_profile, list_profiles, profiles_dir


def test_create_and_delete_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    # Seed _example template
    example = tmp_path / "_example"
    example.mkdir()
    (example / "config.toml").write_text(
        'provider = "yahoo"\nemail = "you@example.com"\n', encoding="utf-8"
    )
    (example / "rules.yaml").write_text("keep: []\nstage: []\n", encoding="utf-8")
    (example / "firewall.yaml").write_text("version: 1\n", encoding="utf-8")
    (example / ".env.example").write_text(
        "MAIL_JANITOR_EMAIL=you@example.com\nMAIL_JANITOR_APP_PASSWORD=x\n",
        encoding="utf-8",
    )

    out = create_profile("Mom Yahoo", provider="yahoo")
    assert out["profile"] == "mom-yahoo"
    assert "mom-yahoo" in list_profiles()
    assert (profiles_dir() / "mom-yahoo" / "config.toml").exists()

    with pytest.raises(ValueError, match="already exists"):
        create_profile("mom-yahoo")

    with pytest.raises(ValueError, match="Switch"):
        delete_profile("mom-yahoo", active="mom-yahoo")

    deleted = delete_profile("mom-yahoo", active="other")
    assert deleted["deleted"] == "mom-yahoo"
    assert "mom-yahoo" not in list_profiles()
