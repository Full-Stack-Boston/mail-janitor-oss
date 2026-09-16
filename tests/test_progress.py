"""Tests for progress / ETA helpers."""

from mail_janitor.progress import eta_seconds, format_duration, progress_snapshot


def test_format_duration():
    assert format_duration(9) == "9s"
    assert format_duration(65) == "1m 05s"
    assert format_duration(3661) == "1h 01m"
    assert format_duration(None) == "—"


def test_eta_seconds_needs_sample():
    assert eta_seconds(done=1, total=100, elapsed_sec=10, min_done=3) is None
    eta = eta_seconds(done=50, total=100, elapsed_sec=50, min_done=3)
    assert eta == 50


def test_progress_snapshot_summary():
    from datetime import datetime, timedelta, timezone

    started = (datetime.now(timezone.utc) - timedelta(seconds=50)).isoformat()
    snap = progress_snapshot(
        done=100,
        total=200,
        started_at=started,
        label="moved",
        min_done=3,
    )
    assert snap["done"] == 100
    assert snap["total"] == 200
    assert snap["eta_sec"] == 50
    assert "100/200 moved" in snap["summary"]
    assert "ETA" in snap["summary"]
