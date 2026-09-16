from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace


class DeadThread:
    def is_alive(self):
        return False


class LiveThread:
    def is_alive(self):
        return True


def test_apply_job_manager(monkeypatch):
    import mail_janitor.web.apply_jobs as jobs

    mgr = jobs.ApplyJobManager()
    assert mgr.status()["state"] == "idle"
    mgr.heartbeat(x=1)
    assert not mgr.is_running()
    assert mgr.acknowledge()["state"] == "idle"

    mgr._status.update(
        state="running",
        started_at=jobs._now(),
        progress={"moved_this_job": 2, "remaining_estimate": 3, "folder": "Inbox"},
    )
    mgr.heartbeat(errors_this_job=1)
    assert mgr.status()["eta"]["total"] == 5
    assert mgr.is_running()
    mgr._thread = LiveThread()
    assert mgr._start("p", job="x", message="m", target=lambda: {})["ok"] is False

    mgr._thread = DeadThread()

    class ImmediateThread:
        def __init__(self, target, args, **kwargs):
            self.target, self.args = target, args

        def start(self):
            pass

        def is_alive(self):
            return False

    monkeypatch.setattr(jobs.threading, "Thread", ImmediateThread)
    notified = []
    monkeypatch.setattr(jobs, "notify_job", lambda *a, **k: notified.append((a, k)))
    monkeypatch.setattr(jobs, "load_profile", lambda n: SimpleNamespace())
    monkeypatch.setattr(jobs, "apply_to_ready", lambda *a, **k: {"moved": 2})
    monkeypatch.setattr(jobs, "apply_to_kept", lambda *a, **k: {"moved": 1})
    assert mgr.start_apply("p", "yes")["ok"]
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "done"
    assert mgr.start_apply_kept("p", "yes")["ok"]
    mgr._thread.target(*mgr._thread.args)
    assert notified
    mgr._thread = DeadThread()
    mgr._start(
        "p",
        job="bad",
        message="m",
        target=lambda: (_ for _ in ()).throw(ValueError("boom")),
    )
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "error"


def test_stage_job_manager(monkeypatch):
    import mail_janitor.web.stage_jobs as jobs

    mgr = jobs.StageJobManager()
    assert mgr.status()["state"] == "idle"
    mgr.heartbeat(x=1)
    mgr._status.update(
        state="running",
        started_at=jobs._now(),
        progress={"rules_done": 1, "rules_total": 2},
    )
    mgr.heartbeat(extra=1)
    assert mgr.status()["eta"]
    mgr._thread = LiveThread()
    assert not mgr.start("p")["ok"]

    class ImmediateThread:
        def __init__(self, target, args, **kwargs):
            self.target, self.args = target, args

        def start(self):
            pass

        def is_alive(self):
            return False

    monkeypatch.setattr(jobs.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(jobs, "load_profile", lambda n: SimpleNamespace())
    monkeypatch.setattr(
        jobs,
        "stage_rules",
        lambda *a, **k: {"staged_included": 2, "rules_applied": ["a"]},
    )
    mgr._thread = DeadThread()
    assert mgr.start("p", ["a"], True)["ok"]
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "done"
    monkeypatch.setattr(
        jobs, "stage_rules", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    mgr._thread = DeadThread()
    mgr.start("p")
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "error"


def test_insights_job_manager(monkeypatch, tmp_path):
    import mail_janitor.web.insights_jobs as jobs

    monkeypatch.setenv("MAIL_JANITOR_PUBLIC_BASE", "/base/")
    assert jobs._public_base() == "/base"
    assert jobs._ui("x") == "/base/x"
    monkeypatch.delenv("MAIL_JANITOR_PUBLIC_BASE")
    assert jobs._ui("/x") == "/x"

    mgr = jobs.InsightsRulesJobManager()
    mgr.heartbeat(x=1)
    mgr._status.update(
        state="running",
        started_at=jobs._now(),
        progress={"done": 1, "total": 2, "phase": "write"},
    )
    mgr.heartbeat(extra=1)
    assert mgr.status()["eta"]
    mgr._thread = LiveThread()
    assert not mgr.start("p", [], "keep")["ok"]

    class ImmediateThread:
        def __init__(self, target, args, **kwargs):
            self.target, self.args = target, args

        def start(self):
            pass

        def is_alive(self):
            return False

    monkeypatch.setattr(jobs.threading, "Thread", ImmediateThread)
    profile = SimpleNamespace(rules_path=tmp_path / "rules.yaml")
    monkeypatch.setattr(jobs, "load_profile", lambda n: profile)
    monkeypatch.setattr(
        jobs,
        "rules_from_insight_selections",
        lambda *a, **k: [SimpleNamespace(id="r", label="Rule")],
    )
    mgr._thread = DeadThread()
    mgr.start("p", [{"x": 1}], "keep")
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["result"]["next"] == "/rules"
    mgr._thread = DeadThread()
    mgr.start("p", [], "stage")
    mgr._thread.target(*mgr._thread.args)
    assert "suggestions" in mgr.status()["result"]["next"]
    assert json.loads((tmp_path / "last_focus_batch.json").read_text()) == ["r"]
    monkeypatch.setattr(
        jobs,
        "rules_from_insight_selections",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("bad")),
    )
    mgr._thread = DeadThread()
    mgr.start("p", [], "stage")
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "error"

    # Focus persistence is best effort.
    profile.rules_path = tmp_path / "missing" / "rules.yaml"
    monkeypatch.setattr(
        jobs,
        "rules_from_insight_selections",
        lambda *a, **k: [SimpleNamespace(id="r", label="Rule")],
    )
    mgr._thread = DeadThread()
    mgr.start("p", [], "stage")
    mgr._thread.target(*mgr._thread.args)
    assert mgr.status()["state"] == "done"


def test_scan_job_file_helpers(monkeypatch, tmp_path):
    import mail_janitor.web.scan_jobs as jobs

    p = SimpleNamespace(db_path=tmp_path / "mail.db")
    monkeypatch.setattr(jobs, "load_profile", lambda n: p)
    assert jobs._status_path_for("p").parent == tmp_path
    path = tmp_path / "s.json"
    jobs._atomic_write(path, {"x": 1})
    assert jobs._read_status(path) == {"x": 1}
    path.write_text("bad")
    assert jobs._read_status(path) is None
    assert jobs._read_status(tmp_path / "missing") is None
    idle = jobs._idle_status()
    assert idle["state"] == "idle"
    run = dict(
        idle,
        state="running",
        started_at=jobs._now(),
        progress={"uids_done": 0, "uids_planned": None, "phase": "planned"},
    )
    assert "Planning" in jobs._enrich(run)["message"]
    run["progress"] = {
        "uids_done": 2,
        "uids_planned": 5,
        "phase": "batch",
        "folder": "Inbox",
    }
    assert "Scanning" in jobs._enrich(run)["message"]

    # Atomic write cleanup on replace failure.
    monkeypatch.setattr(
        jobs.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("replace"))
    )
    monkeypatch.setattr(
        jobs.os, "unlink", lambda *a: (_ for _ in ()).throw(OSError("unlink"))
    )
    try:
        jobs._atomic_write(tmp_path / "bad.json", {})
    except OSError:
        pass


def test_scan_worker_success_repair_and_error(monkeypatch, tmp_path):
    import mail_janitor.web.scan_jobs as jobs

    path = tmp_path / "status.json"
    jobs._atomic_write(path, dict(jobs._idle_status(), state="running"))
    profile = SimpleNamespace(db_path=tmp_path / "mail.db")
    monkeypatch.setattr(jobs, "load_profile", lambda n: profile)
    monkeypatch.setattr(jobs, "message_count", lambda c: 4)
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(jobs, "init_db", lambda p: conn)
    monkeypatch.setattr(
        jobs,
        "scan_mailbox",
        lambda *a, **k: (
            k["progress_cb"](uids_done=1)
            or {"messages_upserted": 2}
        ),
    )
    monkeypatch.setattr(
        jobs, "blank_header_stats", lambda p: {"needs_repair": True, "blank": 1}
    )
    monkeypatch.setattr(jobs, "refresh_blank_headers", lambda p: {"repaired": 1})
    monkeypatch.setattr(jobs, "notify_job", lambda *a, **k: None)
    jobs._scan_worker("p", True, str(path))
    assert jobs._read_status(path)["state"] == "done"

    monkeypatch.setattr(
        jobs, "load_profile", lambda n: (_ for _ in ()).throw(ValueError("bad"))
    )
    jobs._scan_worker("p", True, str(path))
    assert jobs._read_status(path)["state"] == "error"

    # Heartbeats ignore stale/non-running status.
    jobs._atomic_write(path, jobs._idle_status())
    monkeypatch.setattr(jobs, "load_profile", lambda n: profile)
    monkeypatch.setattr(
        jobs,
        "scan_mailbox",
        lambda *a, **k: (
            k["progress_cb"](uids_done=1) or {"messages_upserted": 0}
        ),
    )
    monkeypatch.setattr(
        jobs, "blank_header_stats", lambda p: {"needs_repair": False}
    )
    jobs._scan_worker("p", True, str(path))


def test_scan_job_manager(monkeypatch, tmp_path):
    import mail_janitor.web.scan_jobs as jobs

    mgr = jobs.ScanJobManager()
    assert mgr.status()["state"] == "idle"
    mgr.heartbeat(x=1)
    mgr._proc = LiveThread()
    assert not mgr.start("p")["ok"]

    class Proc:
        exitcode = 7

        def __init__(self, *a, **k):
            self.alive = True

        def start(self):
            pass

        def is_alive(self):
            return self.alive

    path = tmp_path / "s.json"
    monkeypatch.setattr(jobs, "_status_path_for", lambda n: path)
    monkeypatch.setattr(
        jobs.mp,
        "get_context",
        lambda n: SimpleNamespace(Process=lambda *a, **k: Proc()),
    )
    mgr._proc = None
    assert mgr.start("p", False)["ok"]
    mgr.heartbeat(uids_done=1)
    assert jobs._read_status(path)["progress"]["uids_done"] == 1

    mgr._proc.alive = False
    jobs._atomic_write(path, dict(jobs._read_status(path), state="running"))
    assert mgr.status()["state"] == "error"

    mgr._proc = Proc()
    mgr._proc.alive = False
    jobs._atomic_write(path, dict(jobs._idle_status(), state="running"))
    real_write = jobs._atomic_write
    monkeypatch.setattr(
        jobs,
        "_atomic_write",
        lambda *a, **k: (_ for _ in ()).throw(OSError("write")),
    )
    assert mgr.status()["state"] == "error"
    monkeypatch.setattr(jobs, "_atomic_write", real_write)

    mgr._proc = Proc()
    mgr._proc.alive = False
    jobs._atomic_write(path, dict(jobs._idle_status(), state="done"))
    assert mgr.status()["state"] == "done"

    mgr._status_path = path
    jobs._atomic_write(path, dict(jobs._idle_status(), state="idle"))
    mgr.heartbeat(x=1)
