from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message


class Job:
    def __init__(self):
        self.value = {"state": "idle", "job": None}
        self.ok = True

    def status(self):
        return dict(self.value)

    def is_running(self):
        return self.value.get("state") == "running"

    def start(self, *a, **k):
        return {"ok": self.ok, "error": "busy", "status": self.status()}

    def start_apply(self, *a, **k):
        return self.start()

    def start_apply_kept(self, *a, **k):
        return self.start()

    def start_restore_kept(self, *a, **k):
        return self.start()

    def start_to_trash(self, *a, **k):
        return self.start()

    def acknowledge(self):
        return self.status()


@pytest.fixture
def web_client(tmp_path, monkeypatch):
    import mail_janitor.web.app as web

    p = Profile(
        name="p",
        path=tmp_path,
        provider="imap",
        email="me@example.com",
        imap_host="imap.example.com",
        imap_port=993,
        imap_ssl=True,
        app_password="pw",
    )
    p.config_path.write_text(
        'provider="imap"\nemail="me@example.com"\nimap_host="imap.example.com"\n'
    )
    p.rules_path.write_text(
        """
keep:
  - id: keep-friend
    from_address: friend@example.com
stage:
  - id: stage-junk
    from_address: junk@bad.test
""",
        encoding="utf-8",
    )
    p.firewall_path.write_text("enabled: false\n")
    c = init_db(p.db_path)
    for uid, addr, domain in [
        (1, "junk@bad.test", "bad.test"),
        (2, "friend@example.com", "example.com"),
    ]:
        upsert_message(
            c,
            {
                "folder": "Inbox",
                "uid": uid,
                "from_addr": addr,
                "from_domain": domain,
                "subject": "sale" if uid == 1 else "hello",
                "date_ts": 1,
                "size": 10,
            },
        )
    c.execute(
        "INSERT INTO staged(folder,uid,rule_id,reason,included) VALUES('Inbox',1,'stage-junk','x',1)"
    )
    c.commit()
    c.close()

    monkeypatch.setattr(web, "client_mode", lambda: False)
    monkeypatch.setattr(web, "load_profile", lambda n: p)
    monkeypatch.setattr(web, "list_profiles", lambda: ["p", "other"])
    monkeypatch.setattr(web, "profile_summaries", lambda: [{"name": "p"}])
    monkeypatch.setattr(
        web.TEMPLATES,
        "TemplateResponse",
        lambda request, name, context: JSONResponse({"template": name}),
    )
    scan, apply, stage, insights = Job(), Job(), Job(), Job()
    monkeypatch.setattr(web, "SCAN_JOBS", scan)
    monkeypatch.setattr(web, "APPLY_JOBS", apply)
    monkeypatch.setattr(web, "STAGE_JOBS", stage)
    monkeypatch.setattr(web, "INSIGHTS_RULES_JOBS", insights)
    monkeypatch.setattr(
        web,
        "discover",
        lambda *a, **k: {
            "triage": {
                "likely_keep": [{"from_addr": "a@x"}],
                "likely_keep_total": 1,
            }
        },
    )
    monkeypatch.setattr(web, "coverage_stats", lambda p: {"total": 2})
    monkeypatch.setattr(web, "audit_keep_rules", lambda *a, **k: [])
    monkeypatch.setattr(
        web,
        "list_keep_rule_senders",
        lambda *a, **k: {"rows": [], "total": 0},
    )
    monkeypatch.setattr(
        web, "narrow_broad_keep_rule", lambda *a, **k: {"ok": True}
    )
    monkeypatch.setattr(
        web, "restore_broad_domain_keep", lambda *a, **k: {"ok": True}
    )
    monkeypatch.setattr(web, "preview_domain_suffix", lambda *a: {"rows": []})
    monkeypatch.setattr(
        web,
        "search_indexed",
        lambda *a, **k: {"rows": [], "total": 0},
    )
    monkeypatch.setattr(
        web,
        "search_imap_body",
        lambda *a, **k: {
            "rows": [{"from_addr": "a", "from_domain": "x"}]
        },
    )
    monkeypatch.setattr(web, "mark_seen", lambda *a: len(a[1]))
    monkeypatch.setattr(web, "reset_review_state", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(web, "clear_all_keep_rules", lambda *a, **k: {"cleared": 1})
    monkeypatch.setattr(web, "clear_all_stage_rules", lambda *a, **k: {"cleared": 1})
    monkeypatch.setattr(web, "preflight_staged", lambda *a, **k: {"count": 1})
    monkeypatch.setattr(web, "preflight_kept_inbox", lambda *a, **k: {"count": 1})
    monkeypatch.setattr(web, "refresh_blank_headers", lambda p: {"repaired": 1})
    monkeypatch.setattr(
        web, "blank_header_stats", lambda p: {"blank": 0, "needs_repair": False}
    )
    monkeypatch.setattr(web, "archive_dormant_stage_rules", lambda p: {"archived": 0})
    monkeypatch.setattr(
        web,
        "propose_cleanup_selections",
        lambda *a, **k: [{"kind": "from_address", "value": "a@x"}],
    )
    monkeypatch.setattr(
        web,
        "rules_from_insight_selections",
        lambda *a, **k: [SimpleNamespace(id="new", label="New")],
    )
    monkeypatch.setattr(web, "create_profile", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(web, "delete_profile", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(web, "apply_provider_pack", lambda *a, **k: None)
    monkeypatch.setattr(web, "write_profile_credentials", lambda *a, **k: None)
    monkeypatch.setattr(web, "test_imap_connection", lambda p: {"ok": True})
    monkeypatch.setattr(
        web,
        "list_staged",
        lambda *a, **k: (
            [
                {
                    "folder": "Inbox",
                    "uid": 1,
                    "date_ts": 1,
                    "size": 2,
                    "subject": "sale",
                    "from_addr": "a@x",
                }
            ],
            600,
        ),
    )
    monkeypatch.setattr(web, "set_staged_included", lambda *a: None)
    monkeypatch.setattr(web, "set_many_included", lambda *a: 1)
    monkeypatch.setattr(web, "set_all_staged_included", lambda *a, **k: 2)
    monkeypatch.setattr(web, "stage_rules", lambda *a, **k: {"staged": 1})
    monkeypatch.setattr(web, "stage_by_confidence", lambda *a, **k: {"matched": 1})
    monkeypatch.setattr(
        web, "add_keep_sender", lambda *a: SimpleNamespace(id="k")
    )
    monkeypatch.setattr(
        web, "add_stage_rule", lambda *a: SimpleNamespace(id="s")
    )
    monkeypatch.setattr(
        web, "delete_keep_rule", lambda *a: True
    )
    monkeypatch.setattr(web, "undo_from_ready", lambda *a, **k: {"restored": 1})
    monkeypatch.setattr(web, "undo_from_kept", lambda *a, **k: {"restored": 1})
    monkeypatch.setattr(web, "ready_to_trash", lambda *a, **k: {"moved": 1})
    monkeypatch.setattr(
        web, "preflight_end_stage", lambda *a, **k: {"kept_count": 1, "ready_count": 2}
    )

    body_client = SimpleNamespace(
        select=lambda *a, **k: None,
        fetch_body=lambda uid: ("text/plain", "body"),
        close=lambda: None,
    )
    monkeypatch.setattr(
        web,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: body_client),
    )
    app = web.create_app("p")
    return SimpleNamespace(
        client=TestClient(app),
        web=web,
        profile=p,
        jobs=(scan, apply, stage, insights),
        app=app,
    )


def test_web_pages_and_basic_apis(web_client, monkeypatch):
    c = web_client.client
    for path in (
        "/",
        "/guide",
        "/advanced",
        "/home",
        "/suggestions",
        "/insights",
        "/keepers",
        "/review?show_all=1&sort=triage",
        "/open?folder=Inbox&uid=1",
        "/rules",
    ):
        r = c.get(path)
        assert r.status_code in (200, 302), (path, r.text)
    for path in (
        "/api/stats",
        "/api/stats/detail",
        "/api/folders",
        "/api/scan/status",
        "/api/keepers/stats",
        "/api/keepers/keep-audit",
        "/api/keepers/broad-senders?rule_id=x",
        "/api/keepers/suffix-preview?suffix=.com",
        "/api/keepers/search?from_contains=a",
        "/api/keepers/search?body_keyword=x",
        "/api/staged",
        "/api/stage/status",
        "/api/preflight",
        "/api/preflight-kept",
        "/api/apply/status",
        "/api/rules/business-prefixes/preview",
        "/api/rules/from-insights/status",
        "/api/discover",
        "/api/providers",
        "/api/profiles",
        "/api/session/status",
        "/api/guide/protect-candidates",
        "/api/blank-headers",
        "/api/mission-control/status",
        "/export.csv",
    ):
        r = c.get(path)
        assert r.status_code == 200, (path, r.text)

    # Session focus file branches.
    focus = web_client.profile.path / "last_focus_batch.json"
    focus.write_text('["stage-junk"]')
    assert c.get("/suggestions?focus=session").status_code == 200
    focus.write_text("bad")
    assert c.get("/suggestions?focus=session").status_code == 200
    focus.unlink()
    assert c.get("/suggestions?focus=session").status_code == 200
    assert c.get("/review?page=2").status_code == 200
    monkeypatch.setattr(web_client.web, "list_staged", lambda *a, **k: ([], 1))
    assert c.get("/review?show_all=1").status_code == 200


def test_web_mutating_happy_paths(web_client, monkeypatch):
    c = web_client.client
    calls = [
        ("post", "/api/config/stage-folders", {"json": {"folders": ["Inbox"]}}),
        ("post", "/api/config/stage-folders", {"json": {"all_folders": True}}),
        ("post", "/api/scan", {"data": {"resume": 1}}),
        ("post", "/api/refresh-blank-headers", {}),
        (
            "post",
            "/api/keepers/narrow-keep",
            {"json": {"rule_id": "x", "keep_addresses": ["a@x"]}},
        ),
        (
            "post",
            "/api/keepers/narrow-keep",
            {"json": {"rule_id": "x", "exclude_addresses": ["b@x"]}},
        ),
        (
            "post",
            "/api/keepers/restore-domain-keep",
            {"json": {"domain": "x.com"}},
        ),
        (
            "post",
            "/api/rules/reset",
            {
                "json": {
                    "keep": True,
                    "confirm": "RESET ALL KEEP RULES",
                    "review_state": True,
                }
            },
        ),
        (
            "post",
            "/api/rules/reset",
            {"json": {"stage": True, "confirm": "RESET ALL STAGE RULES"}},
        ),
        (
            "post",
            "/api/keepers/mark-seen",
            {"json": {"items": [{"folder": "Inbox", "uid": 1}]}},
        ),
        (
            "post",
            "/api/keepers/keep-suffix",
            {"json": {"suffix": ".example.com"}},
        ),
        (
            "post",
            "/api/keepers/keep-bulk",
            {"json": {"kind": "subject_contains", "value": "invoice"}},
        ),
        (
            "post",
            "/api/keepers/keep-bulk",
            {"json": {"kind": "from_address", "values": ["a@x"]}},
        ),
        (
            "post",
            "/api/keepers/keep-bulk",
            {"json": {"kind": "from_address", "value": "a@x"}},
        ),
        (
            "post",
            "/api/staged/include",
            {"data": {"folder": "Inbox", "uid": 1, "included": 1}},
        ),
        ("post", "/api/staged/bulk", {"json": {"all": True, "included": False}}),
        (
            "post",
            "/api/staged/bulk",
            {"json": {"items": [{"folder": "Inbox", "uid": 1}]}},
        ),
        ("post", "/api/keep-sender", {"data": {"from_addr": "a@x"}}),
        (
            "post",
            "/api/stage?background=1",
            {"json": {"rule_ids": ["stage-junk"], "clear": True}},
        ),
        (
            "post",
            "/api/stage?background=0",
            {"json": {"rule_id": "stage-junk"}},
        ),
        (
            "post",
            "/api/stage/junk",
            {"json": {"limit": 2, "clear": True, "confidence": "junk"}},
        ),
        (
            "post",
            "/api/rules/update",
            {"json": {"rule_id": "stage-junk", "older_than_days": 2, "label": "x"}},
        ),
        ("post", "/api/rules/delete", {"json": {"rule_id": "stage-junk"}}),
        (
            "post",
            "/api/rules/stage",
            {"json": {"id": "another", "from_domain": "z.test"}},
        ),
        ("post", "/api/apply-kept", {"data": {"confirm": "x"}}),
        ("post", "/api/apply", {"data": {"confirm": "x"}}),
        ("post", "/api/apply/ack", {}),
        ("post", "/api/undo", {"data": {"confirm": "x"}}),
        ("post", "/api/undo-kept", {"data": {"confirm": "x"}}),
        ("post", "/api/to-trash", {"data": {"confirm": "x", "batch_size": 1}}),
        ("get", "/api/end-stage", {}),
        ("post", "/api/end-stage/restore-kept", {"data": {"confirm": "x"}}),
        ("post", "/api/end-stage/to-trash", {"data": {"confirm": "x", "batch_size": 1}}),
        (
            "post",
            "/api/rules/from-insights?background=1",
            {"json": {"selections": [{"kind": "from_address", "value": "a@x"}]}},
        ),
        (
            "post",
            "/api/rules/from-insights?background=0",
            {
                "json": {
                    "action": "keep",
                    "selections": [{"kind": "from_address", "value": "a@x"}],
                }
            },
        ),
        ("post", "/api/rules/propose-batch", {"json": {"kinds": "from_address"}}),
        (
            "post",
            "/api/rules/keep",
            {"json": {"id": "keep-new", "from_address": "z@x"}},
        ),
        (
            "post",
            "/api/rules/keep/delete",
            {"json": {"rule_id": "keep-new"}},
        ),
        ("post", "/api/profiles", {"json": {"name": "new", "provider": "imap"}}),
        ("delete", "/api/profiles/old", {}),
        ("post", "/api/profiles/switch", {"json": {"profile": "other"}}),
        (
            "post",
            "/api/guide/connect",
            {
                "json": {
                    "profile_name": "new",
                    "provider": "imap",
                    "email": "a@x",
                    "app_password": "pw",
                    "imap_host": "imap.example.com",
                }
            },
        ),
        ("post", "/api/rules/archive-dormant", {}),
    ]
    import mail_janitor.rules as rules

    monkeypatch.setattr(
        rules,
        "add_keep_domain_suffix",
        lambda *a: SimpleNamespace(id="k", label="K"),
    )
    monkeypatch.setattr(
        rules,
        "add_keep_rule",
        lambda *a: SimpleNamespace(id="k", label="K"),
    )
    monkeypatch.setattr(
        rules,
        "_selection_to_rule_data",
        lambda *a, **k: {"id": "k", "from_address": "a@x"},
    )
    monkeypatch.setattr(
        rules,
        "preview_business_prefix_matches",
        lambda *a: {"count": 1},
    )
    monkeypatch.setattr(
        rules,
        "add_stage_business_prefix_rule",
        lambda *a: SimpleNamespace(id="b", label="B"),
    )
    assert c.post("/api/rules/stage/business-prefixes").status_code == 200
    for method, path, kwargs in calls:
        r = getattr(c, method)(path, **kwargs)
        assert r.status_code == 200, (method, path, r.text)


def test_web_open_cache_and_busy_statuses(web_client):
    c, web = web_client.client, web_client.web
    web._BODY_CACHE.clear()
    assert c.get("/api/open?folder=Inbox&uid=1").json()["cached"] is False
    assert c.get("/api/open?folder=Inbox&uid=1").json()["cached"] is True
    web._BODY_CACHE["old"] = (0, "x")
    assert c.get("/api/open?folder=Inbox&uid=2").status_code == 200
    assert "old" not in web._BODY_CACHE

    scan, apply, stage, insights = web_client.jobs
    scan.value = {
        "state": "running",
        "progress": {"uids_done": 3, "uids_planned": 5},
    }
    assert c.get("/api/stats").json()["indexed_total"] is None
    assert c.get("/api/scan/status").json()["message_count_live"] == 3
    assert c.post("/api/refresh-blank-headers").status_code == 409
    assert c.delete("/api/profiles/old").status_code == 409
    assert c.post("/api/profiles/switch", json={"profile": "other"}).status_code == 409
    scan.ok = False
    assert c.post("/api/scan", data={"resume": 1}).status_code == 409

    scan.value = {"state": "idle"}
    apply.value = {
        "state": "running",
        "job": "apply-kept",
        "started_at": "2020-01-01T00:00:00+00:00",
        "progress": {
            "moved_this_job": 2,
            "remaining_estimate": 3,
            "last_ok_at": "2020-01-01T00:00:00+00:00",
        },
    }
    assert "kept still" in c.get("/api/apply/status").json()["message"]
    apply.ok = False
    assert c.post("/api/apply", data={"confirm": "x"}).status_code == 409
    assert c.post("/api/apply-kept", data={"confirm": "x"}).status_code == 409
    stage.ok = False
    assert c.post("/api/stage", json={}).status_code == 409
    insights.ok = False
    assert (
        c.post(
            "/api/rules/from-insights",
            json={"selections": [{"kind": "from_address", "value": "a@x"}]},
        ).status_code
        == 409
    )


def test_web_validation_errors(web_client, monkeypatch):
    c, web = web_client.client, web_client.web
    cases = [
        ("post", "/api/config/stage-folders", {"json": {"folders": "x"}}),
        ("post", "/api/keepers/narrow-keep", {"json": {}}),
        (
            "post",
            "/api/keepers/narrow-keep",
            {"json": {"rule_id": "r", "keep_addresses": "x"}},
        ),
        (
            "post",
            "/api/keepers/narrow-keep",
            {"json": {"rule_id": "r", "exclude_addresses": "x"}},
        ),
        (
            "post",
            "/api/keepers/narrow-keep",
            {"json": {"rule_id": "r"}},
        ),
        ("post", "/api/keepers/restore-domain-keep", {"json": {}}),
        ("post", "/api/rules/reset", {"json": {}}),
        ("post", "/api/rules/reset", {"json": {"keep": True, "confirm": "bad"}}),
        ("post", "/api/rules/reset", {"json": {"stage": True, "confirm": "bad"}}),
        ("post", "/api/keepers/keep-bulk", {"json": {}}),
        (
            "post",
            "/api/keepers/keep-bulk",
            {"json": {"kind": "subject_contains"}},
        ),
        ("post", "/api/stage/junk", {"content": "{", "headers": {"content-type": "application/json"}}),
        ("post", "/api/rules/update", {"json": {}}),
        ("post", "/api/rules/delete", {"json": {}}),
        ("post", "/api/rules/from-insights", {"json": {}}),
        (
            "post",
            "/api/rules/from-insights",
            {"json": {"action": "bad", "selections": [{}]}},
        ),
        (
            "post",
            "/api/rules/from-insights",
            {
                "json": {
                    "action": "keep",
                    "selections": [{"kind": "older_than_days", "value": 1}],
                }
            },
        ),
        (
            "post",
            "/api/rules/from-insights",
            {
                "json": {
                    "selections": [
                        {"kind": "from_address", "value": "me@example.com"}
                    ]
                }
            },
        ),
        ("post", "/api/rules/keep/delete", {"json": {}}),
        ("post", "/api/profiles/switch", {"json": {"profile": "missing"}}),
    ]
    for method, path, kwargs in cases:
        r = getattr(c, method)(path, **kwargs)
        assert 400 <= r.status_code < 500, (path, r.text)
    assert c.post("/api/session/end").status_code == 400

    monkeypatch.setattr(
        web, "search_indexed", lambda *a, **k: (_ for _ in ()).throw(ValueError("x"))
    )
    assert c.get("/api/keepers/search?from_contains=x").status_code == 400
    monkeypatch.setattr(
        web, "search_imap_body", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert c.get("/api/keepers/search?body_keyword=x").status_code == 500
    monkeypatch.setattr(
        web, "search_imap_body", lambda *a, **k: (_ for _ in ()).throw(ValueError("x"))
    )
    assert c.get("/api/keepers/search?body_keyword=x").status_code == 400
    monkeypatch.setattr(
        web, "propose_cleanup_selections", lambda *a, **k: []
    )
    assert c.post("/api/rules/propose-batch", json={}).status_code == 400


def test_web_function_error_branches(web_client, monkeypatch):
    c, web = web_client.client, web_client.web
    assert web._mj_list_folders(web_client.profile)
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "bad")
    assert c.get("/api/stats").status_code == 200
    monkeypatch.delenv("MAIL_JANITOR_SESSION_TTL_HOURS")

    monkeypatch.setattr(
        web,
        "save_stage_folders",
        lambda *a: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert c.post("/api/config/stage-folders", json={"folders": ["x"]}).status_code == 400
    monkeypatch.setattr(web, "save_stage_folders", lambda *a: None)
    for attr, path in [
        ("list_keep_rule_senders", "/api/keepers/broad-senders?rule_id=x"),
        ("preview_domain_suffix", "/api/keepers/suffix-preview?suffix=x"),
    ]:
        monkeypatch.setattr(
            web, attr, lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
        )
        assert c.get(path).status_code == 400
    monkeypatch.setattr(
        web, "narrow_broad_keep_rule", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert (
        c.post(
            "/api/keepers/narrow-keep",
            json={"rule_id": "x", "keep_addresses": []},
        ).status_code
        == 400
    )
    monkeypatch.setattr(
        web, "restore_broad_domain_keep", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert c.post("/api/keepers/restore-domain-keep", json={"domain": "x"}).status_code == 400

    import mail_janitor.rules as rules

    monkeypatch.setattr(
        rules,
        "add_keep_domain_suffix",
        lambda *a: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert c.post("/api/keepers/keep-suffix", json={"suffix": "x"}).status_code == 400
    # Form-data staging branch.
    assert (
        c.post(
            "/api/stage?background=0",
            data={"rule_id": "x", "clear": "on"},
        ).status_code
        == 200
    )
    monkeypatch.setattr(
        web, "stage_rules", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad"))
    )
    assert c.post("/api/stage?background=0", json={}).status_code == 500
    assert c.post("/api/stage/junk", json={"confidence": "junk"}).status_code == 200
    monkeypatch.setattr(
        web, "stage_by_confidence", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert c.post("/api/stage/junk", json={}).status_code == 400
    monkeypatch.setattr(
        web, "stage_by_confidence", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad"))
    )
    assert c.post("/api/stage/junk", json={}).status_code == 500

    monkeypatch.setattr(
        rules, "update_stage_rule", lambda *a: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert c.post("/api/rules/update", json={"rule_id": "x"}).status_code == 404
    monkeypatch.setattr(rules, "delete_stage_rule", lambda *a: False)
    assert c.post("/api/rules/delete", json={"rule_id": "x"}).status_code == 404
    monkeypatch.setattr(web, "delete_keep_rule", lambda *a: False)
    assert c.post("/api/rules/keep/delete", json={"rule_id": "x"}).status_code == 404

    for attr, path in [
        ("undo_from_ready", "/api/undo"),
        ("undo_from_kept", "/api/undo-kept"),
        ("ready_to_trash", "/api/to-trash"),
    ]:
        monkeypatch.setattr(
            web, attr, lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
        )
        assert c.post(path, data={"confirm": "x"}).status_code == 400

    monkeypatch.setattr(
        web.APPLY_JOBS,
        "start_restore_kept",
        lambda *a, **k: {"ok": False, "error": "busy"},
    )
    assert c.post("/api/end-stage/restore-kept", data={"confirm": "x"}).status_code == 409
    monkeypatch.setattr(
        web.APPLY_JOBS,
        "start_to_trash",
        lambda *a, **k: {"ok": False, "error": "busy"},
    )
    assert c.post("/api/end-stage/to-trash", data={"confirm": "x"}).status_code == 409

    monkeypatch.setattr(
        web,
        "rules_from_insight_selections",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("bad")),
    )
    body = {"selections": [{"kind": "from_address", "value": "a@x"}]}
    assert c.post("/api/rules/from-insights?background=0", json=body).status_code == 400
    assert c.post("/api/rules/propose-batch", json={}).status_code == 400

    monkeypatch.setattr(
        web, "create_profile", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert c.post("/api/profiles", json={"name": "x"}).status_code == 400
    monkeypatch.setattr(
        web, "delete_profile", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("bad"))
    )
    assert c.delete("/api/profiles/x").status_code == 404
    monkeypatch.setattr(
        web, "delete_profile", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert c.delete("/api/profiles/x").status_code == 400

    monkeypatch.setattr(
        web, "test_imap_connection", lambda p: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert (
        c.post(
            "/api/guide/connect",
            json={"provider": "imap", "email": "a@x", "app_password": "x"},
        ).status_code
        == 400
    )


def test_web_foreground_stage_insights_and_status_variants(web_client, monkeypatch):
    c, web = web_client.client, web_client.web
    body = {
        "action": "stage",
        "selections": [{"kind": "from_address", "value": "a@x"}],
    }
    assert c.post("/api/rules/from-insights?background=0", json=body).status_code == 200
    monkeypatch.setenv("MAIL_JANITOR_PUBLIC_BASE", "/mail")
    assert c.post("/api/rules/from-insights?background=0", json=body).json()["next"].startswith("/mail")
    assert c.post("/api/rules/propose-batch", json={}).json()["next"].startswith("/mail")
    monkeypatch.delenv("MAIL_JANITOR_PUBLIC_BASE")
    original_path = web_client.profile.path
    web_client.profile.path = original_path / "missing"
    assert c.post("/api/rules/from-insights?background=0", json=body).status_code == 200
    web_client.profile.path = original_path

    _, apply, _, _ = web_client.jobs
    apply.value = {
        "state": "running",
        "job": "apply",
        "started_at": "2020-01-01T00:00:00+00:00",
        "progress": {"moved_this_job": 1, "last_ok_at": "not-a-date"},
    }
    out = c.get("/api/apply/status").json()
    assert out["seconds_since_last_ok"] is None and "staged left" in out["message"]
    apply.value["progress"]["last_ok_at"] = datetime_now = __import__(
        "datetime"
    ).datetime.now(__import__("datetime").timezone.utc).isoformat()
    assert "last ok" in c.get("/api/apply/status").json()["message"]
    apply.value = {"state": "idle", "job": "apply-kept"}
    assert c.get("/api/apply/status").json()["preflight"]["count"] == 1

    scan, apply, _, _ = web_client.jobs
    scan.value = {"state": "running", "progress": {"uids_done": 2}}
    assert c.get("/api/mission-control/status").json()["blank_headers"] is None
    scan.value = {"state": "idle"}
    monkeypatch.setattr(
        web,
        "blank_header_stats",
        lambda p: (_ for _ in ()).throw(RuntimeError("bad")),
    )
    assert c.get("/api/mission-control/status").json()["blank_headers"] is None


def test_run_server(monkeypatch, web_client):
    import sys
    import mail_janitor.web.app as web

    called = []
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda *a, **k: called.append((a, k))),
    )
    monkeypatch.setattr(web, "create_app", lambda n: "app")
    web.run_server("p", port=1)
    assert called


def test_client_mode_middleware_and_sessions(tmp_path, monkeypatch):
    import mail_janitor.web.app as web

    p = Profile("u", tmp_path, "imap", "a@x", "h", 993, True, app_password="pw")
    p.rules_path.write_text("keep: []\nstage: []")
    state = {"uid": None}
    monkeypatch.setattr(web, "client_mode", lambda: True)
    monkeypatch.setattr(web, "current_uid", lambda: state["uid"])
    monkeypatch.setattr(web, "start_reaper_thread", lambda: None)
    monkeypatch.setattr(web, "load_profile", lambda n: p)
    monkeypatch.setattr(web, "ensure_workspace", lambda uid: tmp_path)
    monkeypatch.setattr(web, "touch_activity", lambda uid: None)
    monkeypatch.setattr(web, "clear_request_identity", lambda: state.update(uid=None))
    monkeypatch.setattr(
        web,
        "set_request_identity",
        lambda uid, email: state.update(uid=uid) or uid,
    )
    monkeypatch.setattr(
        web,
        "parse_authentik_headers",
        lambda h: (
            (h.get("x-authentik-uid"), "")
            if h.get("x-authentik-uid")
            else (_ for _ in ()).throw(PermissionError("sign in"))
        ),
    )
    monkeypatch.setattr(web, "session_status", lambda uid: {"ok": True})
    monkeypatch.setattr(web, "wipe_session", lambda uid: {"wiped": uid})
    monkeypatch.setattr(web, "profile_summaries", lambda: [])
    monkeypatch.setattr(
        web.TEMPLATES,
        "TemplateResponse",
        lambda request, name, context: JSONResponse({"template": name}),
    )
    app = web.create_app("ignored")
    c = TestClient(app)
    assert c.get("/api/session/status").status_code == 401
    assert c.get("/guide").status_code == 401
    assert c.get("/guide", headers={"accept": "text/html"}).status_code == 401
    h = {"x-authentik-uid": "u"}
    assert c.get("/api/session/status", headers=h).status_code == 200
    assert c.get("/guide", headers=h).status_code == 200
    assert c.post("/api/session/end", headers=h).status_code == 200
    # Health endpoint bypasses auth and has a dedicated anonymous response.
    assert c.get("/api/mission-control/status").status_code == 200
    assert c.post("/api/profiles", headers=h, json={}).status_code == 403
    assert c.delete("/api/profiles/x", headers=h).status_code == 403
    assert c.post("/api/profiles/switch", headers=h, json={}).status_code == 403

    monkeypatch.setattr(web, "validate_imap_host", lambda h, p: h)
    monkeypatch.setattr(web, "apply_provider_pack", lambda *a, **k: None)
    monkeypatch.setattr(web, "write_profile_credentials", lambda *a, **k: None)
    monkeypatch.setattr(web, "test_imap_connection", lambda p: {"ok": True})
    assert (
        c.post(
            "/api/guide/connect",
            headers=h,
            json={
                "provider": "imap",
                "email": "a@x",
                "app_password": "pw",
                "imap_host": "mail.example.com",
            },
        ).status_code
        == 200
    )

    # Handler-level identity defenses (normally preempted by outer middleware).
    def endpoint(path, method):
        return next(
            route.endpoint
            for route in app.routes
            if getattr(route, "path", None) == path and method in getattr(route, "methods", set())
        )

    state["uid"] = None
    with pytest.raises(Exception):
        endpoint("/guide", "GET")(None)
    with pytest.raises(Exception):
        endpoint("/api/session/status", "GET")()
    with pytest.raises(Exception):
        endpoint("/api/session/end", "POST")()

    import asyncio

    class Req:
        async def json(self):
            return {"provider": "imap", "email": "a@x", "app_password": "x"}

    with pytest.raises(Exception):
        asyncio.run(endpoint("/api/guide/connect", "POST")(Req()))

    root = endpoint("/", "GET")
    closure = dict(zip(root.__code__.co_freevars, root.__closure__ or ()))
    assert closure["_abs"].cell_contents("guide") == "/guide"

    # Busy session cannot be wiped.
    state["uid"] = "u"
    monkeypatch.setattr(web.APPLY_JOBS, "is_running", lambda: True)
    assert c.post("/api/session/end", headers=h).status_code == 409

    monkeypatch.setattr(
        web,
        "parse_authentik_headers",
        lambda h: (_ for _ in ()).throw(ValueError("bad headers")),
    )
    with pytest.raises(Exception):
        c.get("/guide", headers=h)


def test_base_template_includes_scripts_block():
    """If base.html omits {% block scripts %}, guide/insights JS never loads."""
    templates = Path(__file__).resolve().parents[1] / "src/mail_janitor/web/templates"
    base = (templates / "base.html").read_text(encoding="utf-8")
    guide = (templates / "guide.html").read_text(encoding="utf-8")
    assert "{% block scripts %}" in base
    assert "{% block scripts %}" in guide
    assert "btn-test-connect" in guide
    assert "Checking your sign-in" in guide


def test_guide_connect_restores_env_on_imap_failure(web_client, monkeypatch, tmp_path):
    c, web = web_client.client, web_client.web
    profile_dir = tmp_path / "restore-me"
    profile_dir.mkdir()
    env_path = profile_dir / ".env"
    env_path.write_text(
        "MAIL_JANITOR_EMAIL=old@x\nMAIL_JANITOR_APP_PASSWORD=oldpw\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(web, "ensure_profile_files", lambda n: profile_dir)
    monkeypatch.setattr(web, "apply_provider_pack", lambda *a, **k: None)
    monkeypatch.setattr(
        web,
        "write_profile_credentials",
        lambda *a, **k: env_path.write_text(
            "MAIL_JANITOR_EMAIL=new@x\nMAIL_JANITOR_APP_PASSWORD=newpw\n",
            encoding="utf-8",
        ),
    )
    monkeypatch.setattr(
        web, "test_imap_connection", lambda p: (_ for _ in ()).throw(ValueError("bad"))
    )
    assert (
        c.post(
            "/api/guide/connect",
            json={
                "profile_name": "restore-me",
                "provider": "imap",
                "email": "new@x",
                "app_password": "newpw",
                "imap_host": "imap.example.com",
            },
        ).status_code
        == 400
    )
    assert "old@x" in env_path.read_text(encoding="utf-8")


def test_guide_connect_client_mode_clears_creds_on_failure(web_client, monkeypatch):
    c, web = web_client.client, web_client.web
    monkeypatch.setattr(web, "client_mode", lambda: True)
    monkeypatch.setattr(web, "current_uid", lambda: "sess1")
    monkeypatch.setattr(web, "validate_imap_host", lambda *a, **k: "imap.example.com")
    monkeypatch.setattr(web, "apply_provider_pack", lambda *a, **k: None)
    monkeypatch.setattr(web, "ensure_profile_files", lambda n: web_client.profile.path)
    monkeypatch.setattr(web, "write_profile_credentials", lambda *a, **k: None)
    monkeypatch.setattr(
        web, "test_imap_connection", lambda p: (_ for _ in ()).throw(ValueError("bad"))
    )
    cleared = []
    restored = []

    import mail_janitor.client_sessions as sessions

    monkeypatch.setattr(sessions, "load_credentials", lambda n: None)
    monkeypatch.setattr(sessions, "clear_credentials", lambda n: cleared.append(n))
    assert (
        c.post(
            "/api/guide/connect",
            json={
                "provider": "imap",
                "email": "a@x",
                "app_password": "x",
                "imap_host": "imap.example.com",
            },
            headers={"X-authentik-uid": "sess1"},
        ).status_code
        == 400
    )
    assert cleared == ["sess1"]

    # Prior client creds are restored when IMAP fails.
    monkeypatch.setattr(
        sessions, "load_credentials", lambda n: ("old@x", "oldpw")
    )
    monkeypatch.setattr(
        sessions,
        "store_credentials",
        lambda n, e, p: restored.append((n, e, p)),
    )
    assert (
        c.post(
            "/api/guide/connect",
            json={
                "provider": "imap",
                "email": "a@x",
                "app_password": "x",
                "imap_host": "imap.example.com",
            },
            headers={"X-authentik-uid": "sess1"},
        ).status_code
        == 400
    )
    assert restored == [("sess1", "old@x", "oldpw")]


def test_guide_connect_unlink_oserror_is_swallowed(web_client, monkeypatch, tmp_path):
    c, web = web_client.client, web_client.web
    profile_dir = tmp_path / "new-only"
    profile_dir.mkdir()
    env_path = profile_dir / ".env"
    monkeypatch.setattr(web, "ensure_profile_files", lambda n: profile_dir)
    monkeypatch.setattr(web, "apply_provider_pack", lambda *a, **k: None)
    monkeypatch.setattr(
        web,
        "write_profile_credentials",
        lambda *a, **k: env_path.write_text("x\n", encoding="utf-8"),
    )
    monkeypatch.setattr(
        web, "test_imap_connection", lambda p: (_ for _ in ()).throw(ValueError("bad"))
    )
    real_unlink = Path.unlink

    def boom(self, *a, **k):
        if self == env_path:
            raise OSError("busy")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", boom)
    assert (
        c.post(
            "/api/guide/connect",
            json={
                "profile_name": "new-only",
                "provider": "imap",
                "email": "a@x",
                "app_password": "x",
                "imap_host": "imap.example.com",
            },
        ).status_code
        == 400
    )
