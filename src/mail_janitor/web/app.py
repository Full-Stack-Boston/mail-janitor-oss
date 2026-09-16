"""Local FastAPI review UI — metadata list; body on request only."""

from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from mail_janitor.apply import (
    CONFIRM_KEPT,
    CONFIRM_READY,
    CONFIRM_RESTORE_INBOX,
    CONFIRM_TRASH,
    CONFIRM_UNDO,
    CONFIRM_UNDO_KEPT,
    apply_to_ready,
    preflight_end_stage,
    preflight_kept_inbox,
    preflight_staged,
    ready_to_trash,
    undo_from_kept,
    undo_from_ready,
)
from mail_janitor.client_sessions import (
    clear_request_identity,
    client_mode,
    current_uid,
    ensure_workspace,
    parse_authentik_headers,
    session_status,
    set_request_identity,
    start_reaper_thread,
    touch_activity,
    validate_imap_host,
    wipe_session,
)
from mail_janitor.config import (
    Profile,
    apply_provider_pack,
    create_profile,
    delete_profile,
    ensure_profile_files,
    list_profiles,
    load_profile,
    profile_summaries,
    save_stage_folders,
    test_imap_connection,
    write_profile_credentials,
)
from mail_janitor.db import (
    folder_message_count,
    init_db,
    inbox_message_count,
    list_indexed_folders,
    message_count,
    staged_count,
)
from mail_janitor.discover import discover, preview_all_stage_rules, propose_cleanup_selections
from mail_janitor.keeper import (
    audit_keep_rules,
    coverage_stats,
    list_keep_rule_senders,
    mark_seen,
    narrow_broad_keep_rule,
    preview_domain_suffix,
    restore_broad_domain_keep,
    reset_review_state,
    search_imap_body,
    search_indexed,
)
from mail_janitor.heuristics import score_message
from mail_janitor.parse_headers import format_size, format_ts
from mail_janitor.providers import get_provider
from mail_janitor.scan import blank_header_stats, refresh_blank_headers
from mail_janitor.providers.packs import list_provider_packs
from mail_janitor.rules import (
    RESET_KEEP_PHRASE,
    RESET_STAGE_PHRASE,
    add_keep_sender,
    add_stage_rule,
    archive_dormant_stage_rules,
    clear_all_keep_rules,
    clear_all_stage_rules,
    delete_keep_rule,
    load_rules,
    rules_from_insight_selections,
)
from mail_janitor.stage import (
    list_staged,
    set_all_staged_included,
    set_many_included,
    set_staged_included,
    stage_by_confidence,
    stage_rules,
)
from mail_janitor.web.apply_jobs import APPLY_JOBS
from mail_janitor.web.insights_jobs import INSIGHTS_RULES_JOBS
from mail_janitor.web.scan_jobs import SCAN_JOBS
from mail_janitor.web.stage_jobs import STAGE_JOBS

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(WEB_DIR / "templates"))


def _tojson(value: Any) -> Markup:
    """JSON for embedding in <script> tags (must not be HTML-escaped)."""
    return Markup(json.dumps(value))


TEMPLATES.env.filters["tojson"] = _tojson
TEMPLATES.env.globals["base_path"] = ""
TEMPLATES.env.globals["theme"] = "fsb"
TEMPLATES.env.globals["is_demo"] = False
TEMPLATES.env.globals["is_client"] = False
TEMPLATES.env.globals["session_ttl_hours"] = 12


def _mj_list_folders(profile: Profile) -> list[dict[str, Any]]:
    conn = init_db(profile.db_path)
    try:
        return list_indexed_folders(conn)
    finally:
        conn.close()


TEMPLATES.env.globals["mj_list_folders"] = _mj_list_folders

# Memory-only body cache: key -> (expires_ts, text)
_BODY_CACHE: dict[str, tuple[float, str]] = {}
_BODY_TTL = 300.0

_HEALTH_PATHS = frozenset({"/api/mission-control/status"})


def public_base_path() -> str:
    """Optional public path prefix when reverse-proxied under Mission Control."""
    return (os.environ.get("MAIL_JANITOR_PUBLIC_BASE") or "").rstrip("/")


def ui_theme() -> str:
    """Visual skin: `fsb` (Mission Control) or `demo` (daylight mailroom)."""
    raw = (os.environ.get("MAIL_JANITOR_THEME") or "fsb").strip().lower()
    return "demo" if raw == "demo" else "fsb"


def create_app(profile_name: str) -> FastAPI:
    in_client = client_mode()
    if in_client:
        # Profile name is bound per Authentik user in middleware.
        app = FastAPI(title="Mail Janitor — client", docs_url=None, redoc_url=None)
        app.state.profile_name = ""
        start_reaper_thread()
    else:
        profile = load_profile(profile_name)
        app = FastAPI(title=f"Mail Janitor — {profile.name}", docs_url=None, redoc_url=None)
        app.state.profile_name = profile_name
    base = public_base_path()

    static_dir = WEB_DIR / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def get_profile() -> Profile:
        if client_mode():
            uid = current_uid()
            if not uid:
                raise HTTPException(
                    status_code=401,
                    detail="Sign in via Authentik is required",
                )
            return load_profile(uid)
        return load_profile(app.state.profile_name)

    def _abs(path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}" if base else path

    # Register inject first (inner), then client auth (outer) so identity is set before handlers.
    @app.middleware("http")
    async def _inject_template_globals(request: Request, call_next):
        theme = ui_theme()
        is_client = client_mode()
        try:
            ttl_h = float(os.environ.get("MAIL_JANITOR_SESSION_TTL_HOURS") or "12")
        except ValueError:
            ttl_h = 12.0
        names: list[str] = []
        if is_client:
            uid = current_uid()
            names = [uid] if uid else []
        else:
            names = list_profiles() or [app.state.profile_name]
        TEMPLATES.env.globals["profile_names"] = names
        TEMPLATES.env.globals["base_path"] = public_base_path()
        TEMPLATES.env.globals["theme"] = theme
        TEMPLATES.env.globals["is_demo"] = theme == "demo"
        TEMPLATES.env.globals["is_client"] = is_client
        TEMPLATES.env.globals["session_ttl_hours"] = ttl_h
        return await call_next(request)

    @app.middleware("http")
    async def _client_auth_and_workspace(request: Request, call_next):
        if not client_mode():
            return await call_next(request)
        path = request.url.path
        # Mesh health for Mission Control BFF (no Authentik headers).
        if path in _HEALTH_PATHS or path.rstrip("/") in _HEALTH_PATHS:
            return await call_next(request)
        try:
            uid, email = parse_authentik_headers(request.headers)
            sid = set_request_identity(uid, email)
            ensure_workspace(sid)
            touch_activity(sid)
        except PermissionError as exc:
            clear_request_identity()
            from fastapi.responses import JSONResponse

            accept = (request.headers.get("accept") or "").lower()
            if "application/json" in accept or path.startswith("/api/"):
                return JSONResponse(
                    {"detail": str(exc)},
                    status_code=401,
                )
            return HTMLResponse(
                content=(
                    "<!DOCTYPE html><html><body style='font-family:sans-serif;padding:2rem'>"
                    "<h1>Sign in required</h1>"
                    f"<p>{exc}</p>"
                    "<p>Open this site through Authentik, or ask your operator for an invite.</p>"
                    "</body></html>"
                ),
                status_code=401,
            )
        except Exception as exc:
            clear_request_identity()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            return await call_next(request)
        finally:
            clear_request_identity()

    @app.get("/", response_class=HTMLResponse)
    def root_redirect():
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url=_abs("/guide"), status_code=302)

    @app.get("/guide", response_class=HTMLResponse)
    def guide_page(request: Request):
        p = get_profile()
        # Avoid blocking the HTML shell if a scan holds the DB; counts refresh via JS.
        inbox = 0
        msgs = 0
        if SCAN_JOBS.status().get("state") != "running":
            conn = init_db(p.db_path)
            try:
                inbox = inbox_message_count(conn, p.inbox_folder)
                msgs = message_count(conn)
            finally:
                conn.close()
        return TEMPLATES.TemplateResponse(
            request,
            "guide.html",
            {
                "request": request,
                "profile": p,
                "inbox_count": inbox,
                "message_count": msgs,
                "confirm_ready": CONFIRM_READY,
                "confirm_restore_inbox": CONFIRM_RESTORE_INBOX,
                "confirm_trash": CONFIRM_TRASH,
                "provider_packs": list_provider_packs(),
                "connected": bool(p.email and p.app_password),
                "base_path": public_base_path(),
            },
        )

    @app.get("/advanced", response_class=HTMLResponse)
    def advanced_page(request: Request):
        p = get_profile()
        conn = init_db(p.db_path)
        try:
            ctx = {
                "request": request,
                "profile": p,
                "message_count": message_count(conn),
                "staged_count": staged_count(conn),
                "inbox_count": inbox_message_count(conn, p.inbox_folder),
                "confirm_restore_inbox": CONFIRM_RESTORE_INBOX,
                "confirm_trash": CONFIRM_TRASH,
            }
        finally:
            conn.close()
        return TEMPLATES.TemplateResponse(request, "advanced.html", ctx)

    @app.get("/home", response_class=HTMLResponse)
    def home(request: Request):
        p = get_profile()
        conn = init_db(p.db_path)
        try:
            ctx = {
                "request": request,
                "profile": p,
                "message_count": message_count(conn),
                "staged_count": staged_count(conn),
                "confirm_ready": CONFIRM_READY,
                "confirm_kept": CONFIRM_KEPT,
                "confirm_trash": CONFIRM_TRASH,
                "confirm_undo": CONFIRM_UNDO,
                "confirm_undo_kept": CONFIRM_UNDO_KEPT,
                "confirm_restore_inbox": CONFIRM_RESTORE_INBOX,
                "kept_folder": p.kept_folder,
                "inbox_folder": p.inbox_folder,
                "scan_status": SCAN_JOBS.status(),
            }
        finally:
            conn.close()
        return TEMPLATES.TemplateResponse(request, "index.html", ctx)

    @app.get("/api/stats")
    def api_stats():
        """Lightweight live counters for the header (polled often — keep this cheap)."""
        p = get_profile()
        scan_state = SCAN_JOBS.status().get("state")
        if scan_state == "running":
            # Don't contend with the scan worker on SQLite; header will catch up after.
            return {
                "inbox_count": None,
                "indexed_total": None,
                "staged_included": None,
                "scan_state": scan_state,
                "inbox_folder": p.inbox_folder,
                "kept_folder": p.kept_folder,
            }
        conn = init_db(p.db_path)
        try:
            return {
                "inbox_count": inbox_message_count(conn, p.inbox_folder),
                "indexed_total": message_count(conn),
                "staged_included": staged_count(conn, included_only=True),
                "scan_state": scan_state,
                "inbox_folder": p.inbox_folder,
                "kept_folder": p.kept_folder,
            }
        finally:
            conn.close()

    @app.get("/api/stats/detail")
    def api_stats_detail():
        """Heavier counters for advanced pages (not polled from the guide header)."""
        p = get_profile()
        conn = init_db(p.db_path)
        try:
            kept_pending: int | None = None
            if not APPLY_JOBS.is_running():
                kept_pending = preflight_kept_inbox(p, detail=False)["count"]
            effective = p.effective_stage_folders()
            return {
                "inbox_count": inbox_message_count(conn, p.inbox_folder),
                "indexed_total": message_count(conn),
                "staged_included": staged_count(conn, included_only=True),
                "kept_folder_count": folder_message_count(conn, p.kept_folder),
                "kept_inbox_pending": kept_pending,
                "inbox_folder": p.inbox_folder,
                "kept_folder": p.kept_folder,
                "indexed_folders": list_indexed_folders(conn),
                "effective_stage_folders": effective,
                "stage_scope_label": p.stage_scope_label(),
                "all_folders_mode": effective is None,
            }
        finally:
            conn.close()

    @app.get("/api/folders")
    def api_folders():
        """Indexed folders and current cleanup (stage/preview) scope."""
        p = get_profile()
        conn = init_db(p.db_path)
        try:
            folders = list_indexed_folders(conn)
        finally:
            conn.close()
        effective = p.effective_stage_folders()
        return {
            "folders": folders,
            "effective_stage_folders": effective,
            "stage_scope_label": p.stage_scope_label(),
            "all_folders_mode": effective is None,
        }

    @app.post("/api/config/stage-folders")
    async def api_save_stage_folders(request: Request):
        body = await request.json()
        p = get_profile()
        if body.get("all_folders"):
            save_stage_folders(p, None)
        else:
            folders = body.get("folders")
            if not isinstance(folders, list):
                raise HTTPException(status_code=400, detail="folders must be a list")
            try:
                save_stage_folders(p, [str(f) for f in folders])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        p = load_profile(app.state.profile_name)
        effective = p.effective_stage_folders()
        return {
            "ok": True,
            "effective_stage_folders": effective,
            "stage_scope_label": p.stage_scope_label(),
            "all_folders_mode": effective is None,
        }

    @app.get("/api/scan/status")
    def api_scan_status():
        """Lightweight status for polling — avoid blocking on a locked DB mid-scan."""
        status = SCAN_JOBS.status()
        if status.get("state") != "running":
            p = get_profile()
            conn = init_db(p.db_path)
            try:
                status["message_count_live"] = message_count(conn)
                status["inbox_count"] = inbox_message_count(conn)
            finally:
                conn.close()
        else:
            # Prefer in-memory progress counts while the worker holds the DB.
            prog = status.get("progress") or {}
            if prog.get("uids_done") is not None:
                status["message_count_live"] = prog.get("uids_done")
        return status

    @app.post("/api/scan")
    def api_scan(resume: int = Form(1)):
        """Start headers-only scan in the background (resume=1 default)."""
        result = SCAN_JOBS.start(app.state.profile_name, resume=bool(resume))
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result.get("error") or "Scan busy")
        return result

    @app.post("/api/refresh-blank-headers")
    def api_refresh_blank_headers():
        """Re-fetch From/Subject for indexed rows that scanned blank."""
        if SCAN_JOBS.status().get("state") == "running" or APPLY_JOBS.is_running():
            raise HTTPException(status_code=409, detail="Busy — wait for scan/move to finish")
        return refresh_blank_headers(get_profile())

    @app.get("/suggestions", response_class=HTMLResponse)
    def suggestions_page(request: Request, focus: str | None = None):
        """
        focus = comma-separated rule ids just created from Insights.
        Those are the main review; other stage rules stay active but de-emphasized.
        """
        p = get_profile()
        focus_ids = [x.strip() for x in (focus or "").split(",") if x.strip()]
        if focus_ids == ["session"]:
            batch_path = p.rules_path.parent / "last_focus_batch.json"
            if batch_path.exists():
                try:
                    focus_ids = [
                        str(x)
                        for x in json.loads(batch_path.read_text(encoding="utf-8"))
                        if x
                    ]
                except Exception:
                    focus_ids = []
            else:
                focus_ids = []
        focus_set = set(focus_ids)
        ruleset = load_rules(p.rules_path)

        if focus_set:
            # Only preview the new batch — full preview of 1000+ rules is multi-minute.
            focus_previews = preview_all_stage_rules(p, rule_ids=focus_ids)
            other_stage = [r for r in ruleset.stage if r.id not in focus_set]
            existing_previews: list = []
            dormant_count = 0
            existing_match_total = 0
            existing_rule_count = len(other_stage)
        else:
            # Direct visit: count-only pass, then samples only for rules with matches.
            counts = preview_all_stage_rules(p, include_samples=False)
            matching_ids = [
                pview["rule_id"]
                for pview in counts
                if int(pview.get("match_count") or 0) > 0
            ]
            focus_previews = (
                preview_all_stage_rules(p, rule_ids=matching_ids)
                if matching_ids
                else []
            )
            existing_previews = []
            dormant_count = len(counts) - len(matching_ids)
            existing_match_total = 0
            existing_rule_count = 0

        conn = init_db(p.db_path)
        try:
            indexed_folders = list_indexed_folders(conn)
        finally:
            conn.close()
        effective_folders = p.effective_stage_folders()
        return TEMPLATES.TemplateResponse(
            request,
            "suggestions.html",
            {
                "request": request,
                "profile": p,
                "focus_previews": focus_previews,
                "existing_previews": existing_previews,
                "existing_match_total": existing_match_total,
                "existing_rule_count": existing_rule_count,
                "dormant_count": dormant_count,
                "has_focus_batch": bool(focus_set),
                "previews": focus_previews,
                "indexed_folders": indexed_folders,
                "indexed_folders_json": json.dumps(indexed_folders),
                "stage_scope_label": p.stage_scope_label(),
                "effective_stage_folders": effective_folders,
                "all_folders_mode": effective_folders is None,
            },
        )
    @app.get("/insights", response_class=HTMLResponse)
    def insights(request: Request):
        p = get_profile()
        data = discover(p)
        return TEMPLATES.TemplateResponse(
            request,
            "insights.html",
            {"request": request, "profile": p, "data": data, "format_size": format_size},
        )

    @app.get("/keepers", response_class=HTMLResponse)
    def keepers_page(request: Request):
        p = get_profile()
        stats = coverage_stats(p)
        keep_audit = audit_keep_rules(p, sample_n=2)
        kept_preflight = preflight_kept_inbox(p, detail=False)
        return TEMPLATES.TemplateResponse(
            request,
            "keepers.html",
            {
                "request": request,
                "profile": p,
                "stats": stats,
                "keep_audit": keep_audit,
                "kept_preflight": kept_preflight,
                "confirm_kept": CONFIRM_KEPT,
                "confirm_undo_kept": CONFIRM_UNDO_KEPT,
                "reset_keep_phrase": RESET_KEEP_PHRASE,
                "reset_stage_phrase": RESET_STAGE_PHRASE,
            },
        )

    @app.get("/api/keepers/stats")
    def api_keepers_stats():
        return coverage_stats(get_profile())

    @app.get("/api/keepers/keep-audit")
    def api_keepers_keep_audit():
        return {"rules": audit_keep_rules(get_profile(), sample_n=3)}

    @app.get("/api/keepers/broad-senders")
    def api_keepers_broad_senders(
        rule_id: str = Query(...),
        limit: int = 200,
        offset: int = 0,
    ):
        try:
            return list_keep_rule_senders(
                get_profile(),
                rule_id,
                limit=limit,
                offset=offset,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/keepers/narrow-keep")
    async def api_keepers_narrow_keep(request: Request):
        body = await request.json()
        rule_id = str(body.get("rule_id") or "").strip()
        if not rule_id:
            raise HTTPException(status_code=400, detail="rule_id required")
        keep_addresses = body.get("keep_addresses")
        exclude_addresses = body.get("exclude_addresses")
        if keep_addresses is not None and not isinstance(keep_addresses, list):
            raise HTTPException(status_code=400, detail="keep_addresses must be a list")
        if exclude_addresses is not None and not isinstance(exclude_addresses, list):
            raise HTTPException(status_code=400, detail="exclude_addresses must be a list")
        if keep_addresses is None and exclude_addresses is None:
            raise HTTPException(
                status_code=400,
                detail="keep_addresses or exclude_addresses required",
            )
        try:
            p = get_profile()
            result = narrow_broad_keep_rule(
                p,
                rule_id,
                keep_addresses=keep_addresses,
                exclude_addresses=exclude_addresses,
            )
            result["stats"] = coverage_stats(p)
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/keepers/restore-domain-keep")
    async def api_keepers_restore_domain_keep(request: Request):
        body = await request.json()
        domain = str(body.get("domain") or "").strip()
        if not domain:
            raise HTTPException(status_code=400, detail="domain required")
        try:
            p = get_profile()
            result = restore_broad_domain_keep(
                p,
                domain,
                rule_id=body.get("rule_id"),
                remove_address_keeps=bool(body.get("remove_address_keeps", True)),
            )
            result["stats"] = coverage_stats(p)
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/rules/reset")
    async def api_rules_reset(request: Request):
        """Reset keep and/or stage rules (backs up rules.yaml first)."""
        body = await request.json()
        p = get_profile()
        backup = bool(body.get("backup", True))
        result: dict[str, Any] = {}
        if body.get("keep"):
            confirm = str(body.get("confirm") or "")
            if confirm != RESET_KEEP_PHRASE:
                raise HTTPException(
                    status_code=400,
                    detail=f"Type exactly: {RESET_KEEP_PHRASE}",
                )
            result["keep"] = clear_all_keep_rules(p.rules_path, backup=backup)
        if body.get("stage"):
            confirm = str(body.get("confirm") or "")
            if confirm != RESET_STAGE_PHRASE:
                raise HTTPException(
                    status_code=400,
                    detail=f"Type exactly: {RESET_STAGE_PHRASE}",
                )
            result["stage"] = clear_all_stage_rules(p.rules_path, backup=backup)
        if body.get("review_state"):
            result["review_state"] = reset_review_state(
                p,
                staged=bool(body.get("clear_staged", True)),
                evaluated=bool(body.get("clear_evaluated", True)),
            )
        if not result:
            raise HTTPException(status_code=400, detail="Nothing to reset")
        result["stats"] = coverage_stats(p)
        return result

    @app.get("/api/keepers/suffix-preview")
    def api_keepers_suffix_preview(suffix: str = Query(...)):
        try:
            return preview_domain_suffix(get_profile(), suffix)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/keepers/search")
    def api_keepers_search(
        domain_suffix: str | None = None,
        from_contains: str | None = None,
        domain_contains: str | None = None,
        subject_contains: str | None = None,
        body_keyword: str | None = None,
        folder: str | None = None,
        not_kept_only: int = 1,
        unseen_only: int = 0,
        limit: int = 100,
        offset: int = 0,
    ):
        p = get_profile()
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        if body_keyword and body_keyword.strip():
            try:
                result = search_imap_body(
                    p,
                    body_keyword.strip(),
                    folder=folder or "Inbox",
                    limit=limit,
                )
                result["mode"] = "imap_body"
                result["senders"] = len({r.get("from_addr") for r in result.get("rows", [])})
                result["domains"] = len({r.get("from_domain") for r in result.get("rows", [])})
                return result
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e)) from e
        try:
            result = search_indexed(
                p,
                domain_suffix=domain_suffix,
                from_contains=from_contains,
                domain_contains=domain_contains,
                subject_contains=subject_contains,
                not_kept_only=bool(not_kept_only),
                unseen_only=bool(unseen_only),
                folder=folder or None,
                limit=limit,
                offset=offset,
            )
            result["mode"] = "index"
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/keepers/mark-seen")
    async def api_keepers_mark_seen(request: Request):
        body = await request.json()
        items = body.get("items") or []
        pairs = [(str(i["folder"]), int(i["uid"])) for i in items if i.get("folder") and i.get("uid")]
        n = mark_seen(get_profile(), pairs)
        return {"ok": True, "updated": n}

    @app.post("/api/keepers/keep-suffix")
    async def api_keepers_keep_suffix(request: Request):
        from mail_janitor.rules import add_keep_domain_suffix

        body = await request.json()
        suffix = body.get("suffix") or ""
        try:
            rule = add_keep_domain_suffix(get_profile().rules_path, suffix)
            return {"ok": True, "rule_id": rule.id, "label": rule.label}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/keepers/keep-bulk")
    async def api_keepers_keep_bulk(request: Request):
        from mail_janitor.rules import add_keep_rule, rules_from_insight_selections

        p = get_profile()
        body = await request.json()
        kind = str(body.get("kind") or "").strip()
        if kind == "subject_contains":
            value = body.get("value") or ""
            if not value:
                raise HTTPException(status_code=400, detail="value required")
            created = rules_from_insight_selections(
                p.rules_path,
                [{"kind": "subject_contains", "value": value}],
                action="keep",
            )
            return {"ok": True, "created": [r.id for r in created]}
        values = body.get("values") or []
        if not values and body.get("value"):
            values = [body.get("value")]
        if kind not in ("from_address", "from_domain") or not values:
            raise HTTPException(status_code=400, detail="kind and values required")
        from mail_janitor.rules import _selection_to_rule_data

        created_ids: list[str] = []
        for v in values:
            rule = add_keep_rule(
                p.rules_path, _selection_to_rule_data(kind, v, action="keep")
            )
            created_ids.append(rule.id)
        return {"ok": True, "created": created_ids}

    @app.get("/review", response_class=HTMLResponse)
    def review(
        request: Request,
        q: str | None = None,
        rule_id: str | None = None,
        from_domain: str | None = None,
        page: int = 1,
        show_excluded: bool = False,
        show_all: int = 0,
        sort: str = "date",
    ):
        p = get_profile()
        page = max(1, page)
        # Default paginate — "show all" with 60k+ staged rows never finishes loading
        # in the browser, so the apply JS never attaches and the move form no-ops.
        show_all_flag = bool(show_all)
        show_all_capped = False
        if show_all_flag:
            limit = 500
            offset = 0
        else:
            limit = 100
            offset = (page - 1) * limit
        rows, total = list_staged(
            p,
            included_only=not show_excluded,
            limit=limit,
            offset=offset,
            from_domain=from_domain,
            rule_id=rule_id,
            q=q,
        )
        if show_all_flag and total > limit:
            show_all_capped = True
            show_all_flag = False  # force pager UI when capped
            pages = max(1, (total + 100 - 1) // 100)
        else:
            pages = 1 if show_all_flag else max(1, (total + 100 - 1) // 100)
        for r in rows:
            r["date_human"] = format_ts(r.get("date_ts"))
            r["size_human"] = format_size(r.get("size"))
            sc = score_message(r)
            r["triage_confidence"] = sc["confidence"]
            r["triage_score"] = sc["score"]
            r["triage_flags"] = sc["flags"]
        if sort == "triage":
            rank = {"keep": 0, "uncertain": 1, "junk": 2}
            rows.sort(
                key=lambda r: (
                    rank.get(r.get("triage_confidence") or "junk", 9),
                    int(r.get("triage_score") or 0),
                    r.get("date_ts") is not None,
                    r.get("date_ts") or 0,
                )
            )
        conn = init_db(p.db_path)
        try:
            indexed_total = message_count(conn)
        finally:
            conn.close()
        return TEMPLATES.TemplateResponse(
            request,
            "review.html",
            {
                "request": request,
                "profile": p,
                "rows": rows,
                "total": total,
                "indexed_total": indexed_total,
                "page": page,
                "pages": pages,
                "show_all": show_all_flag and not show_all_capped,
                "show_all_capped": show_all_capped,
                "q": q or "",
                "rule_id": rule_id or "",
                "from_domain": from_domain or "",
                "show_excluded": show_excluded,
                "sort": sort or "date",
                "confirm_ready": CONFIRM_READY,
                "preflight": preflight_staged(p, detail=False),
                "apply_status": APPLY_JOBS.status(),
            },
        )

    @app.get("/api/staged")
    def api_staged(
        q: str | None = None,
        rule_id: str | None = None,
        from_domain: str | None = None,
        limit: int = 100,
        offset: int = 0,
        included_only: bool = True,
    ):
        p = get_profile()
        rows, total = list_staged(
            p,
            included_only=included_only,
            limit=limit,
            offset=offset,
            from_domain=from_domain,
            rule_id=rule_id,
            q=q,
        )
        return {"total": total, "rows": rows}

    @app.post("/api/staged/include")
    def api_include(folder: str = Form(...), uid: int = Form(...), included: int = Form(...)):
        p = get_profile()
        set_staged_included(p, folder, uid, bool(included))
        return {"ok": True}

    @app.post("/api/staged/bulk")
    async def api_bulk(request: Request):
        p = get_profile()
        body = await request.json()
        included = bool(body.get("included", True))
        if body.get("all"):
            n = set_all_staged_included(
                p,
                included,
                from_domain=body.get("from_domain") or None,
                rule_id=body.get("rule_id") or None,
                q=body.get("q") or None,
            )
            return {"ok": True, "updated": n, "scope": "all_matching"}
        items = [(i["folder"], int(i["uid"])) for i in body.get("items", [])]
        n = set_many_included(p, items, included)
        return {"ok": True, "updated": n, "scope": "items"}

    @app.post("/api/keep-sender")
    def api_keep_sender(from_addr: str = Form(...)):
        p = get_profile()
        rule = add_keep_sender(p.rules_path, from_addr)
        return {"ok": True, "rule_id": rule.id}

    @app.post("/api/stage")
    async def api_stage(request: Request, background: int = Query(1)):
        """Stage approved rules. background=1 (default) runs with live ETA polling.

        Prefer JSON ``{"rule_ids": [...], "clear": true}`` — FormData with one
        field per rule hits Starlette's default 1000-field multipart cap.
        """
        p = get_profile()
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            body = await request.json()
            clear = bool(body.get("clear", False))
            raw_ids = body.get("rule_ids") or body.get("rule_id") or []
            if isinstance(raw_ids, str):
                raw_ids = [raw_ids]
            rule_ids = [str(v) for v in raw_ids if v]
        else:
            # Large approve batches need a raised field ceiling for FormData fallback.
            form = await request.form(max_fields=50_000)
            clear = str(form.get("clear") or "0") in ("1", "true", "on")
            rule_ids = [str(v) for v in form.getlist("rule_id") if v]
        ids = rule_ids or None
        if background:
            result = STAGE_JOBS.start(p.name, rule_ids=ids, clear=clear)
            if not result.get("ok"):
                raise HTTPException(status_code=409, detail=result.get("error") or "Busy")
            return result
        try:
            return stage_rules(p, rule_ids=ids, clear=clear)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/api/stage/junk")
    async def api_stage_junk(
        request: Request,
        limit: int = Query(50, ge=1, le=5000),
        clear: int = Query(1),
        confidence: str = Query("junk"),
    ):
        """Stage high-confidence junk (metadata triage).

        Accepts JSON body and/or query params (guide uses ``?limit=50&clear=1``).
        """
        p = get_profile()
        body: dict = {}
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            raw = await request.body()
            if raw.strip():
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        body = parsed
                except json.JSONDecodeError as e:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid JSON body: {e}"
                    ) from e
        if "limit" in body:
            limit = int(body.get("limit") or limit)
        if "clear" in body:
            clear_flag = bool(body.get("clear"))
        else:
            clear_flag = str(clear) in ("1", "true", "on", "yes")
        if body.get("confidence"):
            confidence = str(body.get("confidence"))
        try:
            return stage_by_confidence(
                p, confidence=confidence, limit=limit, clear=clear_flag
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/api/stage/status")
    def api_stage_status():
        return STAGE_JOBS.status()

    @app.post("/api/rules/update")
    async def api_rules_update(request: Request):
        from mail_janitor.rules import update_stage_rule

        p = get_profile()
        body = await request.json()
        rule_id = body.get("rule_id")
        if not rule_id:
            raise HTTPException(status_code=400, detail="rule_id required")
        updates = {}
        if "older_than_days" in body:
            updates["older_than_days"] = body.get("older_than_days")
        if "label" in body:
            updates["label"] = body.get("label")
        try:
            rule = update_stage_rule(p.rules_path, rule_id, updates)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return {"ok": True, "rule_id": rule.id, "older_than_days": rule.older_than_days}

    @app.post("/api/rules/delete")
    async def api_rules_delete(request: Request):
        from mail_janitor.rules import delete_stage_rule

        p = get_profile()
        body = await request.json()
        rule_id = body.get("rule_id")
        if not rule_id:
            raise HTTPException(status_code=400, detail="rule_id required")
        ok = delete_stage_rule(p.rules_path, rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"ok": True}
    @app.get("/api/preflight")
    def api_preflight():
        return preflight_staged(get_profile())

    @app.get("/api/preflight-kept")
    def api_preflight_kept():
        return preflight_kept_inbox(get_profile())

    @app.post("/api/apply-kept")
    def api_apply_kept(confirm: str = Form(...)):
        """Move Inbox keep-rule matches to the intentionally kept folder."""
        result = APPLY_JOBS.start_apply_kept(app.state.profile_name, confirm=confirm)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result.get("error") or "Busy")
        return result

    @app.post("/api/apply")
    def api_apply(confirm: str = Form(...)):
        """Start background move of ALL included staged messages."""
        result = APPLY_JOBS.start_apply(app.state.profile_name, confirm=confirm)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result.get("error") or "Busy")
        return result

    @app.get("/api/apply/status")
    def api_apply_status():
        status = APPLY_JOBS.status()
        p = get_profile()
        job = status.get("job")
        running = status.get("state") == "running"
        prog = status.get("progress") or {}

        if not running:
            if job == "apply-kept":
                status["preflight"] = preflight_kept_inbox(p, detail=False)
            else:
                status["preflight"] = preflight_staged(p, detail=False)

        conn = init_db(p.db_path)
        try:
            status["moves_done"] = int(
                conn.execute("SELECT COUNT(*) AS c FROM moves WHERE undone = 0").fetchone()["c"]
            )
            status["staged_remaining"] = staged_count(conn, included_only=True)
            status["inbox_count"] = inbox_message_count(conn, p.inbox_folder)
            if running and job == "apply-kept":
                status["kept_inbox_pending"] = int(prog.get("remaining_estimate") or 0)
            elif not running:
                status["kept_inbox_pending"] = preflight_kept_inbox(p, detail=False)["count"]
            last_moved = conn.execute(
                "SELECT MAX(moved_at) AS t FROM moves WHERE undone = 0"
            ).fetchone()["t"]
            status["last_moved_at"] = last_moved
        finally:
            conn.close()

        # Age of last successful DB move (seconds) — hang detector for the UI
        from datetime import datetime, timezone

        from mail_janitor.progress import format_duration, progress_snapshot

        last_ok = (status.get("progress") or {}).get("last_ok_at")
        if not last_ok and not running:
            last_ok = last_moved
        if last_ok:
            try:
                age = (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(str(last_ok).replace("Z", "+00:00"))
                ).total_seconds()
                status["seconds_since_last_ok"] = int(age)
            except Exception:
                status["seconds_since_last_ok"] = None
        else:
            status["seconds_since_last_ok"] = None

        if status.get("state") == "running":
            prog = status.get("progress") or {}
            moved_job = int(prog.get("moved_this_job") or 0)
            if job == "apply-kept":
                remaining = int(status.get("kept_inbox_pending") or 0)
            else:
                remaining = int(status.get("staged_remaining") or 0)
            total = prog.get("total_planned")
            if total is None:
                total = moved_job + remaining
            snap = progress_snapshot(
                done=moved_job,
                total=total,
                started_at=status.get("started_at"),
                label="moved",
                min_done=5,
            )
            status["eta"] = snap
            age = status.get("seconds_since_last_ok")
            hang = ""
            if age is not None and age > 90:
                hang = f" · STALLED? no ok for {format_duration(age)}"
            elif age is not None:
                hang = f" · last ok {format_duration(age)} ago"
            if job == "apply-kept":
                status["message"] = (
                    f"{snap['summary']} · kept still in Inbox {remaining:,}{hang}"
                )
            else:
                status["message"] = (
                    f"{snap['summary']} · staged left {remaining:,}{hang}"
                )
        return status

    @app.post("/api/apply/ack")
    def api_apply_ack():
        """Compat no-op: finished jobs remain 'done' so the result JSON stays visible."""
        return APPLY_JOBS.acknowledge()

    @app.post("/api/undo")
    def api_undo(confirm: str = Form(...), limit: int | None = Form(None)):
        p = get_profile()
        try:
            return undo_from_ready(p, confirm=confirm, limit=limit)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/undo-kept")
    def api_undo_kept(confirm: str = Form(...), limit: int | None = Form(None)):
        p = get_profile()
        try:
            return undo_from_kept(p, confirm=confirm, limit=limit)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/to-trash")
    def api_to_trash(
        confirm: str = Form(...),
        batch_size: int = Form(100),
        drain: bool = Form(False),
    ):
        p = get_profile()
        try:
            return ready_to_trash(
                p, confirm=confirm, batch_size=batch_size, drain=drain
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/end-stage")
    def api_end_stage():
        return preflight_end_stage(get_profile())

    @app.post("/api/end-stage/restore-kept")
    def api_end_stage_restore_kept(confirm: str = Form(...)):
        p = get_profile()
        started = APPLY_JOBS.start_restore_kept(p.name, confirm=confirm)
        if not started.get("ok"):
            raise HTTPException(
                status_code=409, detail=started.get("error") or "Job not started"
            )
        return started

    @app.post("/api/end-stage/to-trash")
    def api_end_stage_to_trash(
        confirm: str = Form(...), batch_size: int = Form(100)
    ):
        p = get_profile()
        started = APPLY_JOBS.start_to_trash(
            p.name, confirm=confirm, batch_size=batch_size
        )
        if not started.get("ok"):
            raise HTTPException(
                status_code=409, detail=started.get("error") or "Job not started"
            )
        return started

    @app.get("/api/open")
    def api_open(folder: str = Query(...), uid: int = Query(...)):
        """On-request body fetch — not written to mail.db."""
        p = get_profile()
        cache_key = f"{p.name}:{folder}:{uid}"
        now = time.time()
        cached = _BODY_CACHE.get(cache_key)
        if cached and cached[0] > now:
            return {"folder": folder, "uid": uid, "body": cached[1], "cached": True}

        # Expire old entries
        expired = [k for k, (exp, _) in _BODY_CACHE.items() if exp <= now]
        for k in expired:
            _BODY_CACHE.pop(k, None)

        provider = get_provider(p.provider)
        client = provider.connect(p)
        try:
            client.select(folder, readonly=True)
            _, text = client.fetch_body(uid)
        finally:
            client.close()
        _BODY_CACHE[cache_key] = (now + _BODY_TTL, text)
        return {"folder": folder, "uid": uid, "body": text, "cached": False}

    @app.get("/open", response_class=HTMLResponse)
    def open_message(request: Request, folder: str = Query(...), uid: int = Query(...)):
        p = get_profile()
        return TEMPLATES.TemplateResponse(
            request,
            "open.html",
            {"request": request, "profile": p, "folder": folder, "uid": uid},
        )

    @app.get("/export.csv")
    def export_csv(
        included_only: bool = True,
        q: str | None = None,
        rule_id: str | None = None,
        from_domain: str | None = None,
    ):
        p = get_profile()
        rows, _ = list_staged(
            p,
            included_only=included_only,
            limit=1_000_000,
            offset=0,
            from_domain=from_domain,
            rule_id=rule_id,
            q=q,
        )
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "folder",
                "uid",
                "from_addr",
                "from_domain",
                "subject",
                "date_ts",
                "size",
                "rule_id",
                "reason",
                "included",
                "list_unsubscribe",
                "message_id",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in writer.fieldnames})
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{p.name}-staged.csv"'},
        )

    @app.get("/rules", response_class=HTMLResponse)
    def rules_page(request: Request):
        p = get_profile()
        ruleset = load_rules(p.rules_path)
        previews = preview_all_stage_rules(p)
        return TEMPLATES.TemplateResponse(
            request,
            "rules.html",
            {
                "request": request,
                "profile": p,
                "ruleset": ruleset,
                "previews": previews,
            },
        )

    @app.post("/api/rules/stage")
    async def api_add_stage_rule(request: Request):
        p = get_profile()
        data = await request.json()
        rule = add_stage_rule(p.rules_path, data)
        return {"ok": True, "rule": rule.id}

    @app.get("/api/rules/business-prefixes/preview")
    def api_business_prefix_preview():
        from mail_janitor.rules import preview_business_prefix_matches

        p = get_profile()
        return preview_business_prefix_matches(p.rules_path, p.db_path)

    @app.post("/api/rules/stage/business-prefixes")
    def api_add_business_prefix_rule():
        from mail_janitor.rules import (
            add_stage_business_prefix_rule,
            preview_business_prefix_matches,
        )

        p = get_profile()
        rule = add_stage_business_prefix_rule(p.rules_path)
        preview = preview_business_prefix_matches(p.rules_path, p.db_path)
        return {"ok": True, "rule_id": rule.id, "label": rule.label, **preview}

    @app.post("/api/rules/from-insights")
    async def api_rules_from_insights(request: Request, background: int = Query(1)):
        """Checkbox → stage or keep rules from Insights.

        background=1 (default): run with live ETA via /api/rules/from-insights/status.
        """
        p = get_profile()
        body = await request.json()
        selections = body.get("selections") or []
        action = str(body.get("action") or "stage").strip().lower()
        if action not in ("stage", "keep"):
            raise HTTPException(status_code=400, detail="action must be 'stage' or 'keep'")
        if not selections:
            raise HTTPException(status_code=400, detail="No selections")
        self_email = (p.email or "").lower()
        cleaned = []
        for sel in selections:
            kind = sel.get("kind")
            value = sel.get("value")
            if kind == "from_address" and str(value).lower() == self_email:
                continue
            if action == "keep" and kind in (
                "older_than_days",
                "list_unsubscribe_older_than",
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Age / List-Unsubscribe rules are cleanup-only — pick senders, domains, or folders for Keep.",
                )
            cleaned.append(sel)
        if not cleaned:
            raise HTTPException(status_code=400, detail="No valid selections")

        if background:
            result = INSIGHTS_RULES_JOBS.start(p.name, cleaned, action)
            if not result.get("ok"):
                raise HTTPException(status_code=409, detail=result.get("error") or "Busy")
            return result

        try:
            created = rules_from_insight_selections(p.rules_path, cleaned, action=action)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        ids = [r.id for r in created]
        if action != "keep":
            try:
                (p.rules_path.parent / "last_focus_batch.json").write_text(
                    json.dumps(ids), encoding="utf-8"
                )
            except OSError:
                pass
        if action == "keep":
            return {
                "ok": True,
                "action": "keep",
                "created_rule_ids": ids,
                "created_labels": [r.label for r in created],
                "next": f"{public_base_path()}/rules" if public_base_path() else "/rules",
            }
        return {
            "ok": True,
            "action": "stage",
            "created_rule_ids": ids,
            "created_labels": [r.label for r in created],
            "next": (
                f"{public_base_path()}/suggestions?focus=session"
                if public_base_path()
                else "/suggestions?focus=session"
            ),
        }

    @app.get("/api/rules/from-insights/status")
    def api_rules_from_insights_status():
        return INSIGHTS_RULES_JOBS.status()

    @app.post("/api/rules/propose-batch")
    async def api_propose_batch(request: Request):
        """
        Create cleanup rules for the next N candidates above a threshold.
        Still requires Suggested rules → email review → confirm phrase before any move.
        """
        p = get_profile()
        body = await request.json()
        min_count = int(body.get("min_count") or 20)
        limit = int(body.get("limit") or 50)
        heuristic_only = bool(body.get("heuristic_only"))
        kinds = body.get("kinds") or ["from_address"]
        if isinstance(kinds, str):
            kinds = [kinds]
        selections = propose_cleanup_selections(
            p,
            min_count=min_count,
            limit=limit,
            kinds=list(kinds),
            heuristic_only=heuristic_only,
            skip_existing_stage_rules=True,
        )
        if not selections:
            raise HTTPException(
                status_code=400,
                detail="No new candidates matched. Lower the threshold, load more, or add Keep rules and try again.",
            )
        # Strip helper fields before rule creation
        cleaned = [{"kind": s["kind"], "value": s["value"]} for s in selections]
        try:
            created = rules_from_insight_selections(p.rules_path, cleaned, action="stage")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {
            "ok": True,
            "action": "stage",
            "proposed": selections,
            "created_rule_ids": [r.id for r in created],
            "created_labels": [r.label for r in created],
            "next": (
                f"{public_base_path()}/suggestions?focus=" + ",".join(r.id for r in created)
                if public_base_path()
                else "/suggestions?focus=" + ",".join(r.id for r in created)
            ),
        }

    @app.post("/api/rules/keep")
    async def api_add_keep_rule(request: Request):
        from mail_janitor.rules import add_keep_rule

        p = get_profile()
        data = await request.json()
        rule = add_keep_rule(p.rules_path, data)
        return {"ok": True, "rule": rule.id}

    @app.post("/api/rules/keep/delete")
    async def api_delete_keep_rule(request: Request):
        p = get_profile()
        body = await request.json()
        rule_id = body.get("rule_id")
        if not rule_id:
            raise HTTPException(status_code=400, detail="rule_id required")
        ok = delete_keep_rule(p.rules_path, rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Keep rule not found")
        return {"ok": True}

    @app.get("/api/discover")
    def api_discover(
        top_n: int = 100,
        sender_offset: int = 0,
        domain_offset: int = 0,
    ):
        return discover(
            get_profile(),
            top_n=top_n,
            sender_offset=sender_offset,
            domain_offset=domain_offset,
        )

    @app.get("/api/providers")
    def api_providers():
        return {"providers": list_provider_packs()}

    @app.get("/api/profiles")
    def api_profiles():
        names = list_profiles()
        active = current_uid() if client_mode() else app.state.profile_name
        return {
            "profiles": names,
            "active": active,
            "summaries": profile_summaries(),
        }

    @app.post("/api/profiles")
    async def api_profiles_create(request: Request):
        if client_mode():
            raise HTTPException(
                status_code=403,
                detail="Mailbox creation is disabled in client mode",
            )
        body = await request.json()
        name = str(body.get("name") or body.get("profile") or "").strip()
        provider = str(body.get("provider") or "yahoo").strip()
        try:
            return create_profile(name, provider=provider)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/profiles/{name}")
    def api_profiles_delete(name: str):
        if client_mode():
            raise HTTPException(
                status_code=403,
                detail="Mailbox deletion is disabled in client mode",
            )
        if SCAN_JOBS.status().get("state") == "running" or APPLY_JOBS.is_running():
            raise HTTPException(status_code=409, detail="Busy — wait for scan/move to finish")
        try:
            return delete_profile(name, active=app.state.profile_name)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/profiles/switch")
    async def api_profiles_switch(request: Request):
        if client_mode():
            raise HTTPException(
                status_code=403,
                detail="Mailbox switching is disabled in client mode",
            )
        body = await request.json()
        name = str(body.get("profile") or "").strip()
        if not name or name not in list_profiles():
            raise HTTPException(status_code=404, detail="Unknown profile")
        if SCAN_JOBS.status().get("state") == "running" or APPLY_JOBS.is_running():
            raise HTTPException(status_code=409, detail="Busy — wait for scan/move to finish")
        app.state.profile_name = name
        return {"ok": True, "active": name}

    @app.get("/api/session/status")
    def api_session_status():
        if not client_mode():
            return {"ok": True, "client_mode": False}
        uid = current_uid()
        if not uid:
            raise HTTPException(status_code=401, detail="Sign in via Authentik is required")
        out = session_status(uid)
        out["client_mode"] = True
        return out

    @app.post("/api/session/end")
    def api_session_end():
        if not client_mode():
            raise HTTPException(status_code=400, detail="Not in client mode")
        uid = current_uid()
        if not uid:
            raise HTTPException(status_code=401, detail="Sign in via Authentik is required")
        if SCAN_JOBS.status().get("state") == "running" or APPLY_JOBS.is_running():
            raise HTTPException(status_code=409, detail="Busy — wait for scan/move to finish")
        return wipe_session(uid)

    @app.post("/api/guide/connect")
    async def api_guide_connect(request: Request):
        body = await request.json()
        provider = str(body.get("provider") or "yahoo").strip()
        email = str(body.get("email") or "").strip()
        password = str(body.get("app_password") or "").strip()
        imap_host = body.get("imap_host")
        try:
            if client_mode():
                uid = current_uid()
                if not uid:
                    raise HTTPException(status_code=401, detail="Sign in via Authentik is required")
                name = uid
                host = validate_imap_host(
                    str(imap_host) if imap_host else None,
                    provider,
                )
            else:
                name = str(body.get("profile_name") or app.state.profile_name).strip()
                host = str(imap_host) if imap_host else None
            apply_provider_pack(name, provider, imap_host=host)
            # Keep prior credentials until IMAP proves the new ones work.
            previous_creds = None
            if client_mode():
                from mail_janitor.client_sessions import load_credentials, store_credentials

                previous_creds = load_credentials(name)
            path = ensure_profile_files(name)
            env_path = path / ".env"
            previous_env = (
                None
                if client_mode()
                else (env_path.read_text(encoding="utf-8") if env_path.exists() else None)
            )
            write_profile_credentials(name, email, password)
            try:
                result = test_imap_connection(load_profile(name))
            except Exception:
                if client_mode():
                    from mail_janitor.client_sessions import clear_credentials, store_credentials

                    if previous_creds:
                        store_credentials(name, previous_creds[0], previous_creds[1])
                    else:
                        clear_credentials(name)
                elif previous_env is None:
                    try:
                        env_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                else:
                    env_path.write_text(previous_env, encoding="utf-8")
                raise
            switched = (not client_mode()) and name != app.state.profile_name
            if not client_mode():
                app.state.profile_name = name
            result["switched"] = switched
            return result
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/guide/protect-candidates")
    def api_guide_protect_candidates(limit: int = 40):
        p = get_profile()
        data = discover(p, top_n=5)
        triage = data.get("triage") or {}
        candidates = list(triage.get("likely_keep") or [])[: max(1, min(limit, 80))]
        return {"candidates": candidates, "total": triage.get("likely_keep_total") or len(candidates)}

    @app.post("/api/rules/archive-dormant")
    def api_archive_dormant():
        return archive_dormant_stage_rules(get_profile())

    @app.get("/api/blank-headers")
    def api_blank_headers():
        return blank_header_stats(get_profile())

    @app.get("/api/mission-control/status")
    def api_mission_control_status():
        """Compact status for Mission Control cards / health checks."""
        if client_mode() and not current_uid():
            return {
                "service": "mail-janitor",
                "client_mode": True,
                "ok": True,
                "profile": None,
                "email": None,
                "ui_path": "/guide",
                "public_base": public_base_path(),
                "note": "client instance — Authentik-gated; mesh health only",
            }
        p = get_profile()
        scan = SCAN_JOBS.status()
        apply = APPLY_JOBS.status()
        # Keep this endpoint cheap — MC / portal may poll it; never run keep-rule preflight here.
        out: dict[str, Any] = {
            "service": "mail-janitor",
            "client_mode": client_mode(),
            "profile": p.name,
            "email": p.email if p.email != "you@example.com" else None,
            "provider": p.provider,
            "scan_state": scan.get("state"),
            "scan_message": scan.get("message"),
            "apply_state": apply.get("state"),
            "apply_job": apply.get("job"),
            "apply_message": apply.get("message"),
            "ui_path": f"{public_base_path()}/guide" if public_base_path() else "/guide",
            "public_base": public_base_path(),
            "profiles": list_profiles(),
            "profile_summaries": profile_summaries(),
        }
        if scan.get("state") != "running":
            conn = init_db(p.db_path)
            try:
                out["inbox_count"] = inbox_message_count(conn, p.inbox_folder)
                out["indexed_total"] = message_count(conn)
                out["staged_included"] = staged_count(conn, included_only=True)
            finally:
                conn.close()
            try:
                blanks = blank_header_stats(p)
                out["blank_headers"] = blanks.get("blank")
                out["blank_needs_repair"] = blanks.get("needs_repair")
            except Exception:
                out["blank_headers"] = None
                out["blank_needs_repair"] = None
        else:
            prog = scan.get("progress") or {}
            out["indexed_total"] = prog.get("uids_done")
            out["inbox_count"] = None
            out["staged_included"] = None
            out["blank_headers"] = None
            out["blank_needs_repair"] = None
        return out

    return app


def run_server(profile_name: str, host: str = "127.0.0.1", port: int = 8787) -> None:
    import uvicorn

    app = create_app(profile_name)
    print(f"Mail Janitor · open http://{host}:{port}/guide", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")
