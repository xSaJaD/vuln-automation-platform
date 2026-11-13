"""مهام Celery — أغلفة رفيعة حول منطق الـ recon."""

from __future__ import annotations

from workers import tools

# يُستورد celery_app بشكل كسول داخل الدالة لتجنّب دورة الاستيراد عند التسجيل.
from workers.celery_app import celery_app  # noqa: E402
from workers.recon_logic import ReconTools, run_full_recon
from workers.resilient import RETRY, ResilientTask
from workers.scan_logic import ScanTools, scan_hosts
from workers.strix_logic import run_strix_scan

DEFAULT_TOOLS = ReconTools(
    subfinder=tools.run_subfinder,
    httpx=tools.run_httpx,
    naabu=tools.run_naabu,
)

DEFAULT_SCAN_TOOLS = ScanTools(nuclei=tools.run_nuclei)


@celery_app.task(name="recon.run_full", base=ResilientTask, **RETRY)
def recon_run_full(program_id: int, seed: str) -> dict:
    """يشغّل السلسلة الكاملة لبرنامج وبذرة. البذرة يُفترض أنها مرّت الحارس مسبقًا."""
    from api.db import SessionLocal
    from api.models.program import Program

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        hosts = run_full_recon(db, program, seed, DEFAULT_TOOLS)
        return {
            "program_id": program_id,
            "seed": seed,
            "hosts_total": len(hosts),
            "in_scope": sum(1 for h in hosts if h.in_scope),
            "live": sum(1 for h in hosts if h.is_live),
        }
    finally:
        db.close()


@celery_app.task(name="scan.run_nuclei", base=ResilientTask, **RETRY)
def scan_run_nuclei(program_id: int) -> dict:
    """يفحص المضيفات الحيّة ضمن النطاق بـ nuclei ويخزّن النتائج كـ findings."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        scan_run, findings = scan_hosts(
            db, program, DEFAULT_SCAN_TOOLS, output_dir=settings.strix_runs_dir
        )
        sev: dict[str, int] = {}
        for f in findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1

        # تنبيهات (best-effort) عن النتائج المهمّة وانتهاء الفحص.
        from api.services.notify import get_notifier, notify_findings

        notifier = get_notifier()
        if notifier:
            notify_findings(notifier, findings)
            notifier.scan_done(program.handle, len(findings))

        return {
            "scan_run_id": scan_run.id,
            "findings": len(findings),
            "by_severity": sev,
        }
    finally:
        db.close()


@celery_app.task(name="pipeline.run_full", base=ResilientTask, **RETRY)
def pipeline_run_full(program_id: int, seed: str, use_strix: bool = False) -> dict:
    """السلسلة الكاملة recon → scan → (Strix اختياري) → correlate تحت قفل تزامن."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.locks import redis_lock
    from workers.orchestration import PipelineLocked, run_pipeline

    strix_runner = None
    if use_strix:
        from workers.strix_cli import run_strix_cli

        def strix_runner(tgt: str, instr: str | None):
            return run_strix_cli(
                tgt,
                instr,
                output_root=settings.strix_runs_dir,
                budget=settings.strix_budget or None,
                timeout=settings.strix_timeout,
            )

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        try:
            correlated = run_pipeline(
                db, program, seed, DEFAULT_TOOLS, DEFAULT_SCAN_TOOLS,
                lock=redis_lock(f"pipeline:{program_id}"),
                output_dir=settings.strix_runs_dir,
                strix_runner=strix_runner,
            )
        except PipelineLocked as exc:
            return {"status": "skipped", "reason": str(exc)}
        return {"status": "done", "correlated": len(correlated), "used_strix": use_strix}
    finally:
        db.close()


@celery_app.task(name="authscan.run", base=ResilientTask, **RETRY)
def authscan_run(program_id: int, targets: list[str], login: dict | None = None) -> dict:
    """فحص مُصادَق (DAST): يسجّل دخولًا ثم يفحص روابط بارامترية بـ nuclei -dast."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.audit import AuditLog
    from api.models.program import Program
    from workers.authscan import (
        LoginConfig,
        UrllibClient,
        authenticate,
        cookie_header,
        run_authscan,
    )
    from workers.correlation_logic import correlate

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}

        # تسجيل دخول دائم: إن لم يُمرَّر login صراحةً، نحمّل ملف المصادقة المخزَّن.
        if login is None:
            from api.services.auth_loader import load_login_config

            login = load_login_config(db, program_id)

        hdr = ""
        if login and (login.get("url") or login.get("extra_cookies")):
            cfg = LoginConfig(**login)
            try:
                hdr = cookie_header(authenticate(UrllibClient(), cfg))
            except Exception as exc:  # فشل الدخول لا يُسقط المهمة — نكمل بلا كوكي
                db.add(
                    AuditLog(
                        action="authscan_login",
                        target_value=cfg.url or "login",
                        program_id=program_id,
                        decision="failed",
                        reason=f"login failed: {exc}"[:400],
                        actor="authscan",
                    )
                )
                db.commit()

        def nuclei_dast(tgts: list[str]) -> list[dict]:
            extra = ["-dast"]
            if hdr:
                extra += ["-H", "Cookie: " + hdr]
            return tools.run_nuclei(tgts, extra_args=extra, timeout=settings.strix_timeout or 1800)

        run_authscan(db, program, targets, nuclei_dast)
        correlated = correlate(db, program)
        return {"status": "done", "correlated": len(correlated), "authenticated": bool(hdr)}
    finally:
        db.close()


@celery_app.task(name="autoscan.run", base=ResilientTask, **RETRY)
def autoscan_run(program_id: int, seed: str) -> dict:
    """فحص ذاتي بلا LLM: دخول تلقائي (كشف النموذج) → زحف → fuzzing على المكتشَف.

    لا يحتاج إدخال حقول/أهداف يدويًا — فقط رابط بداية + بيانات دخول محفوظة (اختيارية).
    """
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from api.services.auth_loader import load_login_config
    from workers.authscan import UrllibClient, cookie_header, run_authscan
    from workers.autologin import auto_login
    from workers.correlation_logic import correlate

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}

        # 1) دخول تلقائي: يكتشف النموذج بنفسه (بالاعتماد المحفوظ إن وُجد).
        login = load_login_config(db, program_id)
        hdr = ""
        if login and login.get("username"):
            try:
                cookies = auto_login(
                    UrllibClient(),
                    login.get("url") or seed,
                    login["username"],
                    login.get("password") or "",
                )
                cookies.update(login.get("extra_cookies") or {})
                hdr = cookie_header(cookies)
            except Exception:
                hdr = ""
        elif login and login.get("extra_cookies"):
            hdr = cookie_header(dict(login["extra_cookies"]))

        # 2) زحف لاكتشاف الصفحات والبارامترات (بالجلسة إن توفّرت).
        try:
            crawled = tools.run_katana(seed, cookie_header=hdr or None, depth=3)
        except Exception:
            crawled = []
        if seed not in crawled:
            crawled = [seed] + crawled

        # نفضّل الروابط ذات البارامترات، ونزيل التكرار حسب (المسار + أسماء البارامترات)
        # حتى لا نفحص نفس النقطة بقيَم مختلفة — فيتنوّع ما يُفحص ضمن الحدّ.
        from urllib.parse import parse_qs, urlsplit

        params = [u for u in crawled if "?" in u]
        seen_keys: set = set()
        targets: list[str] = []
        for u in params:
            p = urlsplit(u)
            key = (p.path, tuple(sorted(parse_qs(p.query).keys())))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            targets.append(u)
        targets = (targets or crawled)[:80]

        # 3) فحص DAST على المكتشَف (run_authscan يعيد التحقق من النطاق لكل هدف).
        def nuclei_dast(tgts: list[str]) -> list[dict]:
            extra = ["-dast"]
            if hdr:
                extra += ["-H", "Cookie: " + hdr]
            return tools.run_nuclei(tgts, extra_args=extra, timeout=settings.strix_timeout or 1800)

        run_authscan(db, program, targets, nuclei_dast)
        correlated = correlate(db, program)
        return {
            "status": "done",
            "correlated": len(correlated),
            "crawled": len(crawled),
            "scanned": len(targets),
            "authenticated": bool(hdr),
        }
    finally:
        db.close()


@celery_app.task(name="zap.run", base=ResilientTask, **RETRY)
def zap_run(program_id: int, seed: str) -> dict:
    """فحص نشط عميق مُصادَق عبر OWASP ZAP (spider + active scan) — بلا LLM."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from api.services.auth_loader import load_login_config
    from workers.authscan import UrllibClient, cookie_header
    from workers.autologin import auto_login
    from workers.correlation_logic import correlate
    from workers.zap_scan import ZapClient, run_zap_scan

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}

        # تسجيل دخول تلقائي (يُعاد استخدام الإعداد المحفوظ) للحصول على كوكي الجلسة.
        login = load_login_config(db, program_id)
        hdr = ""
        if login and login.get("username"):
            try:
                cookies = auto_login(
                    UrllibClient(), login.get("url") or seed, login["username"], login.get("password") or ""
                )
                cookies.update(login.get("extra_cookies") or {})
                hdr = cookie_header(cookies)
            except Exception:
                hdr = ""
        elif login and login.get("extra_cookies"):
            hdr = cookie_header(dict(login["extra_cookies"]))

        zap = ZapClient(settings.zap_url, settings.zap_api_key, timeout=60)
        try:
            run_zap_scan(db, program, seed, zap, cookie_header=hdr, max_wait=settings.zap_timeout)
        except Exception as exc:
            # غالبًا ZAP غير مشغّل — نُرجِع سببًا واضحًا بدل انهيار صامت.
            return {"status": "failed", "reason": f"ZAP غير متاح أو فشل الفحص: {str(exc)[:200]}"}

        correlated = correlate(db, program)
        return {"status": "done", "correlated": len(correlated), "authenticated": bool(hdr)}
    finally:
        db.close()


@celery_app.task(name="confirm.run", base=ResilientTask, **RETRY)
def confirm_run(program_id: int) -> dict:
    """تأكيد نشط لكل نتائج البرنامج — يرسل طلبات تحقّق فعلية (بلا LLM)."""
    from api.db import SessionLocal
    from api.models.program import Program
    from api.services.auth_loader import load_login_config
    from workers.authscan import UrllibClient, cookie_header
    from workers.autologin import auto_login
    from workers.confirm_logic import run_confirmations
    from workers.confirmers import HttpProbe

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}

        # جلسة مُصادَقة (يُعاد استخدام إعداد الدخول المحفوظ) حتى يفحص خلف الدخول.
        login = load_login_config(db, program_id)
        hdr = ""
        if login and login.get("username") and login.get("url"):
            try:
                cookies = auto_login(
                    UrllibClient(), login["url"], login["username"], login.get("password") or ""
                )
                cookies.update(login.get("extra_cookies") or {})
                hdr = cookie_header(cookies)
            except Exception:
                hdr = ""
        elif login and login.get("extra_cookies"):
            hdr = cookie_header(dict(login["extra_cookies"]))

        counts = run_confirmations(db, program, HttpProbe(cookie_header=hdr, timeout=20))
        return {"status": "done", **counts}
    finally:
        db.close()


@celery_app.task(name="pipeline.scheduled_recon")
def scheduled_recon() -> dict:
    """مهمة دورية (beat): تشغّل الـ pipeline لكل برنامج نشط حسب نطاقه."""
    from sqlalchemy import select

    from api.db import SessionLocal
    from api.models.program import Program
    from workers.orchestration import derive_seeds

    db = SessionLocal()
    try:
        programs = list(db.scalars(select(Program).where(Program.active.is_(True))))
        enqueued = 0
        for program in programs:
            for seed in derive_seeds(program):
                pipeline_run_full.delay(program.id, seed)
                enqueued += 1
        return {"programs": len(programs), "enqueued": enqueued}
    finally:
        db.close()


@celery_app.task(name="scope.sync", base=ResilientTask, **RETRY)
def scope_sync(program_id: int) -> dict:
    """يزامن نطاق برنامج من HackerOne ويعطّل الأصول التي خرجت من النطاق."""
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.scope_sync import fetch_structured_scopes, reconcile_scope

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        remote = fetch_structured_scopes(program.handle)
        if not remote:
            return {"status": "skipped", "reason": "لا نطاق بعيد (مفاتيح HackerOne غير مهيّأة؟)"}
        return reconcile_scope(db, program, remote)
    finally:
        db.close()


@celery_app.task(name="scope.sync_all")
def scope_sync_all() -> dict:
    """مهمة دورية: يزامن نطاق كل البرامج النشطة."""
    from sqlalchemy import select

    from api.db import SessionLocal
    from api.models.program import Program

    db = SessionLocal()
    try:
        programs = list(db.scalars(select(Program).where(Program.active.is_(True))))
        for program in programs:
            scope_sync.delay(program.id)
        return {"programs": len(programs)}
    finally:
        db.close()


@celery_app.task(name="dup.check", base=ResilientTask, **RETRY)
def dup_check(program_id: int) -> dict:
    """يفحص تكرار نتائج برنامج مقابل تقارير HackerOne السابقة."""
    from api.db import SessionLocal
    from api.models.program import Program
    from api.services.dedupe import flag_duplicates
    from workers.hackerone import fetch_prior_reports

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        priors = fetch_prior_reports(program.handle)
        return {"flagged": flag_duplicates(db, program, priors)}
    finally:
        db.close()


@celery_app.task(name="monitor.check_workers")
def monitor_check_workers() -> dict:
    """مراقبة دورية: يُنبّه إن لم يوجد أي worker نشط."""
    from api.services.notify import evaluate_worker_health, get_notifier

    try:
        ping = celery_app.control.inspect(timeout=2).ping() or {}
    except Exception:
        ping = {}
    alive = evaluate_worker_health(ping, get_notifier())
    return {"alive": alive}


@celery_app.task(name="strix.run", base=ResilientTask, **RETRY)
def strix_run(program_id: int, target: str, instruction: str | None = None) -> dict:
    """يشغّل Strix على هدف واحد (بعد فرض النطاق) ويخزّن نتائجه كـ findings."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.strix_cli import run_strix_cli

    def runner(tgt: str, instr: str | None):
        return run_strix_cli(
            tgt,
            instr,
            output_root=settings.strix_runs_dir,
            budget=settings.strix_budget or None,
            timeout=settings.strix_timeout,
        )

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        scan_run, findings = run_strix_scan(db, program, target, runner, instruction=instruction)
        # دمج حتى تظهر نتائج Strix في اللوحة مع بقية النتائج.
        from workers.correlation_logic import correlate

        correlated = correlate(db, program)
        return {
            "status": "done",
            "scan_run_id": scan_run.id,
            "scan_status": scan_run.status.value,
            "findings": len(findings),
            "correlated": len(correlated),
        }
    finally:
        db.close()
