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
    dnsx=tools.run_dnsx,
    httpx_ports=lambda hosts, ports: tools.run_httpx(hosts, ports=ports),
)

DEFAULT_SCAN_TOOLS = ScanTools(nuclei=tools.run_nuclei)


def scan_tools_for(program) -> ScanTools:
    """أدوات الفحص مع حدّ معدّل البرنامج (ROE: rate_limit_per_min) إن وُجد."""
    rate = getattr(program, "rate_limit_per_min", None)
    if not rate:
        return DEFAULT_SCAN_TOOLS
    return ScanTools(nuclei=lambda targets: tools.run_nuclei(targets, rate_per_min=rate))


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
            db, program, scan_tools_for(program), output_dir=settings.strix_runs_dir
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
            "status": scan_run.status.value,
            "outcome": scan_run.outcome,
            "blocked_hosts": scan_run.blocked_hosts,
            "findings": len(findings),
            "by_severity": sev,
        }
    finally:
        db.close()


@celery_app.task(name="pipeline.run_full", base=ResilientTask, **RETRY)
def pipeline_run_full(program_id: int, seed: str) -> dict:
    """السلسلة الكاملة recon → scan → correlate تحت قفل تزامن."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.locks import redis_lock
    from workers.orchestration import PipelineLocked, run_pipeline

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        try:
            correlated = run_pipeline(
                db, program, seed, DEFAULT_TOOLS, scan_tools_for(program),
                lock=redis_lock(f"pipeline:{program_id}"),
                output_dir=settings.strix_runs_dir,
            )
        except PipelineLocked as exc:
            return {"status": "skipped", "reason": str(exc)}
        return {"status": "done", "correlated": len(correlated)}
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
        if not instruction:
            from api.services.account_summary import strix_idor_instruction
            instruction = strix_idor_instruction(db, program_id)
        scan_run, findings = run_strix_scan(db, program, target, runner, instruction=instruction)
        return {
            "scan_run_id": scan_run.id,
            "status": scan_run.status.value,
            "findings": len(findings),
        }
    finally:
        db.close()


@celery_app.task(name="verify.run", base=ResilientTask, **RETRY)
def verify_run(program_id: int) -> dict:
    """يعيد إنتاج نتائج nuclei (نفس القالب على نفس الهدف) ويعلّم ما تكرّر verified."""
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.verify_logic import verify_findings

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        rate = program.rate_limit_per_min

        def rerun(target: str, template_id: str) -> list[dict]:
            return tools.run_nuclei([target], rate_per_min=rate, template_ids=[template_id])

        return verify_findings(db, program, rerun)
    finally:
        db.close()


@celery_app.task(name="accounts.provision", base=ResilientTask, **RETRY)
def accounts_provision(program_id: int, recipe: dict, count: int = 2) -> dict:
    """ينشئ حسابات اختبار (IDOR) على الهدف عبر نموذج تسجيله. ROE + نطاق إلزاميان."""
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.account_http import register_over_http
    from workers.account_logic import AccountRecipe, provision_accounts

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        accts = provision_accounts(
            db, program, AccountRecipe(**recipe), register_over_http, count=count
        )
        ok = [a for a in accts if a.status == "created"]
        return {"requested": count, "created": len(ok),
                "accounts": [{"label": a.label, "status": a.status} for a in accts]}
    finally:
        db.close()


@celery_app.task(name="idor.run", base=ResilientTask, **RETRY)
def idor_run(program_id: int, resources: list[dict]) -> dict:
    """يشغّل الفحص التفاضلي لـ IDOR على موارد يملكها حساب A، بجلسة الحساب B."""
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.account_http import make_idor_requester
    from workers.idor_db import run_idor
    from workers.idor_logic import OwnedResource

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        owned = [OwnedResource(**r) for r in resources]
        scan_run, findings = run_idor(db, program, owned, make_idor_requester())
        return {"scan_run_id": scan_run.id, "status": scan_run.status.value,
                "outcome": scan_run.outcome, "findings": len(findings)}
    finally:
        db.close()


@celery_app.task(name="accounts.discover_provision", base=ResilientTask, **RETRY)
def accounts_discover_provision(program_id: int, seed: str, count: int = 2) -> dict:
    """يزحف الهدف لاكتشاف نموذج التسجيل تلقائيًا ثم ينشئ الحسابات. ROE + نطاق إلزاميان.

    عند كشف CAPTCHA لا يُتخطّى — يُبلَّغ ويُترك للتجهيز اليدوي.
    """
    from api.db import SessionLocal
    from api.models.audit import AuditLog
    from api.models.program import Program
    from workers.account_http import make_page_fetcher, register_over_http
    from workers.account_logic import provision_accounts
    from workers.form_discovery import discover_registration

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}

        disc = discover_registration(seed, make_page_fetcher())
        db.add(AuditLog(action="register_form_discovery", target_value=seed,
                        program_id=program_id,
                        decision="allow" if disc.recipe else "deny", reason=disc.reason,
                        actor="discover"))
        db.commit()
        if disc.recipe is None:
            return {"status": "no_form", "reason": disc.reason, "captcha": disc.captcha}
        if disc.captcha:
            return {"status": "captcha_blocked", "provider": disc.captcha,
                    "page": disc.page_url,
                    "reason": "لا يُتخطّى CAPTCHA — جهّز الجلسة يدويًا عبر credentials"}

        accts = provision_accounts(db, program, disc.recipe, register_over_http, count=count)
        return {"status": "done", "register_url": disc.recipe.register_url,
                "created": sum(1 for a in accts if a.status == "created"),
                "accounts": [{"label": a.label, "status": a.status} for a in accts]}
    finally:
        db.close()


@celery_app.task(name="idor.auto", base=ResilientTask, **RETRY)
def idor_auto(program_id: int, seed_urls: list[str]) -> dict:
    """اكتشاف مراجع كائنات الحساب A بالزحف ثم فحص IDOR تفاضلي بجلسة B."""
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.account_http import make_idor_requester
    from workers.idor_db import run_auto_idor

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        scan_run, findings = run_auto_idor(db, program, seed_urls, make_idor_requester())
        return {"scan_run_id": scan_run.id, "status": scan_run.status.value,
                "outcome": scan_run.outcome, "findings": len(findings)}
    finally:
        db.close()
