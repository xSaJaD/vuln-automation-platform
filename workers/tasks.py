"""مهام Celery — أغلفة رفيعة حول منطق الـ recon."""

from __future__ import annotations

from workers import tools
from workers.recon_logic import ReconTools, run_full_recon
from workers.scan_logic import ScanTools, scan_hosts
from workers.strix_logic import run_strix_scan

# يُستورد celery_app بشكل كسول داخل الدالة لتجنّب دورة الاستيراد عند التسجيل.
from workers.celery_app import celery_app  # noqa: E402

DEFAULT_TOOLS = ReconTools(
    subfinder=tools.run_subfinder,
    httpx=tools.run_httpx,
    naabu=tools.run_naabu,
)

DEFAULT_SCAN_TOOLS = ScanTools(nuclei=tools.run_nuclei)


@celery_app.task(name="recon.run_full")
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


@celery_app.task(name="scan.run_nuclei")
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
        return {
            "scan_run_id": scan_run.id,
            "findings": len(findings),
            "by_severity": sev,
        }
    finally:
        db.close()


@celery_app.task(name="pipeline.run_full")
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
                db, program, seed, DEFAULT_TOOLS, DEFAULT_SCAN_TOOLS,
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


@celery_app.task(name="strix.run")
def strix_run(program_id: int, target: str, instruction: str | None = None) -> dict:
    """يشغّل Strix على هدف واحد (بعد فرض النطاق) ويخزّن نتائجه كـ findings."""
    from api.config import settings
    from api.db import SessionLocal
    from api.models.program import Program
    from workers.strix_cli import run_strix_cli

    def runner(tgt: str, instr: str | None) -> "StrixResult":  # noqa: F821
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
        return {
            "scan_run_id": scan_run.id,
            "status": scan_run.status.value,
            "findings": len(findings),
        }
    finally:
        db.close()
