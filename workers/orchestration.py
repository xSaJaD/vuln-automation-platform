"""تنسيق الـ pipeline الكامل (recon → scan → correlate) — قابل للاختبار.

القفل (lock) يُحقَن كـ context manager يُرجِع bool (هل حُجز)، حتى يمكن اختباره
ببديل وهمي. في الإنتاج يُمرَّر قفل Redis لمنع التشغيل المتزامن لنفس البرنامج.
"""

from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext

from sqlalchemy.orm import Session

from api.models.program import Program
from workers.correlation_logic import correlate
from workers.recon_logic import ReconTools, run_full_recon
from workers.scan_logic import ScanTools, scan_hosts


class PipelineLocked(Exception):
    """يُرفع حين يكون الـ pipeline قيد التشغيل بالفعل لنفس البرنامج."""


def derive_seeds(program: Program) -> list[str]:
    """يستخرج نطاقات الجذر (seeds) من نطاق البرنامج ضمن النطاق."""
    seeds: set[str] = set()
    for asset in program.scope_assets:
        if not asset.in_scope:
            continue
        kind = asset.kind.value
        if kind == "domain":
            seeds.add(asset.identifier.lower())
        elif kind == "wildcard":
            base = asset.identifier.lower()
            seeds.add(base[2:] if base.startswith("*.") else base)
    return sorted(seeds)


def run_pipeline(
    db: Session,
    program: Program,
    seed: str,
    recon_tools: ReconTools,
    scan_tools: ScanTools,
    *,
    lock: AbstractContextManager[bool] | None = None,
    output_dir: str | None = None,
):
    """يشغّل السلسلة الكاملة تحت قفل تزامن. يرفع PipelineLocked لو القفل محجوز."""
    lock_cm: AbstractContextManager = lock if lock is not None else nullcontext(True)
    with lock_cm as acquired:
        if not acquired:
            raise PipelineLocked(f"pipeline قيد التشغيل بالفعل للبرنامج {program.handle}")
        run_full_recon(db, program, seed, recon_tools)
        scan_hosts(db, program, scan_tools, output_dir=output_dir)
        return correlate(db, program)
