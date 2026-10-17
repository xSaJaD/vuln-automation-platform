"""اختبارات تنسيق الـ pipeline والقفل — معيار قبول Phase 9.

الأهم: القفل يمنع التشغيل المتزامن، والجدولة لا تتكرر بشكل متضارب.
"""

import contextlib

import pytest

from api.models.correlation import CorrelatedFinding
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from workers.orchestration import PipelineLocked, derive_seeds, run_pipeline
from workers.recon_logic import ReconTools
from workers.scan_logic import ScanTools


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [
        ScopeAsset(kind=AssetKind.domain, identifier="example.com", in_scope=True),
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True),
    ]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _recon_tools():
    return ReconTools(
        subfinder=lambda d: ["api.example.com"],
        httpx=lambda hosts: [
            {"input": h, "status_code": 200, "title": "T", "tech": ["nginx"]} for h in hosts
        ],
        naabu=lambda h: [443],
    )


def _scan_tools():
    return ScanTools(
        nuclei=lambda targets: [
            {
                "template-id": "sqli",
                "info": {"name": "SQLi", "severity": "high"},
                "host": t,
                "matched-at": f"https://{t}/x",
            }
            for t in targets
        ]
    )


def test_pipeline_runs_end_to_end(db_session):
    p = _program(db_session)
    correlated = run_pipeline(db_session, p, "example.com", _recon_tools(), _scan_tools())

    assert db_session.query(Host).filter_by(program_id=p.id).count() >= 1
    assert len(correlated) >= 1
    assert db_session.query(CorrelatedFinding).count() >= 1


@contextlib.contextmanager
def _already_locked():
    yield False  # محاكاة قفل محجوز مسبقًا


def test_lock_prevents_concurrent_run(db_session):
    p = _program(db_session)

    with pytest.raises(PipelineLocked):
        run_pipeline(
            db_session, p, "example.com", _recon_tools(), _scan_tools(), lock=_already_locked()
        )

    # لم يُنفَّذ أي شيء لأن القفل محجوز
    assert db_session.query(Host).count() == 0
    assert db_session.query(CorrelatedFinding).count() == 0


@contextlib.contextmanager
def _free_lock():
    yield True


def test_free_lock_allows_run(db_session):
    p = _program(db_session)
    correlated = run_pipeline(
        db_session, p, "example.com", _recon_tools(), _scan_tools(), lock=_free_lock()
    )
    assert len(correlated) >= 1


def test_derive_seeds_dedups(db_session):
    p = _program(db_session)
    # domain=example.com و wildcard=*.example.com كلاهما يؤول إلى example.com
    assert derive_seeds(p) == ["example.com"]
