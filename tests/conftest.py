"""تجهيزات الاختبار — قاعدة SQLite في الذاكرة + عميل FastAPI."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.db import get_db
from api.main import app
from api.models.base import Base


@pytest.fixture
def db_session():
    # StaticPool => اتصال واحد مشترك حتى تبقى قاعدة الذاكرة ثابتة طوال الاختبار.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def client(db_session):
    def _override():
        yield db_session

    app.dependency_overrides[get_db] = _override
    # بدون `with` حتى لا يعمل lifespan (init_db على محرك التطوير) أثناء الاختبار.
    yield TestClient(app)
    app.dependency_overrides.clear()
