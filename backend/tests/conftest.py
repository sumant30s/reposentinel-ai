from pathlib import Path

import pytest
from app.core.config import Settings
from app.main import create_app
from app.models.database import Base, make_engine
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

TOKEN = "testing-only-token-" + "x" * 32


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        database_url=f"sqlite:///{tmp_path}/test.db",
        api_token=TOKEN,
        sample_dir=Path(__file__).resolve().parents[2] / "sample_projects/vulnerable",
        engines="",
        osv_enabled=False,
        rate_limit_per_minute=200,
    )


@pytest.fixture
def engine(settings):
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as session:
        yield session


@pytest.fixture
def client(settings, engine):
    with TestClient(create_app(settings)) as client:
        client.headers["Authorization"] = f"Bearer {TOKEN}"
        yield client
