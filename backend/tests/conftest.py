import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.session import Base, get_db
from app.core.config import settings

TEST_DB_FILE = "./test_session_defense.db"
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"

test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture
def sample_fingerprint():
    return {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "user_agent_family": "Chrome",
        "platform": "MacIntel",
        "language": "en-US",
        "languages": ["en-US", "en"],
        "timezone": "America/New_York",
        "timezone_offset": 300,
        "screen": {
            "width": 1920,
            "height": 1080,
            "color_depth": 24,
            "pixel_ratio": 2.0
        },
        "hardware_concurrency": 8,
        "device_memory": 16.0,
        "canvas_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "webgl_vendor": "Apple",
        "webgl_renderer": "Apple M2 Pro",
        "audio_fingerprint": "124.04375"
    }

@pytest.fixture
def attacker_fingerprint():
    return {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "user_agent_family": "Firefox",
        "platform": "Win32",
        "language": "ru-RU",
        "languages": ["ru-RU", "ru"],
        "timezone": "Europe/Moscow",
        "timezone_offset": -180,
        "screen": {
            "width": 1366,
            "height": 768,
            "color_depth": 24,
            "pixel_ratio": 1.0
        },
        "hardware_concurrency": 4,
        "device_memory": 4.0,
        "canvas_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
        "webgl_vendor": "Google Inc. (NVIDIA)",
        "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0)",
        "audio_fingerprint": "987.65432"
    }
