"""
Tests for audit_agent.server.auth module.
"""

import importlib
import stat
import sys
import types

import pytest


def _load_auth(monkeypatch):
    jose_module = types.ModuleType("jose")
    jose_module.JWTError = Exception
    jose_module.jwt = types.SimpleNamespace()

    class FakeCryptContext:
        def __init__(self, *args, **kwargs):
            pass

        def hash(self, password):
            return f"pbkdf2:{password}"

        def verify(self, plain_password, hashed_password):
            return hashed_password == f"pbkdf2:{plain_password}"

    passlib_module = types.ModuleType("passlib")
    passlib_context_module = types.ModuleType("passlib.context")
    passlib_context_module.CryptContext = FakeCryptContext

    monkeypatch.setitem(sys.modules, "jose", jose_module)
    monkeypatch.setitem(sys.modules, "passlib", passlib_module)
    monkeypatch.setitem(sys.modules, "passlib.context", passlib_context_module)
    monkeypatch.setenv("AUDITAGENT_SECRET_KEY", "bootstrap-secret")
    auth = importlib.import_module("audit_agent.server.auth")
    return importlib.reload(auth)


def test_secret_key_uses_environment(monkeypatch):
    auth = _load_auth(monkeypatch)

    monkeypatch.setenv("AUDITAGENT_SECRET_KEY", "env-secret")

    assert auth._load_secret_key() == "env-secret"


def test_secret_key_reads_existing_file_and_locks_permissions(monkeypatch, tmp_path):
    auth = _load_auth(monkeypatch)
    secret_file = tmp_path / "server_secret"
    secret_file.write_text("file-secret")
    secret_file.chmod(0o644)
    monkeypatch.delenv("AUDITAGENT_SECRET_KEY", raising=False)
    monkeypatch.setenv("AUDITAGENT_SECRET_KEY_FILE", str(secret_file))

    assert auth._load_secret_key() == "file-secret"
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_file.parent.stat().st_mode) == 0o700


def test_secret_key_creates_file_with_restricted_permissions(monkeypatch, tmp_path):
    auth = _load_auth(monkeypatch)
    secret_file = tmp_path / "nested" / "server_secret"
    monkeypatch.delenv("AUDITAGENT_SECRET_KEY", raising=False)
    monkeypatch.setenv("AUDITAGENT_SECRET_KEY_FILE", str(secret_file))

    secret_key = auth._load_secret_key()

    assert secret_key
    assert secret_file.read_text() == secret_key
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_file.parent.stat().st_mode) == 0o700


def test_secret_key_rejects_empty_file(monkeypatch, tmp_path):
    auth = _load_auth(monkeypatch)
    secret_file = tmp_path / "server_secret"
    secret_file.write_text("")
    monkeypatch.delenv("AUDITAGENT_SECRET_KEY", raising=False)
    monkeypatch.setenv("AUDITAGENT_SECRET_KEY_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="Secret key file is empty"):
        auth._load_secret_key()


def test_verify_password_accepts_legacy_bcrypt_hash(monkeypatch):
    auth = _load_auth(monkeypatch)
    password = "admin"
    legacy_hash = "$2b$12$vat7sMIxPPbg5lzYprKL4e8MvR.PXE/I2c.b80hGpeKkQaXAztVUW"

    assert auth.verify_password(password, legacy_hash) is True
