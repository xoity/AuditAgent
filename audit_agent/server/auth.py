import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from passlib.context import CryptContext

from .schemas import TokenData


def _load_secret_key() -> str:
    if secret_key := os.environ.get("AUDITAGENT_SECRET_KEY"):
        return secret_key

    secret_file = Path(
        os.environ.get(
            "AUDITAGENT_SECRET_KEY_FILE",
            Path.home() / ".auditagent" / "server_secret",
        )
    )
    secret_dir = secret_file.parent
    secret_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret_dir.chmod(0o700)

    if secret_file.exists():
        secret_key = secret_file.read_text().strip()
        if not secret_key:
            raise RuntimeError(f"Secret key file is empty: {secret_file}")
        secret_file.chmod(0o600)
        return secret_key

    secret_key = secrets.token_urlsafe(64)
    try:
        fd = os.open(secret_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        secret_key = secret_file.read_text().strip()
        if not secret_key:
            raise RuntimeError(f"Secret key file is empty: {secret_file}")
        secret_file.chmod(0o600)
        return secret_key

    with os.fdopen(fd, "w") as secret_handle:
        secret_handle.write(secret_key)
    return secret_key


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return TokenData(username=username)
    except JWTError:
        return None
