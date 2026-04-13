"""
Demo FastAPI application — security-pipeline scan target.

This app intentionally contains patterns that security scanners should detect,
demonstrating the value of SAST/SCA/DAST in the pipeline.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import hashlib
import os
import logging

# ── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Demo App",
    description="Security pipeline scan target",
    version="1.0.0",
)

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ── Configuration ─────────────────────────────────────────────────────────────
# Secret is read from environment variable — never hardcoded in source.
# Bandit would flag a hardcoded secret; this demonstrates the correct pattern.

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")

# ── Models ────────────────────────────────────────────────────────────────────

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Item(BaseModel):
    name: str
    description: str | None = None

# ── Auth helpers ──────────────────────────────────────────────────────────────

# Simulated user store (would be a DB in production)
USERS: dict[str, str] = {
    "admin": pwd_context.hash("changeme"),
}

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/ready")
def ready():
    return {"status": "ready"}

@app.post("/auth/token", response_model=Token)
def login(user: UserLogin):
    hashed = USERS.get(user.username)
    if not hashed or not verify_password(user.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(
        {"sub": user.username},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/items")
def list_items(current_user: str = Depends(get_current_user)):
    return [{"id": 1, "name": "example", "owner": current_user}]

@app.post("/items")
def create_item(item: Item, current_user: str = Depends(get_current_user)):
    logger.info("User %s created item: %s", current_user, item.name)
    return {"id": 2, **item.model_dump(), "owner": current_user}

@app.get("/hash-demo")
def hash_demo(data: str):
    """
    Demonstrates secure vs insecure hashing.
    Bandit B324 would flag md5/sha1 usage without usedforsecurity=False.
    This endpoint uses SHA-256 (secure).
    """
    secure_hash = hashlib.sha256(data.encode()).hexdigest()
    return {"sha256": secure_hash}
