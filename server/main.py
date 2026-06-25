import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from server.auth import bearer_token, create_token, hash_password, verify_password
from server.database import get_conn, init_db
from server.models import (
    HealthResponse,
    KeyBundleResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="E2EE Relay Server", version="0.1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest):
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT username FROM users WHERE username=?", (req.username,)
        ).fetchone()
        if existing:
            raise HTTPException(400, "Username already taken")
        conn.execute(
            "INSERT INTO users (username, password_hash, IK_sig_pub, IK_dh_pub, SPK_pub, SPK_sig, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                req.username,
                hash_password(req.password),
                req.IK_sig_pub,
                req.IK_dh_pub,
                req.SPK_pub,
                req.SPK_sig,
                int(time.time()),
            ),
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username=?", (req.username,)
        ).fetchone()
    if row is None or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    return {"token": create_token(req.username)}


# ---------------------------------------------------------------------------
# Key bundle lookup  (requires authentication)
# ---------------------------------------------------------------------------

@app.get("/keys/{username}", response_model=KeyBundleResponse)
def get_keys(username: str, _caller: str = Depends(bearer_token)):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT IK_sig_pub, IK_dh_pub, SPK_pub, SPK_sig FROM users WHERE username=?",
            (username,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "User not found")
    return dict(row)
