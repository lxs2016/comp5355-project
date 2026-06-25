import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from server.auth import bearer_token, create_token, hash_password, verify_password
from server.database import get_conn, init_db
from server.models import (
    HandshakeInitRequest,
    HandshakeInitResponse,
    HandshakeStatusResponse,
    HealthResponse,
    KeyBundleResponse,
    LoginRequest,
    LoginResponse,
    PendingHandshake,
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


# ---------------------------------------------------------------------------
# Handshake  (Phase 2)
# ---------------------------------------------------------------------------

@app.post("/handshake", response_model=HandshakeInitResponse)
def post_handshake(
    req: HandshakeInitRequest,
    initiator: str = Depends(bearer_token),
):
    """Initiator submits a new handshake envelope for the responder."""
    with get_conn() as conn:
        # Verify responder exists
        if not conn.execute(
            "SELECT 1 FROM users WHERE username=?", (req.to,)
        ).fetchone():
            raise HTTPException(404, f"User '{req.to}' not found")
        # Guard against duplicate session_id
        if conn.execute(
            "SELECT 1 FROM handshakes WHERE session_id=?", (req.session_id,)
        ).fetchone():
            raise HTTPException(409, "session_id already exists")
        conn.execute(
            "INSERT INTO handshakes "
            "(session_id, initiator, responder, EK_pub, hs_signature, transcript_hash, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                req.session_id,
                initiator,
                req.to,
                req.EK_pub,
                req.hs_sig,
                req.transcript_hash,
                "pending",
                int(time.time()),
            ),
        )
    return {"ok": True}


@app.get("/handshakes/pending", response_model=list[PendingHandshake])
def get_pending_handshakes(responder: str = Depends(bearer_token)):
    """Responder polls for all pending handshakes addressed to them."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT session_id, initiator, EK_pub, hs_signature, transcript_hash "
            "FROM handshakes WHERE responder=? AND status='pending'",
            (responder,),
        ).fetchall()
    return [
        {
            "session_id": r["session_id"],
            "initiator": r["initiator"],
            "EK_pub": r["EK_pub"],
            "hs_sig": r["hs_signature"],
            "transcript_hash": r["transcript_hash"],
        }
        for r in rows
    ]


@app.get("/handshake/{session_id}", response_model=HandshakeStatusResponse)
def get_handshake_status(
    session_id: str,
    _caller: str = Depends(bearer_token),
):
    """Both sides can poll this to check whether the session is established."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status FROM handshakes WHERE session_id=?", (session_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Handshake not found")
    return {"status": row["status"]}


@app.post("/handshake/{session_id}/ack", response_model=HandshakeInitResponse)
def ack_handshake(
    session_id: str,
    responder: str = Depends(bearer_token),
):
    """Responder acknowledges after successfully deriving SK."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status, responder FROM handshakes WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Handshake not found")
        if row["responder"] != responder:
            raise HTTPException(403, "Not the designated responder")
        if row["status"] != "pending":
            raise HTTPException(409, f"Handshake already in state '{row['status']}'")
        conn.execute(
            "UPDATE handshakes SET status='established' WHERE session_id=?",
            (session_id,),
        )
    return {"ok": True}
