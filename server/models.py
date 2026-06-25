from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str
    IK_sig_pub: str  # base64-encoded Ed25519 verify key
    IK_dh_pub: str   # base64-encoded X25519 public key
    SPK_pub: str     # base64-encoded X25519 signed-prekey public key
    SPK_sig: str     # base64-encoded Ed25519 signature of SPK_pub by IK_sig


class RegisterResponse(BaseModel):
    ok: bool


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str


# ---------------------------------------------------------------------------
# Key bundle
# ---------------------------------------------------------------------------

class KeyBundleResponse(BaseModel):
    IK_sig_pub: str
    IK_dh_pub: str
    SPK_pub: str
    SPK_sig: str


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

class HandshakeInitRequest(BaseModel):
    session_id: str
    to: str              # responder username
    EK_pub: str          # base64 ephemeral X25519 public key
    hs_sig: str          # base64 Ed25519 signature of transcript_hash by initiator
    transcript_hash: str  # base64 SHA-256 of (session_id || EK_pub || bob.IK_dh_pub || bob.SPK_pub)


class HandshakeInitResponse(BaseModel):
    ok: bool


class PendingHandshake(BaseModel):
    session_id: str
    initiator: str
    EK_pub: str
    hs_sig: str
    transcript_hash: str


class HandshakeStatusResponse(BaseModel):
    status: str  # "pending" | "established"
