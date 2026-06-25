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
