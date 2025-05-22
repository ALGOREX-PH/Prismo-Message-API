# main.py
from fastapi import FastAPI, Query, Form, Body, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Union
from sympy import randprime
from random import randint
import base64, json, logging

log = logging.getLogger("uvicorn.info")

app = FastAPI(
    title="Prismo Message Tools",
    description="Generates BGN public/private key pairs and encrypts strings.",
    version="1.2.0",
)

# ───────────────────── helpers ─────────────────────

# --- helper: parse private key ------------------------------------
def _b64_or_json_to_privkey(raw: Union[str, Dict]) -> Dict[str, str]:
    if isinstance(raw, dict):
        return raw
    try:
        decoded = base64.b64decode(raw).decode()
        return json.loads(decoded)
    except Exception:
        try:
            return json.loads(raw)
        except Exception:
            log.error("Bad private_key payload: %s", raw)
            raise HTTPException(
                422, "private_key must be Base64-encoded or JSON with fields 'p' and 'q'"
            )

# --- helper: decrypt list[int] ------------------------------------
def decrypt_ciphertext(cipher: List[int], n: int) -> str:
    bytes_out = bytes(c % n for c in cipher)
    return bytes_out.decode("utf-8", errors="replace")

def generate_bgn_keys(bit_length: int = 256) -> Dict[str, Dict[str, str]]:
    p = randprime(2**bit_length, 2**(bit_length + 1))
    q = randprime(2**bit_length, 2**(bit_length + 1))
    while q == p:
        q = randprime(2**bit_length, 2**(bit_length + 1))
    return {"public": {"n": str(p * q)}, "private": {"p": str(p), "q": str(q)}}


def encrypt_value(m: int, n: int) -> int:
    """BGN-style additive encryption"""
    return m + randint(1, 9_999_999) * n


def encrypt_text(message: str, n: int) -> List[int]:
    return [encrypt_value(b, n) for b in message.encode("utf-8")]


def _b64_or_json_to_pubkey(raw: Union[str, Dict]) -> Dict[str, str]:
    """Allow Base64-encoded or plain JSON."""
    if isinstance(raw, dict):
        return raw
    # try Base64 first
    try:
        decoded = base64.b64decode(raw).decode()
        return json.loads(decoded)
    except Exception:
        # maybe the caller gave us raw JSON string
        try:
            return json.loads(raw)
        except Exception:
            log.error("Bad public_key payload: %s", raw)
            raise HTTPException(
                status_code=422,
                detail="public_key must be Base64-encoded or JSON with field 'n'",
            )


def _str_to_bool(raw: str | bool | None, default=True) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    return raw.lower() in {"true", "1", "yes", "y", "t"}

# ───────────────────── Pydantic models ─────────────────────
class PubKey(BaseModel):
    n: str


class EncryptRequest(BaseModel):
    message: str = Field(..., description="Plaintext to encrypt")
    public_key: Union[PubKey, str] = Field(
        ..., description="Either raw {'n': …} or Base64-encoded JSON"
    )
    encode: bool = Field(
        True, description="If true, returns one Base64 blob; otherwise list[int]"
    )

    @validator("public_key", pre=True)
    def _coerce_pubkey(cls, v):
        return _b64_or_json_to_pubkey(v)


class EncryptResponse(BaseModel):
    ciphertext: Union[str, List[int]]

class DecryptRequest(BaseModel):
    ciphertext: Union[str, List[int]] = Field(
        ..., description="Base64 blob (default) or raw list[int]"
    )
    private_key: Union[Dict[str, str], str] = Field(
        ..., description="{'p': …, 'q': …} or Base64-encoded JSON"
    )
    is_b64: bool = Field(
        True, description="Set false if ciphertext is already a JSON list"
    )

class DecryptResponse(BaseModel):
    message: str

# ───────────────────── routes ─────────────────────
@app.get("/generate-keys")
def generate_keys(
    bit_length: int = Query(256, ge=16, le=4096, description="Prime size (bits)"),
    encode: bool = Query(True, description="Return Base64-encoded JSON keys if true"),
):
    keys = generate_bgn_keys(bit_length)
    return (
        {k: base64.b64encode(json.dumps(v).encode()).decode() for k, v in keys.items()}
        if encode
        else keys
    )

@app.post("/decrypt-string", response_model=DecryptResponse)
async def decrypt_string(
    # -------- form-data fields ----------
    ciphertext: str | None = Form(None),
    private_key: str | None = Form(None),
    is_b64: str | None = Form(None),
    # -------- JSON body ----------
    body: DecryptRequest | None = Body(None),
):
    # Decide which path (form-data vs JSON) ------------------------
    if body is None:
        if ciphertext is None or private_key is None:
            raise HTTPException(422, "form-data must include ciphertext and private_key")
        req = DecryptRequest(
            ciphertext=ciphertext,
            private_key=_b64_or_json_to_privkey(private_key),
            is_b64=_str_to_bool(is_b64, default=True),
        )
    else:
        req = body

    # Rebuild n = p * q -------------------------------------------
    priv = _b64_or_json_to_privkey(req.private_key)
    n = int(priv["p"]) * int(priv["q"])

    # Decode ciphertext list[int] ---------------------------------
    cipher_list = (
        json.loads(base64.b64decode(req.ciphertext).decode())
        if req.is_b64
        else req.ciphertext
    )
    if isinstance(cipher_list, str):             # edge: raw JSON string, not list
        cipher_list = json.loads(cipher_list)

    plain = decrypt_ciphertext(cipher_list, n)
    return {"message": plain}

@app.post("/encrypt-string", response_model=EncryptResponse)
async def encrypt_string(
    # ---------- form-data fields ----------
    message: str | None = Form(None),
    public_key: str | None = Form(None),
    encode: str | None = Form(None),
    # ---------- JSON body ----------
    body: EncryptRequest | None = Body(None),
):
    """
    Accepts *either*:\n
      • JSON body that matches EncryptRequest\n
      • multipart form-data with fields: message, public_key, (optional) encode
    """
    if body is None:  # ── form-data path ──
        if message is None or public_key is None:
            raise HTTPException(
                status_code=422,
                detail="form-data must include 'message' and 'public_key'",
            )
        req = EncryptRequest(
            message=message,
            public_key=_b64_or_json_to_pubkey(public_key),
            encode=_str_to_bool(encode, default=True),
        )
    else:             # ── JSON path ──
        req = body

    n_str = req.public_key.n if isinstance(req.public_key, PubKey) else req.public_key["n"]
    n = int(n_str)
    
    ct_list = encrypt_text(req.message, n)

    if req.encode:
        blob = base64.b64encode(json.dumps(ct_list).encode()).decode()
        return {"ciphertext": blob}
    return {"ciphertext": ct_list}