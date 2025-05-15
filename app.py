# main.py
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Union
from sympy import randprime
from random import randint
import base64, json

app = FastAPI(
    title="Prismo Message Tools",
    description="Generates BGN public/private key pairs on demand.",
    version="1.1.0",
)

# ───────────────────── helper: key generation ─────────────────────
def generate_bgn_keys(bit_length: int = 256) -> Dict[str, Dict[str, str]]:
    p = randprime(2**bit_length, 2**(bit_length + 1))
    q = randprime(2**bit_length, 2**(bit_length + 1))
    while q == p:
        q = randprime(2**bit_length, 2**(bit_length + 1))
    return {"public": {"n": str(p * q)}, "private": {"p": str(p), "q": str(q)}}


# ───────────────────── helper: additive encrypt ───────────────────
def encrypt_value(m: int, n: int) -> int:
    """BGN-style additive encryption"""
    return m + randint(1, 9_999_999) * n


def encrypt_text(message: str, n: int) -> List[int]:
    """UTF-8 → per-byte additive encryption list[int]"""
    return [encrypt_value(b, n) for b in message.encode("utf-8")]


# ─────────────────────── schemas ───────────────────────
class PubKey(BaseModel):
    n: str


class EncryptRequest(BaseModel):
    message: str = Field(..., description="Plaintext to encrypt")
    public_key: Union[PubKey, str] = Field(
        ..., description="Either raw {'n': …} or Base64-encoded JSON"
    )
    encode: bool = Field(True, description="Return Base64-encoded ciphertext list")

    @validator("public_key", pre=True)
    def _coerce_pubkey(cls, v):
        if isinstance(v, str):  # accept Base64 string
            v = json.loads(base64.b64decode(v).decode())
        return v


class EncryptResponse(BaseModel):
    ciphertext: Union[str, List[int]]


# ─────────────────────── routes ───────────────────────
@app.get("/generate-keys")
def generate_keys(
    bit_length: int = Query(256, ge=16, le=4096, description="Prime size (bits)"),
    encode: bool = Query(
        True, description="Return Base64-encoded JSON keys if true"
    ),
):
    keys = generate_bgn_keys(bit_length)
    return (
        {k: base64.b64encode(json.dumps(v).encode()).decode() for k, v in keys.items()}
        if encode
        else keys
    )


@app.post("/encrypt-string", response_model=EncryptResponse)
def encrypt_string(req: EncryptRequest):
    n = int(req.public_key["n"])
    ct_list = encrypt_text(req.message, n)

    if req.encode:
        blob = base64.b64encode(json.dumps(ct_list).encode()).decode()
        return {"ciphertext": blob}

    return {"ciphertext": ct_list}