# main.py
from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import Dict
import base64, json
from sympy import randprime                    # demo-grade prime generator

app = FastAPI(
    title="Prismo Message Tools",
    description="Generates BGN public/private key pairs on demand.",
    version="1.0.0",
)

# ─────────────────────────── helpers ────────────────────────────

def _b64enc(data: Dict[str, str] | bytes) -> str:
    """B64-encode dicts (as JSON) or raw bytes."""
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
    return base64.b64encode(data).decode()

def _generate_bgn_keys(bit_length: int = 256) -> Dict[str, Dict[str, str]]:
    """Return {'public': {'n': …}, 'private': {'p': …, 'q': …}}."""
    p = randprime(2**bit_length, 2**(bit_length + 1))
    q = randprime(2**bit_length, 2**(bit_length + 1))
    while p == q:
        q = randprime(2**bit_length, 2**(bit_length + 1))
    return {"public": {"n": str(p * q)}, "private": {"p": str(p), "q": str(q)}}

# Response schemas (purely for OpenAPI docs)
class EncodedKeyPair(BaseModel):
    public_key: str
    private_key: str
class RawKeyPair(BaseModel):
    public_key: Dict[str, str]
    private_key: Dict[str, str]

# ─────────────────────────── endpoint ───────────────────────────

@app.get(
    "/generate-keys",
    summary="Generate a new BGN key-pair",
    responses={
        200: {
            "content": {
                "application/json": {
                    "schema": {"oneOf": [EncodedKeyPair.model_json_schema(), RawKeyPair.model_json_schema()]}
                }
            }
        }
    },
)
def generate_keys(
    bit_length: int = Query(256, ge=16, le=4096, description="Prime size (bits)"),
    encode: bool = Query(True, description="Return Base64-encoded JSON if true"),
):
    keys = _generate_bgn_keys(bit_length)
    return {k: _b64enc(v) if encode else v for k, v in keys.items()}