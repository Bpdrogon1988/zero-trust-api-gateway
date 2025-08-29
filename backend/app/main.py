import os
import hmac
import hashlib
import time
from fastapi import FastAPI, Header, HTTPException, Request
from .aws_secrets import resolve_secret

app = FastAPI(title="Backend Service", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "backend"}


def verify_signature(method: str, endpoint: str, ts: str, subject: str, signature: str) -> bool:
    key = resolve_secret(
        direct_env_var_name="SHARED_BACKEND_KEY",
        secret_name_env_var_name="SHARED_BACKEND_KEY_NAME",
        kms_cipher_env_var_name="SHARED_BACKEND_KEY_KMS_B64",
        required=True,
    )
    if not key:
        return False
    try:
        ts_int = int(ts)
    except Exception:
        return False
    if abs(int(time.time()) - ts_int) > 30:
        return False
    canonical = f"{method}:{endpoint}:{ts}:{subject}"
    expected = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.get("/data")
def data(request: Request, x_gateway_timestamp: str = Header(alias="X-Gateway-Timestamp"), x_gateway_signature: str = Header(alias="X-Gateway-Signature"), x_subject: str = Header(alias="X-Subject")) -> dict:
    endpoint = "data"
    if not verify_signature("GET", endpoint, x_gateway_timestamp, x_subject, x_gateway_signature):
        raise HTTPException(status_code=401, detail="Invalid gateway signature")
    return {"message": "Hello from backend", "items": [1, 2, 3], "subject": x_subject}
