import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
import jwt


def get_jwt_secret() -> str:
    secret: Optional[str] = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret


app = FastAPI(title="Zero Trust API Gateway", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/proxy/{endpoint}")
def proxy(endpoint: str, authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # In a full gateway, this would forward to an internal service.
    # Here we return a placeholder response proving auth succeeded.
    return {"proxied_endpoint": endpoint, "user": payload.get("user")}

