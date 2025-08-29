import os
import time
import hmac
import hashlib
import json
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import jwt
from web3 import Web3
from redis import Redis


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Environment variable {name} is not set")
    return value


def get_jwt_secret() -> str:
    secret: Optional[str] = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret


def get_redis() -> Redis:
    redis_url = get_env("REDIS_URL", "redis://redis:6379/0")
    return Redis.from_url(redis_url, decode_responses=True)


def get_web3() -> Web3:
    provider = get_env("WEB3_PROVIDER_URL", "http://ganache:8545")
    return Web3(Web3.HTTPProvider(provider))


def is_revoked(jti: str) -> bool:
    if not jti:
        return True
    redis_client = get_redis()
    return redis_client.exists(f"revoked:{jti}") == 1


def is_rate_limited(subject: str) -> bool:
    redis_client = get_redis()
    key = f"rl:{subject}:{int(time.time())}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, 1)
    limit = int(os.getenv("RATE_LIMIT_PER_SEC", "10"))
    return count > limit


_contract_cache = {"address": None, "abi": None}


def load_allowlist_contract(web3: Web3):
    global _contract_cache
    if _contract_cache["address"] and _contract_cache["abi"]:
        return web3.eth.contract(address=_contract_cache["address"], abi=_contract_cache["abi"])
    path = os.getenv("ALLOWLIST_CONTRACT_PATH", "/contracts/Allowlist.json")
    try:
        data = json.loads(Path(path).read_text())
        address = Web3.to_checksum_address(data["address"])  # type: ignore
        abi = data["abi"]
        _contract_cache["address"] = address
        _contract_cache["abi"] = abi
        return web3.eth.contract(address=address, abi=abi)
    except Exception:
        return None


def verify_allowlist(address: str) -> bool:
    allowlist = os.getenv("ALLOWLIST_ADDRESSES", "")
    if not allowlist:
        # Try on-chain allowlist if available
        try:
            web3 = get_web3()
            contract = load_allowlist_contract(web3)
            if contract is None:
                return True
            return bool(contract.functions.isAllowed(Web3.to_checksum_address(address)).call())
        except Exception:
            return True
    allowed = {a.strip().lower() for a in allowlist.split(",") if a.strip()}
    return address.lower() in allowed


app = FastAPI(title="Zero Trust API Gateway", version="0.2.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/auth/nonce")
def get_nonce(address: str) -> dict:
    # bind a short-lived nonce to the address for signing
    if not Web3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    nonce = Web3.keccak(text=f"{address}:{time.time_ns()}").hex()
    redis_client = get_redis()
    redis_client.setex(f"nonce:{address.lower()}", 300, nonce)
    return {"nonce": nonce}


@app.post("/auth/login")
def login(address: str, signature: str) -> dict:
    if not Web3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    redis_client = get_redis()
    nonce_key = f"nonce:{address.lower()}"
    nonce = redis_client.get(nonce_key)
    if not nonce:
        raise HTTPException(status_code=400, detail="Nonce expired or not found")

    # EIP-191 personal_sign verification
    web3 = get_web3()
    try:
        from eth_account.messages import encode_defunct
        recovered = web3.eth.account.recover_message(encode_defunct(text=nonce), signature=signature)
    except Exception:
        raise HTTPException(status_code=401, detail="Signature verification failed")

    if recovered.lower() != address.lower():
        raise HTTPException(status_code=401, detail="Signature does not match address")

    if not verify_allowlist(address):
        raise HTTPException(status_code=403, detail="Address not allowed")

    # issue JWT
    now = int(time.time())
    payload = {
        "sub": address.lower(),
        "iat": now,
        "exp": now + int(os.getenv("JWT_TTL_SECONDS", "900")),
        "jti": Web3.keccak(text=f"{address}:{now}").hex(),
    }
    token = jwt.encode(payload, get_jwt_secret(), algorithm="HS256")
    redis_client.delete(nonce_key)
    return {"token": token}


@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"], options={"verify_exp": False})
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    jti = payload.get("jti")
    exp = payload.get("exp", int(time.time()) + 900)
    ttl = max(1, exp - int(time.time()))
    redis_client = get_redis()
    redis_client.setex(f"revoked:{jti}", ttl, 1)
    return {"revoked": True}


@app.get("/proxy/{endpoint}")
async def proxy(endpoint: str, request: Request, authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    subject = payload.get("sub") or payload.get("user")
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid subject")

    if is_revoked(payload.get("jti", "")):
        raise HTTPException(status_code=401, detail="Token revoked")

    if is_rate_limited(subject):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    backend_url = get_env("BACKEND_URL", "http://backend:9000")
    url = f"{backend_url}/{endpoint.lstrip('/')}"

    # HMAC sign request to backend
    key = os.getenv("SHARED_BACKEND_KEY")
    if not key:
        raise HTTPException(status_code=500, detail="Backend signing key not configured")
    ts = str(int(time.time()))
    canonical = f"GET:{endpoint.lstrip('/')}:{ts}:{subject}"
    sig = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                url,
                headers={
                    "X-Gateway-Timestamp": ts,
                    "X-Gateway-Signature": sig,
                    "X-Subject": subject,
                },
            )
        except httpx.RequestError:
            raise HTTPException(status_code=502, detail="Backend unavailable")

    return JSONResponse(status_code=resp.status_code, content=resp.json())

