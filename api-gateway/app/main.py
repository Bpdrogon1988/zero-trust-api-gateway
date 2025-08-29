import os
import time
import hmac
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import jwt
from web3 import Web3
from redis import Redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Environment variable {name} is not set")
    return value


def _load_private_key(pem_data: bytes):
    try:
        return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    except Exception as exc:
        raise RuntimeError("Failed to load private key") from exc


def _public_jwk_from_key(key_obj, kid: str, alg: str) -> Dict[str, Any]:
    # Build minimal JWK for RSA/EC
    if isinstance(key_obj, rsa.RSAPrivateKey) or isinstance(key_obj, rsa.RSAPublicKey):
        public_key = key_obj.public_key() if hasattr(key_obj, "public_key") else key_obj
        numbers = public_key.public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder="big")
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
        return {
            "kty": "RSA",
            "kid": kid,
            "alg": alg,
            "use": "sig",
            "n": _b64url(n),
            "e": _b64url(e),
        }
    if isinstance(key_obj, ec.EllipticCurvePrivateKey) or isinstance(key_obj, ec.EllipticCurvePublicKey):
        public_key = key_obj.public_key() if hasattr(key_obj, "public_key") else key_obj
        numbers = public_key.public_numbers()
        x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, byteorder="big")
        y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, byteorder="big")
        crv_name = {
            "ES256": "P-256",
            "ES384": "P-384",
            "ES512": "P-521",
        }.get(alg, "P-256")
        return {
            "kty": "EC",
            "kid": kid,
            "alg": alg,
            "use": "sig",
            "crv": crv_name,
            "x": _b64url(x),
            "y": _b64url(y),
        }
    raise RuntimeError("Unsupported key type for JWK")


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_keys_cache: Dict[str, Any] = {"loaded_at": 0, "active_kid": None, "keys": {}}  # type: ignore


def _load_keys_from_dir(keys_dir: str) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    # Expect files like <kid>.<alg>.pem where alg in {RS256, ES256}
    path = Path(keys_dir)
    if not path.exists() or not path.is_dir():
        raise RuntimeError("JWT keys directory not found")
    keys: Dict[str, Dict[str, Any]] = {}
    for pem_file in path.glob("*.pem"):
        name = pem_file.stem  # <kid>.<alg>
        parts = name.split(".")
        if len(parts) < 2:
            continue
        kid = ".".join(parts[:-1])
        alg = parts[-1].upper()
        if alg not in {"RS256", "ES256", "ES384", "ES512"}:
            continue
        key_obj = _load_private_key(pem_file.read_bytes())
        keys[kid] = {
            "alg": alg,
            "private": key_obj,
            "public_jwk": _public_jwk_from_key(key_obj, kid, alg),
        }
    if not keys:
        raise RuntimeError("No valid JWT keys found in directory")
    active_kid = os.getenv("JWT_ACTIVE_KID") or sorted(keys.keys())[0]
    if active_kid not in keys:
        raise RuntimeError("JWT_ACTIVE_KID not present in keys")
    return active_kid, keys


def _get_keys(force_reload: bool = False) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    global _keys_cache
    now = time.time()
    if not force_reload and (now - _keys_cache["loaded_at"]) < int(os.getenv("JWT_KEYS_CACHE_SECONDS", "60")):
        return _keys_cache["active_kid"], _keys_cache["keys"]  # type: ignore
    keys_dir = os.getenv("JWT_KEYS_DIR", "/keys")
    active_kid, keys = _load_keys_from_dir(keys_dir)
    _keys_cache = {"loaded_at": now, "active_kid": active_kid, "keys": keys}
    return active_kid, keys


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

    # issue JWT using asymmetric signing (RS256/ES256) with kid
    now = int(time.time())
    payload = {
        "sub": address.lower(),
        "iat": now,
        "exp": now + int(os.getenv("JWT_TTL_SECONDS", "900")),
        "jti": Web3.keccak(text=f"{address}:{now}").hex(),
    }
    try:
        active_kid, keys = _get_keys()
        key_info = keys[active_kid]
        private_key = key_info["private"]
        alg = key_info["alg"]
        if isinstance(private_key, rsa.RSAPrivateKey) or isinstance(private_key, ec.EllipticCurvePrivateKey):
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            raise RuntimeError("Unsupported private key type")
        token = jwt.encode(payload, private_pem, algorithm=alg, headers={"kid": active_kid})
    except Exception:
        # Fallback to HS256 only if explicitly allowed (development)
        if os.getenv("ALLOW_HS256_FALLBACK", "false").lower() == "true":
            secret = os.getenv("JWT_SECRET", "dev-secret")
            token = jwt.encode(payload, secret, algorithm="HS256")
        else:
            raise HTTPException(status_code=500, detail="JWT signing keys not available")
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
        headers_unverified = jwt.get_unverified_header(token)
        kid = headers_unverified.get("kid")
        active_kid, keys = _get_keys()
        key_candidates = []
        if kid and kid in keys:
            key_candidates = [keys[kid]]
        else:
            key_candidates = list(keys.values())
        last_err: Optional[Exception] = None
        payload = None  # type: ignore
        for key_info in key_candidates:
            alg = key_info["alg"]
            public_jwk = key_info["public_jwk"]
            try:
                payload = jwt.decode(
                    token,
                    jwt.algorithms.get_default_algorithms()[alg].from_jwk(json.dumps(public_jwk)),  # type: ignore
                    algorithms=[alg],
                    options={"require": ["exp", "iat", "sub"]},
                )
                break
            except Exception as e:
                last_err = e
                continue
        if payload is None:
            if isinstance(last_err, jwt.ExpiredSignatureError):
                raise HTTPException(status_code=401, detail="Token expired")
            raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception:
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

    # HMAC sign request to backend (will be enhanced in subsequent task for nonce/body hash)
    key = os.getenv("SHARED_BACKEND_KEY")
    key_id = os.getenv("SHARED_BACKEND_KEY_ID", "v1")
    if not key:
        raise HTTPException(status_code=500, detail="Backend signing key not configured")
    ts = str(int(time.time()))
    canonical = f"GET:{endpoint.lstrip('/')}:?:{ts}:{subject}"
    sig = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                url,
                headers={
                    "X-Gateway-Timestamp": ts,
                    "X-Gateway-Signature": sig,
                    "X-Subject": subject,
                    "X-Key-Id": key_id,
                },
            )
        except httpx.RequestError:
            raise HTTPException(status_code=502, detail="Backend unavailable")

    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/.well-known/jwks.json")
def jwks() -> dict:
    try:
        _, keys = _get_keys()
        return {"keys": [info["public_jwk"] for info in keys.values()]}
    except Exception:
        raise HTTPException(status_code=500, detail="JWKS not available")

