# 🔐 Zero Trust API Gateway with Blockchain Validation

A production-ready API Gateway demonstrating **Zero Trust**: device and user auth, short-lived JWTs, revocation, HMAC service-to-service signing, rate limiting, and an on-chain allowlist validated against a local Ethereum test chain.

---

## 🧠 Overview

Enforced controls:

- 🔐 **JWT-based access control** with short TTLs
- 🧾 **Nonce + ECDSA login** (EIP-191 `personal_sign`)
- 🔁 **Revocation** via Redis (per-token JTI TTL)
- 🧱 **HMAC** signatures from gateway to backend
- 🚦 **Per-subject rate limiting**
- ⛓️ **On-chain allowlist** (Solidity contract on Ganache)

---

## 📦 Stack

- FastAPI, Uvicorn
- Web3.py, PyJWT, Redis
- Solidity (Allowlist), Ganache, Python deployer
- Docker Compose

---

## ⚙️ Setup

Export required secrets:

```bash
export JWT_SECRET='replace-with-strong-secret'
export SHARED_BACKEND_KEY='replace-with-strong-key'
# Optional CSV of addresses allowed; if empty, any address is allowed
export ALLOWLIST_ADDRESSES=
```

Bring up services:

```bash
docker compose up --build
```

---

## 🔑 Auth Flow

1) Request nonce:
```bash
curl -X POST 'http://localhost:8080/auth/nonce' -d 'address=0xYourAddress'
```
2) Sign `nonce` with your wallet (personal_sign), send to login:
```bash
curl -X POST 'http://localhost:8080/auth/login' \
  -d 'address=0xYourAddress' \
  -d 'signature=0xSignature'
```
3) Use JWT to access backend via gateway:
```bash
TOKEN=... # from login
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/proxy/data'
```
4) Logout (revokes token by JTI for remainder of TTL):
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/auth/logout'
```

---

## 🧪 Smoke Test

```bash
make up  # or docker compose up --build
make smoke
```

---

## 📁 Services

- `api-gateway`: Auth, JWT issuance, revocation, rate limiting, proxy
- `backend`: Validates HMAC from gateway and returns data
- `ganache`: Local Ethereum test chain
- `deployer`: Compiles and deploys `Allowlist` and publishes ABI+address to a shared volume

---

## 📜 Contract

The `Allowlist` contract exposes `isAllowed(address)` and can be updated by owner via `setAllowed(address,bool)`.
