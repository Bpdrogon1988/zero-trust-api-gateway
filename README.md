# 🔐 Zero Trust API Gateway

A secure, containerized API Gateway implementing **Zero Trust principles** using JWT authentication, Redis token management, and FastAPI—all wrapped in a production-ready Docker environment.

> Built by [@bpdrogon88](https://github.com/bpdrogon88) as part of a hands-on cloud security portfolio.

---

## 🧠 Overview

This gateway acts as a secure intermediary between clients and internal microservices or APIs, enforcing:

- 🔐 **JWT-based access control**
- 🔁 **Session revocation** via Redis
- 🧱 **Dockerized deployment**
- ⚙️ **Stateless validation** with HMAC-SHA256
- 🧿 **Zero Trust posture** (verify every request)

---

## 🧪 Architecture

