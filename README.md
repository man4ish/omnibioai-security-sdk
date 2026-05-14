# OmniBioAI Security SDK

A unified zero-trust security SDK for the OmniBioAI ecosystem.

It provides:

- IAM token validation (with Redis caching)
- Service-to-Service authentication (S2S)
- Policy evaluation integration
- Audit event streaming
- FastAPI middleware stack

---

## Architecture
Request → Auth Middleware → IAM → Policy Engine → Service → Audit Stream


---

## Features

### 🔐 IAM Client
- JWT validation
- Redis caching for sub-ms auth

### 🧠 Policy Enforcement
- RBAC / ABAC integration
- Request-level authorization

### 🔄 Service-to-Service Auth
- Signed service tokens
- Audience-based access control

### 📡 Audit Integration
- Redis Streams logging
- full traceability

---

## Installation

```bash
pip install omnibioai-security-sdk
```

## Usage
FastAPI Setup

from fastapi import FastAPI
from omnibioai_security_sdk.core.config import SecurityConfig
from omnibioai_security_sdk.iam.client import IAMClient
from omnibioai_security_sdk.policy.client import PolicyClient
from omnibioai_security_sdk.middleware.auth import AuthMiddleware
from omnibioai_security_sdk.middleware.policy import PolicyMiddleware

app = FastAPI()

iam = IAMClient(SecurityConfig.IAM_BASE_URL, SecurityConfig.REDIS_URL)
policy = PolicyClient(SecurityConfig.POLICY_BASE_URL)

app.add_middleware(AuthMiddleware, iam=iam)
app.add_middleware(PolicyMiddleware, policy=policy)

Zero Trust Guarantee

Every request is:

Authenticated
Authorized
Audited
Traceable
Designed For
HPC workflows
Distributed bioinformatics pipelines
AI/ML compute orchestration

---

# 🧬 What you now have

This SDK is now:

✔ IAM abstraction  
✔ policy enforcement layer  
✔ S2S authentication  
✔ audit integration  
✔ reusable across all services  

---

# 🚀 Next step (important)

If you want to complete the system properly, next missing piece is:

## 🔥 API Gateway (central enforcement point)

That will:
- remove middleware duplication entirely
- enforce security at network edge
- act like AWS API Gateway + IAM combined