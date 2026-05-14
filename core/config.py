import os


class SecurityConfig:
    IAM_BASE_URL = os.getenv("IAM_BASE_URL", "http://omnibioai-auth:8000")
    POLICY_BASE_URL = os.getenv("POLICY_BASE_URL", "http://policy-engine:8001")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

    SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
    SERVICE_SECRET = os.getenv("SERVICE_SECRET", "dev-secret")