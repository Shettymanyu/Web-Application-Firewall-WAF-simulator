import secrets


class Config:
    SECRET_KEY = secrets.token_hex(32)
    RATE_LIMIT_WINDOW_SECONDS = 60
    RATE_LIMIT_MAX_REQUESTS = 30
    WAF_MODE = "block"   # "block" or "detect"
    LOG_MAX_ENTRIES = 500
    TARGET_APP_PREFIX = "/target"
    DASHBOARD_PREFIX = "/dashboard"
