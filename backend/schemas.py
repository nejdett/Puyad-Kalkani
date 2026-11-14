from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

_Str32 = Annotated[str, Field(max_length=32)]
_Str64 = Annotated[str, Field(max_length=64)]
_Str256 = Annotated[str, Field(max_length=256)]
_Text = Annotated[str, Field(max_length=2000)]
_Command = Annotated[str, Field(max_length=4096)]


class RuleModel(BaseModel):
    id: _Str64
    name: _Str256
    category: _Str64
    severity: _Str32
    check_command: _Command
    fix_command: _Command
    description: _Text


class SnapshotCreateModel(BaseModel):
    label: _Str256 | None = ""


class FixModel(BaseModel):
    auto_snapshot: bool | None = True
    server_id: int | None = 1


class SchedulerConfigModel(BaseModel):
    enabled: bool
    interval: _Str32 | None = "weekly"
    day_of_week: _Str32 | None = "mon"
    hour: int | None = 3
    minute: int | None = 0


class LoginModel(BaseModel):
    username: _Str64
    password: _Str256


class ChangePasswordModel(BaseModel):
    username: _Str64
    old_password: _Str256
    new_password: _Str256


class HoneypotModel(BaseModel):
    port: int
    service: _Str32 | None = "custom"
    label: _Str256 | None = ""


class ServerModel(BaseModel):
    name: _Str256
    ip_address: _Str256
    port: int | None = 8000
    token: _Str256 | None = ""


class ServerUpdateModel(BaseModel):
    name: _Str256 | None = None
    port: int | None = None
    token: _Str256 | None = None
    clear_token: bool = False


class ConfigUpdateModel(BaseModel):
    RUN_MODE: _Str32 | None = None
    AGENT_SHARED_SECRET: _Str256 | None = None
    TELEGRAM_ENABLED: bool | None = None
    TELEGRAM_BOT_TOKEN: _Str256 | None = None
    TELEGRAM_CHAT_ID: _Str64 | None = None
    TELEGRAM_ALLOWED_USER_ID: _Str64 | None = None
    HONEYPOT_BLOCK_HOURS: int | None = Field(None, ge=1, le=8760)
    HONEYPOT_WHITELIST: _Text | None = None
    HONEYPOT_AUTOBLOCK_ENABLED: bool | None = None
    HONEYPOT_AUTOBLOCK_COUNT: int | None = Field(None, ge=2, le=1000)
    HONEYPOT_AUTOBLOCK_MINUTES: int | None = Field(None, ge=1, le=1440)


class ScanModel(BaseModel):
    server_id: int | None = 1


class ScanPostModel(BaseModel):
    server_id: int | None = 1


class JobStartModel(BaseModel):
    kind: Literal["scan", "cve"]
    server_id: int = Field(1, ge=1, le=100000)
    force: bool = False


class ForensicTriggerModel(BaseModel):
    server_id: int | None = 1
    trigger_reason: _Str256 | None = "Manual Trigger"


class TelegramTestModel(BaseModel):
    bot_token: _Str256 | None = None
    chat_id: _Str64 | None = None


class TelegramConfigModel(BaseModel):
    TELEGRAM_ENABLED: bool | None = None
    TELEGRAM_BOT_TOKEN: _Str256 | None = None
    TELEGRAM_CHAT_ID: _Str64 | None = None
    TELEGRAM_ALLOWED_USER_ID: _Str64 | None = None


class RateLimitUpdateModel(BaseModel):
    RATE_LIMIT_ENABLED: bool | None = None
    RATE_LIMIT_AUTH_MAX: int | None = None
    RATE_LIMIT_AUTH_WINDOW: int | None = None
    RATE_LIMIT_AUTH_BLOCK: int | None = None
    RATE_LIMIT_API_MAX: int | None = None
    RATE_LIMIT_API_WINDOW: int | None = None
    RATE_LIMIT_API_BLOCK: int | None = None
    RATE_LIMIT_HEAVY_MAX: int | None = None
    RATE_LIMIT_HEAVY_WINDOW: int | None = None
    RATE_LIMIT_HEAVY_BLOCK: int | None = None
    RATE_LIMIT_EXPORT_MAX: int | None = None
    RATE_LIMIT_EXPORT_WINDOW: int | None = None
    RATE_LIMIT_EXPORT_BLOCK: int | None = None
    RATE_LIMIT_TELEGRAM_MAX: int | None = None
    RATE_LIMIT_TELEGRAM_WINDOW: int | None = None
    RATE_LIMIT_TELEGRAM_BLOCK: int | None = None


class CveFixModel(BaseModel):
    package: _Str256
    server_id: int | None = 1


class CveBatchFixModel(BaseModel):
    packages: Annotated[list[_Str256], Field(max_length=500)]
    server_id: int | None = 1


class AgentHeartbeatModel(BaseModel):
    ip_address: _Str64 | None = None
    port: int | None = 8000
    hostname: _Str256 | None = None
    agent_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")] | None = None
    status: _Str32 | None = "online"
    score: int | None = None
    active_connections: int | None = None
    cert_pem: Annotated[str, Field(max_length=8192)] | None = None


class CertApproveModel(BaseModel):
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

