"""Settings loaded from environment variables (optionally from a local, git-ignored .env)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Characters that would end or restructure a "KEY=value;" Db2 CLI connection string.
_CONN_STRING_FORBIDDEN = (";", "{", "}", "\0", "\n", "\r")
_DB_NAME_RE = re.compile(r"^[A-Z0-9@#$_]{1,8}$")
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[?[0-9A-Fa-f:.]+\]?)$")
_USER_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,128}$")


class ConfigError(ValueError):
    """Raised when configuration is missing or inconsistent."""


def load_dotenv(path: Path | None = None, environ: dict | None = None) -> None:
    """Load KEY=VALUE lines into the environment without overriding existing variables."""
    path = path or PROJECT_ROOT / ".env"
    environ = os.environ if environ is None else environ
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Db2Settings:
    host: str
    port: int
    database: str
    user: str
    password: str = field(repr=False)
    ssl: bool = False

    def validate(self) -> None:
        """Reject values that are missing or would change the meaning of the CLI connection string.

        Messages name the setting but never echo the password.
        """
        if not self.password:
            raise ConfigError("DB2_PASSWORD is not set. Put it in submissions/db2-intelligence-copilot/.env")
        if any(ch in self.password for ch in _CONN_STRING_FORBIDDEN):
            raise ConfigError(
                "DB2_PASSWORD contains a character that is not allowed in a Db2 connection string "
                "(';', '{', '}', NUL or a line break). The value is not shown."
            )
        if not _DB_NAME_RE.match(self.database):
            raise ConfigError(f"DB2_DATABASE must be a Db2 database name of 1-8 letters or digits, got {self.database!r}")
        if not _HOST_RE.match(self.host):
            raise ConfigError(f"DB2_HOST must be a host name or IP address, got {self.host!r}")
        if not _USER_RE.match(self.user):
            raise ConfigError(f"DB2_USER must be 1-128 letters, digits or _ . @ - characters, got {self.user!r}")
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"DB2_PORT must be between 1 and 65535, got {self.port}")

    def describe(self) -> str:
        """Safe one-line description of the target, for error messages. Never includes the password."""
        return f"database {self.database} at {self.host}:{self.port} as user {self.user}"

    def connection_string(self) -> str:
        self.validate()
        parts = [
            f"DATABASE={self.database}",
            f"HOSTNAME={self.host}",
            f"PORT={self.port}",
            "PROTOCOL=TCPIP",
            f"UID={self.user}",
            f"PWD={self.password}",
        ]
        if self.ssl:
            parts.append("SECURITY=SSL")
        return ";".join(parts) + ";"


@dataclass(frozen=True)
class EmbeddingSettings:
    provider: str
    model: str
    dimension: int
    base_url: str
    timeout_seconds: int


@dataclass(frozen=True)
class MigrationSettings:
    allowed_databases: tuple[str, ...]
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")


@dataclass(frozen=True)
class Settings:
    db2: Db2Settings
    embedding: EmbeddingSettings
    migration: MigrationSettings


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    if env is None:
        load_dotenv()
        env = os.environ
    db2 = Db2Settings(
        host=env.get("DB2_HOST", "localhost"),
        port=_int(env, "DB2_PORT", 50000),
        database=env.get("DB2_DATABASE", "TESTDB").upper(),
        user=env.get("DB2_USER", "db2inst1"),
        password=env.get("DB2_PASSWORD", ""),
        ssl=_bool(env.get("DB2_SECURITY")),
    )
    embedding = EmbeddingSettings(
        provider=env.get("EMBEDDING_PROVIDER", "ollama").strip().lower(),
        model=env.get("EMBEDDING_MODEL", "nomic-embed-text").strip(),
        dimension=_int(env, "EMBEDDING_DIM", 768),
        base_url=env.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
        timeout_seconds=_int(env, "EMBEDDING_TIMEOUT_SECONDS", 60),
    )
    allowed = tuple(
        name.strip().upper()
        for name in env.get("DB2INTEL_MIGRATION_DATABASES", "TESTDB").split(",")
        if name.strip()
    )
    hosts = tuple(
        name.strip().lower()
        for name in env.get("DB2INTEL_MIGRATION_HOSTS", "localhost,127.0.0.1,::1").split(",")
        if name.strip()
    )
    return Settings(
        db2=db2,
        embedding=embedding,
        migration=MigrationSettings(allowed_databases=allowed, allowed_hosts=hosts),
    )


# ---- API and LLM settings (Phase 2C) ---------------------------------------------------------
# Loaded separately from load_settings() so the migration runner and the guard CLI are not
# affected by API configuration. Nothing here is required for the database MVP.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
LLM_PROVIDERS = frozenset({"none", "ollama"})
PLANNED_LLM_PROVIDERS = frozenset({"openai", "watsonx"})


def _bounded(env: Mapping[str, str], key: str, default: int, low: int, high: int) -> int:
    value = _int(env, key, default)
    if not low <= value <= high:
        raise ConfigError(f"{key} must be between {low} and {high}, got {value}")
    return value


def _url_host(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ConfigError(f"invalid URL {url!r}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"URL must be http(s)://host[:port], got {url!r}")
    return parts.hostname.lower()


DEFAULT_WORKER_LOG = "logs/guard-worker.log"
WORKER_LOG_OFF = "off"


@dataclass(frozen=True)
class ApiSettings:
    host: str = "127.0.0.1"
    port: int = 8000
    token: str = field(default="", repr=False)  # bearer token; empty means no token check and no guard pool
    pool_size: int = 2
    check_deadline_seconds: int = 60
    startup_deadline_seconds: int = 60
    queue_wait_seconds: int = 2
    max_body_bytes: int = 65_536
    max_rows: int = 500  # mirrors APP_SETTING query.max_rows for offline lint and /ask
    worker_log: str = DEFAULT_WORKER_LOG  # guard worker stderr log (relative to the project root), or "off"

    def validate(self) -> None:
        if self.worker_log != WORKER_LOG_OFF and not self.worker_log.endswith(".log"):
            raise ConfigError(f"DB2INTEL_WORKER_LOG must end in .log (the repository ignores *.log) or be "
                              f"{WORKER_LOG_OFF!r}, got {self.worker_log!r}")
        if self.host.lower() not in LOOPBACK_HOSTS:
            raise ConfigError(f"DB2INTEL_API_HOST must be a loopback address ({', '.join(sorted(LOOPBACK_HOSTS))}), got {self.host!r}")
        if self.token and len(self.token) < 16:
            raise ConfigError("DB2INTEL_API_TOKEN must be at least 16 characters when set (the value is not shown)")
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"APP_PORT must be between 1 and 65535, got {self.port}")


@dataclass(frozen=True)
class LlmSettings:
    provider: str = "none"
    model: str = "qwen2.5-coder:7b"
    base_url: str = "http://localhost:11434"
    timeout_seconds: int = 120
    allow_remote: bool = False

    def validate(self) -> None:
        if self.provider in PLANNED_LLM_PROVIDERS:
            raise ConfigError(
                f"LLM_PROVIDER={self.provider} is planned but not implemented. Use 'ollama' (local, no API key) or 'none'."
            )
        if self.provider not in LLM_PROVIDERS:
            raise ConfigError(f"unknown LLM_PROVIDER={self.provider!r}; expected one of {', '.join(sorted(LLM_PROVIDERS))}")
        if self.provider == "ollama":
            host = _url_host(self.base_url)
            if host not in LOOPBACK_HOSTS and not self.allow_remote:
                raise ConfigError(
                    f"LLM base URL host {host!r} is not local; schema descriptions would leave this machine. "
                    "Set DB2INTEL_LLM_ALLOW_REMOTE=true only if that is intended."
                )


def load_api_settings(env: Mapping[str, str] | None = None) -> tuple[ApiSettings, LlmSettings]:
    if env is None:
        load_dotenv()
        env = os.environ
    api = ApiSettings(
        host=env.get("DB2INTEL_API_HOST", "127.0.0.1").strip(),
        port=_int(env, "APP_PORT", 8000),
        token=env.get("DB2INTEL_API_TOKEN", "").strip(),
        pool_size=_bounded(env, "DB2INTEL_GUARD_WORKERS", 2, 1, 4),
        check_deadline_seconds=_bounded(env, "DB2INTEL_CHECK_DEADLINE_SECONDS", 60, 5, 300),
        startup_deadline_seconds=_bounded(env, "DB2INTEL_WORKER_STARTUP_SECONDS", 60, 5, 300),
        queue_wait_seconds=_bounded(env, "DB2INTEL_QUEUE_WAIT_SECONDS", 2, 0, 30),
        max_body_bytes=_bounded(env, "DB2INTEL_MAX_BODY_BYTES", 65_536, 1_024, 1_048_576),
        max_rows=_bounded(env, "DB2INTEL_API_MAX_ROWS", 500, 1, 100_000),
        worker_log=env.get("DB2INTEL_WORKER_LOG", "").strip() or DEFAULT_WORKER_LOG,
    )
    llm = LlmSettings(
        provider=(env.get("LLM_PROVIDER", "") or "none").strip().lower(),
        model=(env.get("LLM_MODEL", "") or "qwen2.5-coder:7b").strip(),
        base_url=(env.get("LLM_BASE_URL", "") or env.get("OLLAMA_BASE_URL", "") or "http://localhost:11434").strip().rstrip("/"),
        timeout_seconds=_bounded(env, "LLM_TIMEOUT_SECONDS", 120, 1, 600),
        allow_remote=_bool(env.get("DB2INTEL_LLM_ALLOW_REMOTE")),
    )
    api.validate()
    return api, llm
