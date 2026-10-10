from __future__ import annotations

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProbeConfig(BaseModel):
    dns_timeout: float = 5.0
    tcp_timeout: float = 5.0
    tls_timeout: float = 10.0
    http_timeout: float = 15.0
    max_probes: int = 20
    per_host_rate_limit: int = 3
    allow_replay: bool = False
    probe_auth: bool = False


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LAYERS_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    safety_mode: bool = True
    max_body_sample: int = 2048
    inconclusive_threshold: float = 0.35
    low_threshold: float = 0.45
    high_threshold: float = 0.75


settings = Config()
