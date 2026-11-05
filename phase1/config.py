from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state_dir: Path = Path(".state")
    auth_mode: Literal["oauth", "local-test"] = "oauth"
    exposure: Literal["private", "public-https"] = "private"
    bind: str = "127.0.0.1"
    port: int = 8765
    public_url: str | None = None
    issuer: str | None = None
    resource: str | None = None
    subject: str | None = None
    introspection_url: str | None = None
    client_id: str | None = None
    client_secret_file: Path | None = None

    @model_validator(mode="after")
    def safe(self):
        if self.bind not in ("127.0.0.1", "::1") and self.exposure != "public-https":
            raise ValueError(
                "non-loopback bind requires explicit public-https exposure"
            )
        if self.auth_mode == "local-test" and (
            self.exposure != "private" or self.bind not in ("127.0.0.1", "::1")
        ):
            raise ValueError("local-test authentication is loopback only")
        if self.exposure == "public-https" and not (
            self.public_url and self.public_url.startswith("https://")
        ):
            raise ValueError("public-https exposure requires public_url")
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid port")
        return self
