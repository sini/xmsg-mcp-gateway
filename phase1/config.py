from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state_dir: Path = Path(".state")
    service_id: str = Field(
        default="xmsg", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"
    )
    approved_hosted_oauth_client_id: str | None = Field(default=None, min_length=1)
    introspection_auth_method: Literal["client_secret_basic", "none"] = (
        "client_secret_basic"
    )
    auth_mode: Literal["oauth", "local-test"] = "oauth"
    exposure: Literal["private", "public-https"] = "private"
    bind: str = "127.0.0.1"
    port: int = 8765
    public_url: str | None = None
    issuer: str | None = None
    resource: str | None = None
    subject: str | None = None
    introspection_url: str | None = None
    client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("introspection_client_id", "client_id"),
    )
    client_secret_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "introspection_client_secret_file", "client_secret_file"
        ),
    )

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
