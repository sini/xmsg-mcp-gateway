from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

EVENT = "xmsg.message.received.v1"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Empty(Strict):
    pass


class RequestParams(Strict):
    metadata: dict[str, JsonValue] = Field(default_factory=dict, alias="_meta")

    @field_validator("metadata")
    @classmethod
    def progress_token(cls, value):
        if "progressToken" in value and type(value["progressToken"]) not in (str, int):
            raise ValueError("progressToken must be a string or integer")
        return value


class ClientInfo(Strict):
    name: str
    version: str
    title: str | None = None


class Initialize(RequestParams):
    protocolVersion: str
    capabilities: dict
    clientInfo: ClientInfo


class Call(RequestParams):
    name: Literal["xmsg_identity"]
    arguments: Empty = Field(default_factory=Empty)


class Delivery(Strict):
    mode: Literal["webhook"]
    url: str = Field(max_length=4096)


class SignedDelivery(Delivery):
    secret: str = Field(max_length=128)


class Subscribe(RequestParams):
    name: Literal["xmsg.message.received.v1"]
    arguments: Empty
    delivery: SignedDelivery
    cursor: None = None
    ttlMs: int | None = Field(default=None, ge=1000, le=604800000)


class Unsubscribe(RequestParams):
    name: Literal["xmsg.message.received.v1"]
    arguments: Empty
    delivery: Delivery


class ListEvents(RequestParams):
    cursor: None = None


class RPC(Strict):
    jsonrpc: Literal["2.0"]
    id: int | str | None = None
    method: str
    params: dict = Field(default_factory=dict)


PAYLOAD = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "message_id",
        "mailbox",
        "origin",
        "in_reply_to",
        "preview",
        "body_available",
        "sequence",
    ],
    "properties": {
        "message_id": {"type": "string"},
        "mailbox": {"type": "string", "const": "dot@phase1-synthetic"},
        "origin": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "node"],
            "properties": {"id": {"type": "string"}, "node": {"type": "string"}},
        },
        "in_reply_to": {"type": ["string", "null"]},
        "preview": {"type": "string", "maxLength": 256},
        "body_available": {"type": "boolean"},
        "sequence": {"type": "integer", "minimum": 1},
    },
}
