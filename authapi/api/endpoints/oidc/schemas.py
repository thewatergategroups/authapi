from enum import Enum
from uuid import UUID
from pydantic import BaseModel


class ClientType(str, Enum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class GrantTypes(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    PASSWORD = "password"


class ClientAddBody(BaseModel):
    name: str
    type: ClientType
    description: str
    redirect_uris: list[str]
    grant_types: list[GrantTypes]
    scopes: list[str]


class ClientScopesBody(BaseModel):
    client_id: UUID
    scopes: list[str]


class ClientRedirectBody(BaseModel):
    client_id: UUID
    redirect_uris: list[str]


class ClientGrantBody(BaseModel):
    client_id: UUID
    grants: list[GrantTypes]
