from enum import Enum
from pydantic import BaseModel
from ..schemas import Alg


class UserScopesData(BaseModel):
    username: str
    scope: str


class AuthUpdate(BaseModel):
    username: str
    password: str


class AuthData(BaseModel):
    username: str
    password: str
    alg: Alg = Alg.EC
    scopes: list[str]


class ClientType(Enum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class GrantTypes(Enum):
    AUTH_CODE = "authorization_code"
    IMPLICIT = "implicit"
    CLIENT_CREDENTIALS = "client_credentials"
    RESOURCE_OWNER_PASSWORD_CREDENTIALS = "resource_owner_password_credentials"
    REFRESH_TOKEN = "refresh_token"


class ClientData(BaseModel):
    name: str
    description: str
    type: ClientType
    redirect_uris: list[str]
    grant_types: list[GrantTypes]
    scopes: list[str]


class ScopeData(BaseModel):
    scope: str


class Token(BaseModel):
    token: str
