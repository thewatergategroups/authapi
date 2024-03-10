from enum import Enum
from uuid import UUID
from pydantic import BaseModel
from ....schemas import Alg


AUTHORIZATION_CODES = {}


class ClientType(str, Enum):
    CONFIDENTIAL = "confidential"
    # PUBLIC = "public"


class GrantTypes(str, Enum):
    AUTHORIZATION_CODE = (
        "authorization_code"  # exchange authorization code for access token
    )
    IMPLICIT = "implicit"  # returns access token directly
    # REFRESH_TOKEN = "refresh_token"
    # PASSWORD = "password"  # exchanging user's username and password for token


class ClientAddBody(BaseModel):
    name: str
    type: ClientType
    description: str
    redirect_uris: list[str]
    grant_types: list[GrantTypes]
    scopes: list[str]


class OidcTokenBody(BaseModel):
    client_id: UUID
    client_secret: str
    grant_type: GrantTypes
    code: str | None = None
    redirect_uri: str
    alg: Alg = Alg.EC
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


class ResponseTypes(str, Enum):
    TOKEN = "token"  # Used in implicit flow
    CODE = "code"  # used in authorization code flow
    ID_TOKEN = "id_token"  ### for oidc

    ID_T_T = "id_token token"
    C_ID_T = "code id_token"
    C_T = "code token"
    C_ID_T_T = "code id_token token"

    @classmethod
    def get_all(cls):
        return [item.value for item in cls]
