"""
Open ID Connect and oAuth Schemas
"""

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel

from ....schemas import Alg

AUTHORIZATION_CODES = {}


class ClientType(StrEnum):
    """Allowed Client types"""

    CONFIDENTIAL = "confidential"

    # PUBLIC = "public"
    @classmethod
    def get_all(cls):
        """Return all enum member values"""
        return [item.value for item in cls]


class GrantTypes(StrEnum):
    """
    Allowed Grant Types
    1. AUTHORIZATION_CODE: exchange authorization code for access token
    2. IMPLICIT: returns a token directly
    3. PASSWORD: exhange a users username and password for a token
    4. REFRESH_TOKEN: returns a refresh token to create future tokens
    """

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    # REFRESH_TOKEN = "refresh_token"
    # PASSWORD = "password"


class ClientAddBody(BaseModel):
    """Add Client endpoint body"""

    name: str
    type: ClientType
    description: str
    redirect_uris: list[str]
    grant_types: list[GrantTypes]
    scopes: list[str]


class OidcTokenBody(BaseModel):
    """Generate client token body"""

    client_id: UUID
    client_secret: str
    grant_type: GrantTypes
    code: str | None = None
    redirect_uri: str
    alg: Alg = Alg.EC
    scopes: list[str]


class ClientScopesBody(BaseModel):
    """Add client scopes body"""

    client_id: UUID
    scopes: list[str]


class ClientRedirectBody(BaseModel):
    """Add client redirect body"""

    client_id: UUID
    redirect_uris: list[str]


class ClientGrantBody(BaseModel):
    """Add client grant body"""

    client_id: UUID
    grants: list[GrantTypes]


class ResponseTypes(StrEnum):
    """
    Possible response types from the authorization server
    1. TOKEN:  used with IMPLICIT grant type to return a token directly
    2. CODE: returns a authorization code to get a token from the token endpoint
    3. ID_TOKEN: returns a token used to identify the authorized party NOT for authentication.
    Used in OIDC flow
    """

    TOKEN = "token"
    CODE = "code"
    ID_TOKEN = "id_token"

    # ID_T_T = "id_token token"
    # C_ID_T = "code id_token"
    # C_T = "code token"
    # C_ID_T_T = "code id_token token"

    @classmethod
    def get_all(cls):
        """Return all enum member values"""
        return [item.value for item in cls]
