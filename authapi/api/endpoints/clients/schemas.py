"""
Open ID Connect and oAuth Schemas
"""

from enum import StrEnum
from uuid import UUID

from fastapi import Form
from pydantic import BaseModel

from ....schemas import Alg


class ClientType(StrEnum):
    """Allowed Client types"""

    CONFIDENTIAL = "confidential"

    # PUBLIC = "public"
    @classmethod
    def get_all(cls):
        """Return all enum member values"""
        return [item.value for item in cls]


class RefreshTokenStatus(StrEnum):
    """Status of a refresh token"""

    ACTIVE = "active"
    DISABLED = "disabled"


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
    REFRESH_TOKEN = "refresh_token"
    # PASSWORD = "password"


class ClientAddBody(BaseModel):
    """Add Client endpoint body"""

    name: str
    type: ClientType
    description: str
    redirect_uris: list[str]
    grant_types: list[GrantTypes]
    roles: list[str]


class ClientPatchBody(BaseModel):
    """Add Client endpoint body"""

    id_: UUID
    name: str | None = None
    type: ClientType | None = None
    description: str | None = None
    redirect_uris: list[str] | None = None
    grant_types: list[GrantTypes] | None = None
    roles: list[str] | None = None


class OidcTokenBody(BaseModel):
    """Generate client token body"""

    client_id: UUID | None = None
    client_secret: str | None = None
    grant_type: GrantTypes
    code: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None
    redirect_uri: str
    alg: Alg = Alg.EC
    scope: str | None

    @classmethod
    def as_form(
        cls,
        client_id: UUID = Form(None),
        client_secret: str = Form(None),
        grant_type: GrantTypes = Form(...),
        code: str = Form(None),
        code_verifier: str = Form(None),
        redirect_uri: str = Form(...),
        alg: Alg = Form(Alg.EC),
        scope: str = Form(None),
        refresh_token: str = Form(None),
    ):
        """Allows use of this model as form data in an endpoint"""
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            grant_type=grant_type,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            alg=alg,
            scope=scope,
            refresh_token=refresh_token,
        )


class ClientScopesBody(BaseModel):
    """Add client scopes body"""

    client_id: UUID
    roles: list[str]


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


class CodeChallengeMethods(StrEnum):
    """
    Used for Authorization code flow to ensure authorization code is legit
    """

    PLAIN = "plain"  # send the hash in plain text
    S256 = "S256"  # hash the code challenge

    @classmethod
    def get_all(cls):
        """Return all enum member values"""
        return [item.value for item in cls]
