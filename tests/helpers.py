"""
Reusable functions for testing
"""

import requests

from authapi.api.endpoints.oidc.schemas import ClientAddBody, ClientType, GrantTypes
from authapi.api.endpoints.public.schemas import UserLoginBody
from authapi.schemas import Alg


def get_token(url: str, email: str, scopes: list[str]):
    """Get a User token"""
    response = requests.post(
        f"{url}/login",
        data=UserLoginBody(
            email=email,
            password="password",
            scope=" ".join(scopes),
            alg=Alg.EC,
        ).model_dump(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
        allow_redirects=False,
    )
    return response.cookies.get("token")


def create_client(
    url: str,
    token_email: str,
    token_scopes: list[str],
    client_name: str,
    client_roles: list[str],
    redirect_uris: list[str],
    grant_types: list[GrantTypes],
    client_type: ClientType = ClientType.CONFIDENTIAL,
):
    """Create a Client Application"""
    token = get_token(url, token_email, token_scopes)

    response = requests.post(
        f"{url}/clients/add",
        json=ClientAddBody(
            name=client_name,
            description="a test client",
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            roles=client_roles,
            type=client_type,
        ).model_dump(),
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    return response.json()
