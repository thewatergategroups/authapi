"""
Reusable functions for testing
"""

import requests

from authapi.api.endpoints.oidc.schemas import ClientAddBody, ClientType, GrantTypes
from authapi.api.endpoints.public.schemas import UserLoginBody
from authapi.schemas import Alg


def get_token(url: str, username: str, scopes: list[str]):
    """Get a User token"""
    response = requests.post(
        f"{url}/login",
        json=UserLoginBody(
            username=username,
            password="password",
            scopes=scopes,
            alg=Alg.EC,
        ).model_dump(),
        timeout=1,
    )
    data = response.json()
    return data.get("token", "")


def create_client(
    url: str,
    token_username: str,
    token_scopes: list[str],
    client_name: str,
    client_scopes: list[str],
    redirect_uris: list[str],
    grant_types: list[GrantTypes],
    client_type: ClientType = ClientType.CONFIDENTIAL,
):
    """Create a Client Application"""
    token = get_token(url, token_username, token_scopes)

    response = requests.post(
        f"{url}/clients/create",
        json=ClientAddBody(
            name=client_name,
            description="a test client",
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            scopes=client_scopes,
            type=client_type,
        ).model_dump(),
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    return response.json()
