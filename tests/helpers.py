"""
Reusable functions for testing
"""

import requests

from authapi.api.endpoints.clients.schemas import ClientAddBody, ClientType, GrantTypes
from authapi.api.endpoints.public.users.schemas import UserLoginBody
from authapi.schemas import Alg

ADMIN_EMAIL = "admin@email.com"


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
    return response.json().get("id_token"), response.json().get("session_id")


def delete_scope_from_role(
    url: str, token_email: str, token_scopes: list[str], role_id: str, scope_id: str
):
    """delete scope from role"""
    _, session_id = get_token(url, token_email, token_scopes)
    response = requests.delete(
        f"{url}/roles/role/scopes",
        params=dict(role_id=role_id, scope_id=scope_id),
        cookies={"session_id": session_id},
        timeout=1,
    )
    print(response.json())
    response.raise_for_status()


def add_scope_to_role(
    url: str,
    token_email: str,
    token_scopes: list[str],
    role_id: str,
    scope_id: str,
):
    """add scope to role"""
    _, session_id = get_token(url, token_email, token_scopes)
    response = requests.post(
        f"{url}/roles/role/scopes",
        json=dict(role_id=role_id, scope_id=scope_id),
        cookies={"session_id": session_id},
        timeout=1,
    )
    response.raise_for_status()


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
    _, session_id = get_token(url, token_email, token_scopes)

    response = requests.post(
        f"{url}/clients/client",
        json=ClientAddBody(
            name=client_name,
            description="a test client",
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            roles=client_roles,
            type=client_type,
        ).model_dump(),
        cookies=dict(session_id=session_id),
        timeout=1,
    )
    return response.json()


def make_test_client(url: str):
    """create a predefined test client"""
    name = "client1"

    grant_types = [GrantTypes.AUTHORIZATION_CODE, GrantTypes.IMPLICIT]
    redirect_uris = [url]

    return create_client(
        url,
        ADMIN_EMAIL,
        ["admin"],
        name,
        ["admin"],
        redirect_uris,
        grant_types,
    )
