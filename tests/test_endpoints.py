import json
import requests

from yumi import Scopes
from .conftest import server
from authapi.api.endpoints.oidc.schemas import GrantTypes, ResponseTypes
from base64 import b64decode
from .helpers import get_token, create_client


def test_get_token(server):
    username = "admin"
    scopes = ["admin", "read", "write"]
    token = get_token(server, username, scopes)
    fields = token.split(".")
    assert len(fields) == 3
    token_info = json.loads(b64decode(fields[1] + "==").decode())
    assert token_info["sub"] == username
    assert token_info["aud"] == "local"
    assert token_info["iss"] == "authapi"
    assert token_info["scopes"] == scopes


def make_test_client(server):
    name = "client1"
    scopes = [Scopes.READ.value, Scopes.WRITE.value, Scopes.OPENID.value]
    grant_types = [GrantTypes.AUTHORIZATION_CODE, GrantTypes.IMPLICIT]
    redirect_uris = [server]

    return create_client(
        server, "admin", ["admin"], name, scopes, redirect_uris, grant_types
    )


def test_get_client_token(server):
    scopes = [Scopes.READ.value, Scopes.WRITE.value, Scopes.OPENID.value]
    data = make_test_client(server)
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    assert client_id is not None
    assert client_secret is not None
    assert data.get("scopes") == scopes
    assert data.get("type") == "confidential"
    resp = requests.post(
        f"{server}/public/oidc/token",
        json={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GrantTypes.IMPLICIT.value,
            "redirect_uri": server,
            "scopes": ["read"],
        },
        timeout=1,
    )
    data = resp.json()
    assert data.get("token") is not None
    assert data.get("scopes") == ["read"]


def test_authorization_token_flow(server):
    data = make_test_client(server)
    token = get_token(server, "admin", ["admin"])

    client_id = data.get("client_id")
    resp = requests.get(
        f"{server}/public/oidc/authorize",
        params={
            "response_type": ResponseTypes.TOKEN,
            "client_id": client_id,
            "redirect_uri": server,
            "scopes": ["read"],
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    data = resp.json()
    assert data.get("token") is not None
    assert data.get("scopes") == ["read"]


def test_authorization_id_token_flow(server):
    data = make_test_client(server)
    token = get_token(server, "admin", ["admin"])

    client_id = data.get("client_id")
    resp = requests.get(
        f"{server}/public/oidc/authorize",
        params={
            "response_type": ResponseTypes.ID_TOKEN,
            "client_id": client_id,
            "redirect_uri": server,
            "scopes": ["read", "openid"],
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    data = resp.json()
    assert data.get("id_token") is not None


def test_authorization_code_flow_openid(server):
    data = make_test_client(server)
    token = get_token(server, "admin", ["admin"])

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    resp = requests.get(
        f"{server}/public/oidc/authorize",
        params={
            "response_type": ResponseTypes.CODE,
            "client_id": client_id,
            "redirect_uri": server,
            "scopes": ["read", "openid"],
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    data = resp.json()
    code = data.get("code")

    resp = requests.post(
        f"{server}/public/oidc/token",
        json={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GrantTypes.AUTHORIZATION_CODE.value,
            "redirect_uri": server,
            "scopes": ["read", "openid"],
        },
        timeout=1,
    )
    data = resp.json()
    assert data.get("id_token") is not None
    assert data.get("token") is not None
    assert data.get("scopes") == ["openid", "read"]


def test_authorization_code_flow_no_openid(server):
    data = make_test_client(server)
    token = get_token(server, "admin", ["admin"])

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    resp = requests.get(
        f"{server}/public/oidc/authorize",
        params={
            "response_type": ResponseTypes.CODE,
            "client_id": client_id,
            "redirect_uri": server,
            "scopes": ["read"],
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
    )
    data = resp.json()
    code = data.get("code")

    resp = requests.post(
        f"{server}/public/oidc/token",
        json={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GrantTypes.AUTHORIZATION_CODE.value,
            "redirect_uri": server,
            "scopes": ["read"],
        },
        timeout=1,
    )
    data = resp.json()
    assert data.get("id_token") is None
    assert data.get("token") is not None
    assert data.get("scopes") == ["read"]
