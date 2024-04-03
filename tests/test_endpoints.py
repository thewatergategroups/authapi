"""
Endpoint tests
"""

import base64
import hashlib
import json
import secrets
from base64 import b64decode
from urllib.parse import parse_qs, urlparse

import requests

from authapi.api.endpoints.oidc.schemas import (
    CodeChallengeMethods,
    GrantTypes,
    ResponseTypes,
)
from authapi.settings import get_settings

from .conftest import server  # pylint: disable=unused-import
from .helpers import create_client, get_token

ADMIN_EMAIL = "admin@email.com"


def test_get_token(server):  # pylint: disable=redefined-outer-name
    """
    test getting a user token
    TODO: Add a test trying to get scopes you shouldn't have
    """
    scopes = ["admin", "read", "write"]
    token = get_token(server, ADMIN_EMAIL, scopes)
    fields = token.split(".")
    assert len(fields) == 3
    token_info = json.loads(b64decode(fields[1] + "==").decode())
    assert token_info["sub"] == ADMIN_EMAIL
    assert token_info["aud"] == "local"
    assert token_info["iss"] == get_settings().jwt_config.jwks_server_url
    assert token_info["scopes"] == ["admin", "read", "write"]


def make_test_client(server):  # pylint: disable=redefined-outer-name
    """create a predefined test client"""
    name = "client1"

    grant_types = [GrantTypes.AUTHORIZATION_CODE, GrantTypes.IMPLICIT]
    redirect_uris = [server]

    return create_client(
        server,
        ADMIN_EMAIL,
        ["admin"],
        name,
        ["admin"],
        redirect_uris,
        grant_types,
    )


def test_get_client_token(server):  # pylint: disable=redefined-outer-name
    """test getting a client token"""
    data = make_test_client(server)
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    assert client_id is not None
    assert client_secret is not None
    assert data.get("roles") == ["admin"]
    assert data.get("type") == "confidential"
    resp = requests.post(
        f"{server}/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GrantTypes.IMPLICIT.value,
            "redirect_uri": server,
            "scope": "read",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    data = resp.json()
    assert data.get("access_token") is not None
    assert data.get("scopes") == ["read"]


def test_authorization_token_flow(
    server,
):  # pylint: disable=redefined-outer-name
    """
    test authorization token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a token using user credentials
    4. client token returned
    """
    data = make_test_client(server)
    token = get_token(server, ADMIN_EMAIL, ["admin"])
    client_id = data.get("client_id")
    resp = requests.get(
        f"{server}/oauth2/authorize",
        params={
            "response_type": ResponseTypes.TOKEN,
            "client_id": client_id,
            "redirect_uri": server,
            "scope": "read",
            "state": "extradata",
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
        allow_redirects=False,
    )
    data = resp.headers["Location"]
    assert "access_token=" in data
    assert "token_type=Bearer" in data
    assert "state=extradata" in data
    assert server in data


def test_authorization_id_token_flow(server):  # pylint: disable=redefined-outer-name
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a id token using user credentials
    4. id token with information about user returned
    """
    data = make_test_client(server)
    token = get_token(server, ADMIN_EMAIL, ["admin"])

    client_id = data.get("client_id")
    resp = requests.get(
        f"{server}/oauth2/authorize",
        params={
            "response_type": ResponseTypes.ID_TOKEN,
            "client_id": client_id,
            "redirect_uri": server,
            "scope": "read openid",
            "state": "extradata",
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
        allow_redirects=False,
    )
    print(resp.text)
    data = resp.headers["Location"]
    assert "id_token=" in data
    assert "state=extradata" in data
    assert server in data


def test_authorization_code_flow_openid_plain_code_chal_method(
    server,
):  # pylint: disable=redefined-outer-name
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code with the openid scope
    4. send token request with authorization code and openid scope to get client token and id token
    """
    data = make_test_client(server)
    token = get_token(server, ADMIN_EMAIL, ["admin"])

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    code_verifier = secrets.token_urlsafe(50)

    resp = requests.get(
        f"{server}/oauth2/authorize",
        params={
            "response_type": ResponseTypes.CODE,
            "client_id": client_id,
            "code_challenge": code_verifier,
            "code_challenge_method": CodeChallengeMethods.PLAIN,
            "redirect_uri": server,
            "scope": "read openid",
            "state": "extradata",
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
        allow_redirects=False,
    )
    print(resp.text)
    data = resp.headers["Location"]
    parsed_url = urlparse(data)
    assert "code=" in data
    assert "state=extradata" in data
    assert server in data
    code = parse_qs(parsed_url.query)["code"][0]
    assert code is not None

    resp = requests.post(
        f"{server}/token",
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
            "grant_type": GrantTypes.AUTHORIZATION_CODE.value,
            "redirect_uri": server,
            "scopes": "read openid",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    data = resp.json()
    scopes = ["read", "openid"]
    token = data.get("access_token")
    assert data.get("id_token") is not None
    assert token is not None
    assert data.get("scopes") == scopes
    resp = requests.get(
        f"{server}/userinfo",
        timeout=1,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.json() == {
        "id_": client_id,
        "type": "confidential",
        "name": "client1",
        "description": "a test client",
        "scopes": ["admin", "read", "write", "openid", "email", "profile"],
        "redirect_uris": ["http://0.0.0.0:8000"],
        "grant_types": ["authorization_code", "implicit"],
    }


def test_authorization_code_flow_no_openid_s265_chal_method(
    server,
):  # pylint: disable=redefined-outer-name
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code
    4. send token request with authorization code to get client token
    """
    data = make_test_client(server)
    token = get_token(server, ADMIN_EMAIL, ["admin"])

    code_verifier = secrets.token_urlsafe(50)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    resp = requests.get(
        f"{server}/oauth2/authorize",
        params={
            "response_type": ResponseTypes.CODE,
            "client_id": client_id,
            "redirect_uri": server,
            "code_challenge": code_challenge,
            "code_challenge_method": CodeChallengeMethods.S256,
            "scope": "read",
            "state": "extradata",
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=1,
        allow_redirects=False,
    )
    data = resp.headers["Location"]
    parsed_url = urlparse(data)
    assert "code=" in data
    assert "state=extradata" in data
    assert server in data
    code = parse_qs(parsed_url.query)["code"][0]
    assert code is not None
    resp = requests.post(
        f"{server}/token",
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
            "grant_type": GrantTypes.AUTHORIZATION_CODE.value,
            "redirect_uri": server,
            "scope": "read",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    data = resp.json()
    assert data.get("id_token") is None
    assert data.get("access_token") is not None
    assert data.get("scopes") == ["read"]
