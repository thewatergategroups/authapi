# pylint: disable=redefined-outer-name
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
from sqlalchemy import select

from authapi.api.endpoints.oidc.schemas import (
    CodeChallengeMethods,
    GrantTypes,
    ResponseTypes,
)
from authapi.api.tools import blake2b_hash
from authapi.database.models import SessionModel
from authapi.settings import get_settings

from .conftest import server, session  # pylint: disable=unused-import
from .helpers import add_scope_to_role, create_client, get_token, delete_scope_from_role

ADMIN_EMAIL = "admin@email.com"


def test_get_token(server, session):
    """
    test getting a user token
    """
    scopes = ["admin", "read", "write"]
    id_token, session_id = get_token(server, ADMIN_EMAIL, scopes)
    fields = id_token.split(".")
    assert len(fields) == 3
    token_info = json.loads(b64decode(fields[1] + "==").decode())
    assert session_id is not None
    assert token_info["sub"] == ADMIN_EMAIL
    assert token_info["aud"] == "local"
    assert token_info["iss"] == get_settings().jwt_config.jwks_server_url
    sess_model = session.scalar(
        select(SessionModel).where(SessionModel.id_ == blake2b_hash(session_id))
    )
    assert sess_model is not None
    assert sess_model.scopes == ["admin", "read", "write"]


def test_get_token_disallowed_scope(server, session):
    """
    test getting a user token where one of the scopes is disallowed
    """

    delete_scope_from_role(server, ADMIN_EMAIL, ["admin"], "admin", "write")
    scopes = ["admin", "read", "write"]
    id_token, session_id = get_token(server, ADMIN_EMAIL, scopes)
    fields = id_token.split(".")
    assert len(fields) == 3
    token_info = json.loads(b64decode(fields[1] + "==").decode())
    assert token_info["sub"] == ADMIN_EMAIL
    assert token_info["aud"] == "local"
    assert token_info["iss"] == get_settings().jwt_config.jwks_server_url
    sess_model = session.scalar(
        select(SessionModel).where(SessionModel.id_ == blake2b_hash(session_id))
    )
    assert sess_model is not None
    assert sess_model.scopes == ["admin", "read"]
    add_scope_to_role(server, ADMIN_EMAIL, ["admin"], "admin", "write")


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


def test_get_client_token(server):
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


def authorize(
    server,
    client_id: str,
    response_type: ResponseTypes,
    scope: str,
    extra_params: dict | None = None,
):
    """authorize request"""
    extra_params = extra_params or dict()
    _, session_id = get_token(server, ADMIN_EMAIL, ["admin"])
    resp = requests.get(
        f"{server}/oauth2/authorize",
        params={
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": server,
            "scope": scope,
            "state": "extradata",
            **extra_params,
        },
        cookies={"session_id": session_id},
        timeout=1,
        allow_redirects=False,
    )
    return resp, session_id


def test_authorization_token_flow(
    server,
):
    """
    test authorization token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a token using user credentials
    4. client token returned
    """
    data = make_test_client(server)
    resp, session_id = authorize(
        server, data.get("client_id"), ResponseTypes.TOKEN, "read"
    )
    data = resp.headers["Location"]
    assert "access_token=" in data
    assert "token_type=Bearer" in data
    assert "state=extradata" in data
    assert server in data
    resp = requests.get(
        f"{server}/session/status", cookies={"session_id": session_id}, timeout=1
    )
    assert resp.json() == {"session_active": True}
    resp = requests.post(
        f"{server}/logout", cookies={"session_id": session_id}, timeout=1
    )
    assert resp.status_code == 200
    resp = requests.get(
        f"{server}/session/status", cookies={"session_id": session_id}, timeout=1
    )
    assert resp.json() == {"session_active": False}


def test_authorization_id_token_flow(server):
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a id token using user credentials
    4. id token with information about user returned
    """
    data = make_test_client(server)
    resp, _ = authorize(
        server, data.get("client_id"), ResponseTypes.ID_TOKEN, "read openid"
    )
    data = resp.headers["Location"]
    assert "id_token=" in data
    assert "state=extradata" in data
    assert server in data


def test_authorization_code_flow_openid_plain_code_chal_method(
    server,
):
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code with the openid scope
    4. send token request with authorization code and openid scope to get client token and id token
    """
    data = make_test_client(server)

    client_id = data.get("client_id")
    scopes = ["read", "openid", "email"]
    client_secret = data.get("client_secret")
    code_verifier = secrets.token_urlsafe(50)
    resp, _ = authorize(
        server,
        data.get("client_id"),
        ResponseTypes.CODE,
        " ".join(scopes),
        {
            "code_challenge": code_verifier,
            "code_challenge_method": CodeChallengeMethods.PLAIN,
        },
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
            "scopes": " ".join(scopes),
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    data = resp.json()
    token = data.get("access_token")
    assert data.get("id_token") is not None
    assert data.get("refresh_token") is not None
    assert token is not None
    assert data.get("scopes") == scopes
    resp = requests.get(
        f"{server}/userinfo",
        timeout=1,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.json() == {"email": "admin@email.com"}


def test_authorization_code_flow_no_openid_s265_chal_method(
    server,
):
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code
    4. send token request with authorization code to get client token
    """
    data = make_test_client(server)

    code_verifier = secrets.token_urlsafe(50)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    resp, _ = authorize(
        server,
        client_id,
        ResponseTypes.CODE,
        "read",
        {
            "code_challenge": code_challenge,
            "code_challenge_method": CodeChallengeMethods.S256,
        },
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
    assert data.get("refresh_token") is not None
    assert data.get("scopes") == ["read"]


def test_authorization_code_flow_no_openid_no_code_challenge(
    server,
):
    """
    test authorization id token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code
    4. send token request with authorization code to get client token
    """
    data = make_test_client(server)

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    resp, _ = authorize(server, client_id, ResponseTypes.CODE, "read")

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
    assert data.get("refresh_token") is not None
    assert data.get("scopes") == ["read"]


def assert_token(
    server: str,
    resp: requests.Response,
    scopes: list[str],
    validate_refresh: bool = True,
):
    """assert response to request for token"""
    data = resp.json()
    assert data.get("scopes") == scopes
    token = data.get("access_token")
    assert data.get("id_token") is not None

    assert token is not None
    resp = requests.get(
        f"{server}/userinfo",
        timeout=1,
        headers={"Authorization": f"Bearer {token}"},
    )
    info = resp.json()
    info.pop("created_at")
    info.pop("dob")
    assert info == {
        "email": "admin@email.com",
        "first_name": "admin",
        "surname": "user",
        "postcode": "",
    }
    if validate_refresh:
        refresh_token = data.get("refresh_token")
        assert refresh_token is not None
        return refresh_token


def test_get_token_from_refresh_token_flow(server):
    """
    test refresh token flow
    Steps:
    1. make client
    2. authenticate user
    3. send Authorize request to get a authorization code with the openid scope
    4. send token request with authorization code and openid scope
       to get client token and id token and refresh token
    5. send request to get new token with refresh token
    """
    data = make_test_client(server)
    scopes = ["read", "openid", "email", "profile"]
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    code_verifier = secrets.token_urlsafe(50)
    resp, _ = authorize(
        server,
        client_id,
        ResponseTypes.CODE,
        " ".join(scopes),
        {
            "code_challenge": code_verifier,
            "code_challenge_method": CodeChallengeMethods.PLAIN,
        },
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
            "scopes": " ".join(scopes),
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    refresh_token = assert_token(server, resp, scopes)
    resp = requests.post(
        f"{server}/token",
        data={
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GrantTypes.REFRESH_TOKEN.value,
            "redirect_uri": server,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=1,
    )
    assert_token(server, resp, scopes, False)
