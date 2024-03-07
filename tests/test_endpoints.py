import json
from authapi.schemas import Alg
from .conftest import client
from authapi.api.endpoints.public.schemas import UserLoginBody
from base64 import b64decode


def test_get_token(client):
    username = "admin"
    scopes = ["admin", "read", "write"]
    response = client.post(
        "/public/login",
        json=UserLoginBody(
            username=username,
            password="password",
            scopes=scopes,
            alg=Alg.EC,
        ).dict(),
    )
    data = response.json()
    token = data.get("token", "")
    fields = token.split(".")
    assert len(fields) == 3
    token_info = json.loads(b64decode(fields[1] + "==").decode())
    assert token_info["sub"] == username
    assert token_info["aud"] == "local"
    assert token_info["iss"] == "authapi"
    assert token_info["scopes"] == scopes
    return token
