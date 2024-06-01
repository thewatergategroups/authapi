"""
Helper Functions
"""

from datetime import datetime, timedelta
import jwt
from yumi import Jwt

from .....settings import get_settings
from .....schemas import Alg


def build_user_token(
    email: str,
    scopes: list[str] | None = None,
    alg: Alg = Alg.EC,
    audience: str = "local",
    nonce: str | None = None,
    groups: list[str] | None = None,
):
    """Function to creates a user token based on the passed in information"""
    now = datetime.now()
    payload = Jwt(
        sub=email,
        nonce=nonce,
        exp=(now + timedelta(hours=1)).timestamp(),
        aud=audience,
        iss=get_settings().jwt_config.jwks_server_url,
        iat=now.timestamp(),
        groups=groups,
    )
    if scopes is not None:
        payload.scopes = scopes
    return jwt.encode(
        payload.model_dump(exclude_none=True),
        alg.load_private_key(),
        algorithm=alg.value,
        headers={"kid": alg.load_public_key()["kid"]},
    )
