"""
User Endpoint Schemas
"""

from pydantic import BaseModel

from ....schemas import Alg


class UserScopesBody(BaseModel):
    """Add user scope request body"""

    username: str
    scope: str


class UserUpdateBody(BaseModel):
    """Update user request body"""

    username: str
    password: str


class UserAddBody(BaseModel):
    """add user request body"""

    username: str
    password: str
    alg: Alg = Alg.EC
    scopes: list[str]
