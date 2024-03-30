"""
User Endpoint Schemas
"""

from datetime import datetime
from pydantic import BaseModel

from ....schemas import Alg


class RoleScopesBody(BaseModel):
    """Add user scope request body"""

    role_id: str
    scope: str


class RoleAddBody(BaseModel):
    """Initial role add body"""

    role_id: str
    scopes: list[str]


class UserUpdateBody(BaseModel):
    """Update user request body"""

    email: str
    password: str
    dob: datetime
    postcode: str
    first_name: str
    surname: str


class UserAddBody(UserUpdateBody):
    """add user request body"""

    alg: Alg = Alg.EC


class AddUserRoleBody(BaseModel):
    """add user request body"""

    role_id: str
    user_id: str
