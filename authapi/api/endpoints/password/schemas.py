"""
User Endpoint Schemas
"""

from datetime import date

from pydantic import BaseModel

from ....schemas import Alg


class RoleScopesBody(BaseModel):
    """Add user scope request body"""

    role_id: str
    scope_id: str


class RoleAddBody(BaseModel):
    """Initial role add body"""

    role_id: str
    scopes: list[str]


class UserUpdateBody(BaseModel):
    """Update user request body"""

    email: str
    new_email: str | None = None
    password: str | None = None
    dob: date | None = None
    postcode: str | None = None
    first_name: str | None = None
    surname: str | None = None


class UserAddBody(BaseModel):
    """add user request body"""

    email: str
    password: str
    dob: date
    postcode: str
    first_name: str
    surname: str
    alg: Alg = Alg.EC


class AddUserRoleBody(BaseModel):
    """add user request body"""

    role_id: str
    user_id: str
