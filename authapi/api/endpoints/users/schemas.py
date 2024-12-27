"""
User Endpoint Schemas
"""

from datetime import date

from pydantic import BaseModel

from ....schemas import Alg


class UserUpdateBody(BaseModel):
    """Update user request body"""

    email: str
    new_email: str | None = None
    password: str | None = None
    dob: date | None = None
    postcode: str | None = None
    first_name: str | None = None
    surname: str | None = None
    roles: list[str] | None = None


class UserAddBody(BaseModel):
    """add user request body"""

    email: str
    password: str
    dob: date
    postcode: str
    first_name: str
    surname: str
    alg: Alg = Alg.EC
    roles: list[str] | None = None


class AddUserRoleBody(BaseModel):
    """add user request body"""

    role_id: str
    user_id: str
