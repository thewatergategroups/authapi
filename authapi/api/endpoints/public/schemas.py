"""
Public endpoint Schemas
"""

from fastapi import Form
from pydantic import BaseModel

from ....schemas import Alg


class UserLoginBody(BaseModel):
    """User login request body"""

    username: str
    password: str
    scope: str | None
    alg: Alg = Alg.EC

    @classmethod
    def as_form(
        cls,
        username: str = Form(...),
        password: str = Form(...),
        scope: str = Form(None),
        alg: Alg = Form(Alg.EC),
    ):
        """Allows use of this model as form data in an endpoint"""
        return cls(
            username=username,
            password=password,
            scope=scope,
            alg=alg,
        )
