"""
Public endpoint Schemas
"""

from fastapi import Form
from pydantic import BaseModel

from ....schemas import Alg


class UserLoginBody(BaseModel):
    """User login request body"""

    email: str
    password: str
    scope: str | None
    alg: Alg = Alg.EC
    redirect_url: str | None

    @classmethod
    def as_form(
        cls,
        email: str = Form(...),
        password: str = Form(...),
        scope: str | None = Form(None),
        alg: Alg = Form(Alg.EC),
        redirect_url: str | None = Form(None),
    ):
        """Allows use of this model as form data in an endpoint"""
        return cls(
            email=email,
            password=password,
            scope=scope,
            alg=alg,
            redirect_url=redirect_url,
        )
