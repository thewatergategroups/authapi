from pydantic import BaseModel
from ....schemas import Alg


class UserScopesBody(BaseModel):
    username: str
    scope: str


class UserUpdateBody(BaseModel):
    username: str
    password: str


class UserAddBody(BaseModel):
    username: str
    password: str
    alg: Alg = Alg.EC
    scopes: list[str]
