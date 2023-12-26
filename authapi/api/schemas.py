from pydantic import BaseModel
from ..certificates import Alg


class UserScopesData(BaseModel):
    username: str
    scope: str


class AuthData(BaseModel):
    username: str
    password: str
    alg: Alg = Alg.EC
    scopes: list[str]


class ScopeData(BaseModel):
    scope: str


class Token(BaseModel):
    token: str
