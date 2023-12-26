from pydantic import BaseModel
from ..schemas import Alg


class UserInfo(BaseModel):
    username: str
    scopes: list[str]


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
