from pydantic import BaseModel
from yumi import Algorithms


class UserScopesData(BaseModel):
    username: str
    scope: str


class AuthUpdate(BaseModel):
    username: str
    password: str


class AuthData(BaseModel):
    username: str
    password: str
    alg: Algorithms = Algorithms.EC
    scopes: list[str]


class ScopeData(BaseModel):
    scope: str


class Token(BaseModel):
    token: str
