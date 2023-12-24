from pydantic import BaseModel


class UserScopesData(BaseModel):
    username: str
    scope: str


class AuthData(BaseModel):
    username: str
    password: str


class ScopeData(BaseModel):
    scope: str
