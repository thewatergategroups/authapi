from pydantic import BaseModel
from ....schemas import Alg


class UserLoginBody(BaseModel):
    username: str
    password: str
    scopes: list[str]
    alg: Alg = Alg.EC
    redirext_uri: str | None = None
