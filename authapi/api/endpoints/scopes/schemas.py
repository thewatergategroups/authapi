from pydantic import BaseModel


class ScopeBody(BaseModel):
    scope: str
