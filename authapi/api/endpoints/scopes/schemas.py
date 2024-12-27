"""
Scope Endpoints Schemas
"""

from pydantic import BaseModel


class ScopeBody(BaseModel):
    """Add scope request body"""

    id_: str
