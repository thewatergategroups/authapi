"""
Role Endpoint Schemas
"""

from pydantic import BaseModel


class RoleScopesBody(BaseModel):
    """Add user scope request body"""

    role_id: str
    scope_id: str


class RoleAddBody(BaseModel):
    """Initial role add body"""

    role_id: str
    scopes: list[str]
