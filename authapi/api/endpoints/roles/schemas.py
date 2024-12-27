"""
Role Endpoint Schemas
"""

from pydantic import BaseModel


class RoleScopesBody(BaseModel):
    """Add user scope request body"""

    role_id: str
    scope_id: str


class RoleAddPatchBody(BaseModel):
    """Initial role add body"""

    id_: str
    scopes: list[str]
