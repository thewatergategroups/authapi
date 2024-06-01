"""
Public endpoints for authentication and authorization
"""

from fastapi.routing import APIRouter

from .....schemas import Alg

router = APIRouter(tags=["General Public"])


@router.get("/keys")
async def get_jwks():
    """
    Returns avaliable public keys
    No Authentication required
    """
    return dict(keys=Alg.get_public_keys())
