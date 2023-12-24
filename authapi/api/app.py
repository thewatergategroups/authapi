from fastapi import FastAPI

from .endpoints.public import router as pub_router
from .endpoints.users import router as users_router
from .endpoints.scopes import router as scopes_router

from fastapi.middleware.cors import CORSMiddleware
from ..tools import setup_logging
from ..settings import get_settings


def create_app() -> FastAPI:
    """
    create and return fastapi app
    """
    setup_logging(get_settings())
    app = FastAPI(
        title="Auth Api",
        description="Jwks Authentication API",
        version="1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(pub_router)
    app.include_router(users_router)
    app.include_router(scopes_router)

    return app
