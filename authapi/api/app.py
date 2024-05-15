"""
Create the FastApi application.
1. Add routes
2. Add middlewares
3. setup logging
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from yumi import setup_logging

from ..settings import get_settings
from .endpoints import oidc, password, public, scopes


def create_app() -> FastAPI:
    """
    create and return fastapi app
    """
    setup_logging(get_settings().log_config)
    app = FastAPI(
        title="Auth Api",
        description="Jwks Authentication API",
        version="1.0",
        docs_url=None,
        redoc_url=None,
    )
    origins = ["null", get_settings().jwt_config.jwks_server_url]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(public.router)
    app.include_router(scopes.router)
    app.include_router(password.router)
    app.include_router(oidc.router)
    app.mount("/static", StaticFiles(directory="static"), name="static")
    return app
