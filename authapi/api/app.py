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

routers = [public.router, scopes.router, password.router, oidc.router]


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
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https://.*\.thewatergategroups\.com",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    for router in routers:
        app.include_router(router)
    app.mount("/static", StaticFiles(directory="static"), name="static")

    return app
