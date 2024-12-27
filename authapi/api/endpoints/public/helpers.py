"""
Helper Functions
"""

import logging
from fastapi import HTTPException, status


def redirect_on_unauthorized(message: str, redirect_url: str | None = None):
    """Helper function to redirect on unauthorized"""
    logging.error(message)
    url = (
        f"/login?unauthorized=true&redirect_url={redirect_url}"
        if redirect_url
        else "/login"
    )
    raise HTTPException(status.HTTP_303_SEE_OTHER, message, {"Location": url})
