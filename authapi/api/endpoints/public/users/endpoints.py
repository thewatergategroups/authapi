"""
Public endpoints for authentication and authorization
"""

from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Header, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRouter
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import NotAuthorized, Scopes


from .....database.models import (
    RoleScopeMapModel,
    UserModel,
    UserRoleMapModel,
    SessionModel,
)
from .....deps import get_async_session, get_templates
from .....settings import get_settings
from ....tools import blake2b_hash
from ....validator import (
    session_status,
    validate_session,
)

from .schemas import UserLoginBody
from .helpers import build_user_token
from ..helpers import redirect_on_unauthorized

router = APIRouter(tags=["Users Public"])


@router.get("/logged_in", response_class=HTMLResponse)
async def get_logged_in(request: Request, _=Depends(validate_session)):
    """Serve logged in page"""
    return get_templates().TemplateResponse("logged_in.html", {"request": request})


@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request, redirect_url: str = None, rd: str = None):
    """Serve login page"""
    return get_templates().TemplateResponse(
        "login.html",
        {"request": request, "redirect_url": redirect_url or rd or "/logged_in"},
    )


@router.post("/login")
async def login(
    request: Request,
    data: UserLoginBody = Depends(UserLoginBody.as_form),
    user_agent: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Returns a user token for a user who authenticated with a username and password
    """
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(
            UserModel.email == data.email, UserModel.pwd_hash == passwd
        )
    )
    if not us_exists:
        redirect_on_unauthorized("username or password incorrect", data.redirect_url)

    user_id = await UserModel.select_id_from_email(data.email, session)
    roles = await UserRoleMapModel.get_user_roles(user_id, session)
    scopes = (
        await session.scalars(RoleScopeMapModel.get_roles_scopes_stmt(roles))
    ).all()
    allowed_scopes = scopes
    if data.scope is not None:
        allowed_scopes = [scope for scope in data.scope.split(" ") if scope in scopes]

    if not allowed_scopes:
        redirect_on_unauthorized(
            "user does not have any of the requested scope", data.redirect_url
        )
    if user_agent is None:
        redirect_on_unauthorized("user agent must be present", data.redirect_url)

    session_id, expires_at = await SessionModel.insert(
        user_id, request.client.host, user_agent, allowed_scopes, session
    )
    groups = None
    if Scopes.GROUPS in allowed_scopes:
        groups = roles
    id_token = build_user_token(data.email, alg=data.alg, groups=groups)
    token = build_user_token(
        data.email, alg=data.alg, groups=groups, scopes=allowed_scopes
    )
    response = JSONResponse(dict(access_token=token), 200)
    domain = get_settings().jwt_config.jwks_server_url.split(".", 1)[1]
    response.set_cookie(
        "session_id",
        session_id,
        expires=expires_at,
        secure=True,
        # httponly=True,
        domain=domain,
    )
    if data.redirect_url:
        response.status_code = 303
        response.headers["Location"] = data.redirect_url
    response.set_cookie(
        "id_token",
        id_token,
        expires=expires_at,
        secure=True,
        # httponly=True,
        domain=domain,
    )
    return response


@router.post("/logout")
async def logout(
    session_id: Annotated[str | None, Cookie()] = None,
    session: AsyncSession = Depends(get_async_session),
    _=Depends(validate_session),
):
    """Log out of the application"""
    await SessionModel.delete(session_id, session)
    return {"detail": "Success"}


@router.get("/session/status")
async def get_session_status(
    session_id: Annotated[str | None, Cookie()] = None,
    session: AsyncSession = Depends(get_async_session),
):
    """Check the status of the currently active session"""
    try:
        await session_status(session_id, session)
        return dict(detail="success")
    except NotAuthorized as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED) from exc


@router.get("/iframe-js", response_class=Response)
def iframe_js():
    """Get session checking javascript to be run the in the browser"""
    js_code = (
        """
        window.addEventListener('message', function(event) {
        """
        + f"""
            if (event.origin !== "{get_settings().jwt_config.jwks_server_url}") {{
        """
        + """
                return; // }Ignore messages from untrusted origins
            }
            if (event.data.action === 'checkStatus') {
                checkStatus(); // Function that checks the session status
            }
        });
        // Function to simulate a session check
        function checkStatus() {
            console.log('Checking status within iframe');
        """
        + f"""
            fetch('{get_settings().jwt_config.jwks_server_url}/session/status', {{ credentials: 'include' }})
        """
        + """
                .then(response => response.json())
                .then(data => {
                    if (!data.session_active) {
        """
        + f"""
                            window.location.href = '{get_settings().jwt_config.jwks_server_url}/login';
        """
        + """
                            console.log('Session is inactive, please log in again.');
                    } else {
                        console.log('Session is active, no action needed.');
                    }
                })
                .catch(error => {
                    console.error('Failed to retrieve session status:', error);
                    // Handle errors, e.g., notify parent
                });
        }

        // Expose the checkStatus function to the parent window
        window.checkStatus = checkStatus;

        // Optionally check status when iframe loads
        window.onload = checkStatus;
    """
    )
    return Response(content=js_code, media_type="application/javascript")
