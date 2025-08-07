from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import JSONResponse
import httpx
from urllib.parse import urlencode
import uuid

from utils import get_env_value

# Application Configuration
HOST = get_env_value("HOST")

# Okta OpenID Connect Configuration
OKTA_DOMAIN = get_env_value("OKTA_DOMAIN_OIDC")
OKTA_OIDC_CLIENT_ID = get_env_value("OKTA_OIDC_CLIENT_ID")
OKTA_OIDC_CLIENT_SECRET = get_env_value("OKTA_OIDC_CLIENT_SECRET")
OKTA_REDIRECT_URI = f"{HOST}/openid/callback"

# Okta OpenID Connect Endpoints
OKTA_AUTHORIZATION_ENDPOINT = f"{OKTA_DOMAIN}/oauth2/v1/authorize"
OKTA_TOKEN_ENDPOINT = f"{OKTA_DOMAIN}/oauth2/v1/token"
OKTA_USERINFO_ENDPOINT = f"{OKTA_DOMAIN}/oauth2/v1/userinfo"

adhoc_openid_router = APIRouter()


@adhoc_openid_router.get("/openid/login")
async def openid_login():
    """Initiate OpenID Connect login with Okta"""
    # Build authorization URL directly
    params = {
        "client_id": OKTA_OIDC_CLIENT_ID,
        "redirect_uri": OKTA_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": str(uuid.uuid4()),
        "nonce": str(uuid.uuid4()),
    }

    authorization_url = f"{OKTA_AUTHORIZATION_ENDPOINT}?{urlencode(params)}"

    return JSONResponse(content={"redirect_url": authorization_url})


@adhoc_openid_router.get("/openid/callback")
async def openid_callback(
    code: str = Query(..., description="Authorization code from Okta"),
    state: str = Query(..., description="State parameter for CSRF protection"),
):
    """Handle OpenID Connect callback from Okta"""
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Build token request data directly
    token_data = {
        "client_id": OKTA_OIDC_CLIENT_ID,
        "client_secret": OKTA_OIDC_CLIENT_SECRET,
        "code": code,
        "redirect_uri": OKTA_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                OKTA_TOKEN_ENDPOINT,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_response = response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")

    # Extract tokens
    access_token = token_response.get("access_token")
    id_token = token_response.get("id_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="No access token received")

    # Build userinfo request headers directly
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                OKTA_USERINFO_ENDPOINT,
                headers=headers,
            )
            response.raise_for_status()
            user_info = response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=400, detail=f"Userinfo request failed: {e}")

    # Return the complete authentication result
    return JSONResponse(
        content={
            "access_token": access_token,
            "id_token": id_token,
            "user_info": user_info,
            "token_response": token_response,
        }
    )


@adhoc_openid_router.get("/openid/userinfo")
async def openid_userinfo(request: Request):
    """Get user information using access token from Authorization header"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid Authorization header"
        )

    access_token = auth_header.split(" ")[1]

    # Build userinfo request headers directly
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                OKTA_USERINFO_ENDPOINT,
                headers=headers,
            )
            response.raise_for_status()
            user_info = response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=401, detail=f"Invalid access token: {e}")

    return JSONResponse(content=user_info)


@adhoc_openid_router.get("/openid/.well-known/openid_configuration")
async def openid_configuration():
    """Serve OpenID Connect discovery document"""
    config = {
        "issuer": f"{OKTA_DOMAIN}",
        "authorization_endpoint": OKTA_AUTHORIZATION_ENDPOINT,
        "token_endpoint": OKTA_TOKEN_ENDPOINT,
        "userinfo_endpoint": OKTA_USERINFO_ENDPOINT,
        "jwks_uri": f"{OKTA_DOMAIN}/oauth2/v1/keys",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "claims_supported": [
            "sub",
            "iss",
            "name",
            "email",
            "email_verified",
            "picture",
        ],
        "code_challenge_methods_supported": ["S256"],
    }

    return JSONResponse(content=config)


@adhoc_openid_router.get("/openid/logout")
async def openid_logout():
    """Initiate OpenID Connect logout"""
    # For Okta, we can redirect to the logout endpoint
    logout_url = f"{OKTA_DOMAIN}/oauth2/v1/logout"
    params = {
        "client_id": OKTA_OIDC_CLIENT_ID,
        "post_logout_redirect_uri": f"{HOST}/openid/logout/callback",
    }

    return JSONResponse(content={"logout_url": f"{logout_url}?{urlencode(params)}"})


@adhoc_openid_router.get("/openid/logout/callback")
async def openid_logout_callback():
    """Handle logout callback"""
    return JSONResponse(content={"message": "Successfully logged out"})
