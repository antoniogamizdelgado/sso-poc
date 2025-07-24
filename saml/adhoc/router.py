import base64
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from urllib.parse import urlencode
import uuid

from saml.adhoc.templates import (
    AuthnRequestTemplate,
    SPMetadataTemplate,
)
from utils import get_env_value

# Application Configuration
HOST = get_env_value("HOST")
SP_ENTITY_ID = f"{HOST}/saml/metadata"

# Okta SAML Configuration
OKTA_DOMAIN = get_env_value("OKTA_DOMAIN")
OKTA_SAML_APP_ID = get_env_value("OKTA_SAML_APP_ID")
OKTA_ACS_URL = f"{HOST}/saml/acs"

adhoc_saml_router = APIRouter()


@adhoc_saml_router.get("/saml/login")
async def saml_login():
    """Initiate SAML login with Okta"""
    auth_request = AuthnRequestTemplate.create(
        assertion_consumer_service_url=OKTA_ACS_URL,
        destination=f"{OKTA_DOMAIN}/{OKTA_SAML_APP_ID}/sso/saml",
        issuer=SP_ENTITY_ID,
    )

    encoded_request = base64.b64encode(auth_request.render().encode()).decode()

    okta_url = f"{OKTA_DOMAIN}/{OKTA_SAML_APP_ID}/sso/saml"
    params = {
        "SAMLRequest": encoded_request,
        "RelayState": str(uuid.uuid4()),  # Optional, sent back as form param
    }
    redirect_url = f"{okta_url}?{urlencode(params)}"

    return JSONResponse(content={"redirect_url": redirect_url})


@adhoc_saml_router.post("/saml/acs")
async def saml_acs(request: Request):
    """Handle SAML Assertion Consumer Service (ACS)"""
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")

    if not saml_response or not isinstance(saml_response, str):
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")

    decoded_response = base64.b64decode(saml_response).decode()

    return HTMLResponse(content=decoded_response, media_type="application/xml")


@adhoc_saml_router.get("/saml/metadata")
async def saml_metadata():
    """Generate SP metadata for Okta configuration"""

    template = SPMetadataTemplate.create(
        entity_id=SP_ENTITY_ID,
        assertion_consumer_service_url=OKTA_ACS_URL,
    )
    metadata = template.render()
    return HTMLResponse(content=metadata, media_type="application/xml")
