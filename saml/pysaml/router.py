import base64
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from urllib.parse import urlencode
import uuid
from saml2.metadata import entity_descriptor


from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from utils import get_env_value
from saml2 import BINDING_HTTP_POST, NAMEID_FORMAT_EMAILADDRESS

# Application Configuration
HOST = get_env_value("HOST")
SP_ENTITY_ID = f"{HOST}/saml/metadata"

# Okta SAML Configuration
OKTA_DOMAIN = get_env_value("OKTA_DOMAIN")
OKTA_SAML_APP_ID = get_env_value("OKTA_SAML_APP_ID")
OKTA_ACS_URL = f"{HOST}/saml/acs"

pysaml_saml_router = APIRouter()


def create_saml_config():
    """
    Create SAML2 configuration for the service provider
    Docs: https://djangosaml2.readthedocs.io/contents/setup.html#pysaml2-specific-files-and-configuration
    """
    config = {
        "entityid": SP_ENTITY_ID,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(OKTA_ACS_URL, BINDING_HTTP_POST)]
                },
                "name_id_format": [NAMEID_FORMAT_EMAILADDRESS],
                "authn_requests_signed": False,
                "want_assertions_signed": True,
                "want_response_signed": True,
                "allow_unsolicited": True,  # security things we are ignoring!, IdP initiated SSO
            }
        },
        "key_file": None,
        "cert_file": None,
        "encryption_keypairs": [],
        "metadata": {
            "remote": [
                {
                    "url": "https://integrator-4805496.okta.com/app/exktrbk0piSNWitDm697/sso/saml/metadata"
                }
            ]
        },
        "valid_for": 24,
        "organization": {"display_name": "SSO POC", "name": "SSO POC", "url": HOST},
        "contact_person": [
            {
                "contact_type": "technical",
                "given_name": "Admin",
                "email_address": "admin@example.com",
            }
        ],
    }

    return Saml2Config().load(config)


saml_config = create_saml_config()


@pysaml_saml_router.get("/saml/login")
async def saml_login():
    """Initiate SAML login with Okta using pysaml2"""
    client = Saml2Client(saml_config)
    relay_state = str(uuid.uuid4())
    okta_sso_url = f"{OKTA_DOMAIN}/{OKTA_SAML_APP_ID}/sso/saml"

    _, authn_req = client.create_authn_request(
        entityid=SP_ENTITY_ID,
        destination=okta_sso_url,
        binding=BINDING_HTTP_POST,
        sign=False,
        relay_state=relay_state,  # this could also be a redirect url
    )

    encoded_request = base64.b64encode(str(authn_req).encode()).decode()

    redirect_url = f"{okta_sso_url}?{urlencode({'SAMLRequest': encoded_request, 'RelayState': relay_state})}"

    return JSONResponse(content={"redirect_url": redirect_url})


@pysaml_saml_router.post("/saml/acs")
async def saml_acs(request: Request):
    """Handle SAML Assertion Consumer Service (ACS) using pysaml2"""
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")

    if not saml_response or not isinstance(saml_response, str):
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")

    # Decode base64-encoded SAML XML
    decoded_xml = base64.b64decode(saml_response).decode("utf-8")

    return HTMLResponse(content=decoded_xml, media_type="application/xml")


@pysaml_saml_router.get("/saml/metadata")
async def saml_metadata():
    """Generate SP metadata for Okta configuration using pysaml2"""
    ed = entity_descriptor(saml_config)
    xml_bytes = ed.to_string()
    metadata_xml = (
        xml_bytes.decode("utf-8") if isinstance(xml_bytes, bytes) else str(xml_bytes)
    )
    return HTMLResponse(content=metadata_xml, media_type="application/xml")
