from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
from saml.adhoc.router import adhoc_saml_router
from saml.pysaml.router import pysaml_saml_router

from utils import get_env_value


app = FastAPI()

PORT = int(get_env_value("PORT"))


@app.get("/")
async def health():
    return JSONResponse(content={"health": "Super healthy!"})


if True:
    app.include_router(adhoc_saml_router)
else:
    app.include_router(pysaml_saml_router)

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=PORT,
        reload=True,
        log_level="info",
    )
