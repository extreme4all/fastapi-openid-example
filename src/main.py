import time

import httpx  # httpx > aiohttp because httpx is used in depending lib
from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App
from authlib.jose import JoseError, jwt
from fastapi import FastAPI
from pydantic_settings import BaseSettings
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
import asyncio


class Settings(BaseSettings):
    client_id: str
    client_secret: str
    metadata_url: str
    metadata: dict = {}


settings = Settings()
oauth = OAuth()

oauth.register(
    name="okta",
    overwrite=True,
    server_metadata_url=settings.metadata_url,
    client_id=settings.client_id,
    client_secret=settings.client_secret,
    client_kwargs={"scope": "openid email profile"},
)

oauth: StarletteOAuth2App = oauth.okta


app = FastAPI()

# we need this to save temporary code & state in session
app.add_middleware(SessionMiddleware, secret_key="some-random-string-qsdfqsdf")


# the simplest way
async def token_introspect(access_token, introspection_url):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            introspection_url,
            data={"token": access_token},
            auth=(settings.client_id, settings.client_secret),
        )
        return response.json()


@app.on_event("startup")
async def fetch_config():
    global settings
    async with httpx.AsyncClient() as client:
        response = await client.get(settings.metadata_url)
        config = response.json()

    # Update settings with fetched configuration data
    settings.metadata = config


@app.get("/login")
async def login_via_google(request: Request):
    redirect_uri = request.url_for("callback")
    return await oauth.authorize_redirect(request, redirect_uri)


@app.get("/callback")
async def callback(request: Request):
    token: dict = await oauth.authorize_access_token(request)
    access_token = token.get("access_token")
    id_token = token.get("id_token")
    userinfo = token.get("userinfo")

    # Validate the access token
    access_token_info: dict = await token_introspect(
        access_token, settings.metadata.get("introspection_endpoint")
    )
    if not access_token_info.get("active"):
        return {
            "error": "Access token is not valid",
            "access_token_info": access_token_info,
            "token": token,
        }

    return dict(token)


@app.get("/home")
async def home():
    return {"page": "home"}


@app.get("/")
async def public():
    return {"page": "public"}
