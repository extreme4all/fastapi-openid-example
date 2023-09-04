import httpx  # httpx > aiohttp because httpx is used in depending lib
import jwt
from jwt.jwks_client import PyJWKClient
from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App
from fastapi import FastAPI
from pydantic_settings import BaseSettings
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request


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


async def fetch_jwt_key(key_url, kid):
    async with httpx.AsyncClient() as client:
        response = await client.get(key_url)
        keys = response.json()

    # Find the key with the matching 'kid' (Key ID)
    for key in keys.get("keys", []):
        if key.get("kid") == kid:
            return key

    return None


async def validate_token(token, audience, issuer, jwks_uri):
    print("local validation")
    try:
        jwks_client = PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Validate the token using the fetched key
        decoded_token = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],  # Specify the algorithm used for signing
            audience=audience,
            issuer=issuer,
        )

        return decoded_token
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token signature"}
    except Exception as e:
        return {"error": str(e)}


# the simplest way
async def token_introspect(access_token, introspection_url):
    print("introspect")
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
    # this should also do all the checking ???
    token: dict = await oauth.authorize_access_token(request)
    access_token: str = token.get("access_token")
    id_token: str = token.get("id_token")
    userinfo: dict = token.get("userinfo")

    # Validate the tokens
    # introspect
    # access token
    resp: dict = await token_introspect(
        access_token, settings.metadata.get("introspection_endpoint")
    )
    if not resp.get("active"):
        return {
            "error": "Access token is not valid",
            "access_token_info": resp,
            "token": token,
        }

    # id token
    resp: dict = await token_introspect(
        id_token, settings.metadata.get("introspection_endpoint")
    )
    if not resp.get("active"):
        return {
            "error": "Access token is not valid",
            "access_token_info": resp,
            "token": token,
        }

    # local token validation
    # access token
    resp = await validate_token(
        access_token,
        jwks_uri=settings.metadata.get("jwks_uri"),
        audience="api://default",
        issuer=settings.metadata.get("issuer"),
    )
    if resp.get("error"):
        return {
            "error": "Access token is not valid",
            "access_token_info": resp.get("error"),
            "token": token,
        }

    # id token
    resp = await validate_token(
        id_token,
        jwks_uri=settings.metadata.get("jwks_uri"),
        audience=settings.client_id,
        issuer=settings.metadata.get("issuer"),
    )
    if resp.get("error"):
        return {
            "error": "Access token is not valid",
            "access_token_info": resp.get("error"),
            "token": token,
        }
    return dict(token)


@app.get("/home")
async def home():
    return {"page": "home"}


@app.get("/")
async def public():
    return {"page": "public"}
