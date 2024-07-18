from jwt import InvalidTokenError, ExpiredSignatureError
from starlette.authentication import AuthenticationBackend, AuthCredentials, BaseUser
from starlette.requests import HTTPConnection

from fastjwt.core import JWTCore


class FastJWTUser(BaseUser):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)

    @property
    def is_authenticated(self) -> bool:
        return True


class JWTAuthenticationBackend(AuthenticationBackend):
    def __init__(self, jwt_core: JWTCore):
        self.core = jwt_core

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        access_token = conn.cookies.get("X-Access-Token", None)
        if access_token is None:
            return
        try:
            user_payload = self.core.verify_token(access_token)
        except (ExpiredSignatureError, InvalidTokenError):
            return
        auth_credentials = AuthCredentials(["authenticated"])
        user_instance = FastJWTUser(**user_payload)
        return auth_credentials, user_instance
