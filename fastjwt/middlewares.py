from starlette.middleware.authentication import AuthenticationMiddleware

from fastjwt.auth import JWTAuthenticationBackend
from fastjwt.core import JWTCore


class JWTAuthenticationMiddleware(AuthenticationMiddleware):
    def __init__(self, jwt_core: JWTCore, *args, **kwargs):
        self.core = jwt_core
        super().__init__(*args, **kwargs, backend=JWTAuthenticationBackend(self.core))
