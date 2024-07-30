from starlette.middleware.authentication import AuthenticationMiddleware

from .auth import JWTAuthenticationBackend
from .core import JWTCore


class JWTAuthenticationMiddleware(AuthenticationMiddleware):
    def __init__(self, jwt_core: JWTCore, *args, **kwargs):
        self.core = jwt_core
        super().__init__(
            *args, **kwargs, backend=JWTAuthenticationBackend(self.core)
        )
