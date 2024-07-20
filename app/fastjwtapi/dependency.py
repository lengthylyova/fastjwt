from fastapi import HTTPException
from fastapi import status, Depends
from fastapi.requests import Request
from jwt import ExpiredSignatureError, InvalidTokenError

from .core import JWTCore


class JWTDependency:
    def __init__(self, jwt_core: JWTCore):
        self.core = jwt_core

    def x_access_token_cookie(self):
        def inner_logic(request: Request):
            token = request.cookies.get("X-Access-Token", None)
            if token is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="X-Access-Token not provided"
                )
            try:
                self.core.verify_token(token)
            except (ExpiredSignatureError, InvalidTokenError) as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid X-Access-Token cookie: {e.__repr__()}"
                )

        return Depends(inner_logic)
