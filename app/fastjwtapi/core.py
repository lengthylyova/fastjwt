import time
from typing import Any, List, Callable

import jwt
from fastapi import Depends, HTTPException, APIRouter, status
from fastapi.requests import Request
from fastapi.responses import Response
from sqlalchemy.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.orm import Session


class JWTCore:
    def __init__(self,
                 user_model_class: Any,
                 token_payload_fields: List[str],
                 secret_key: str,
                 auth_schema: Any,
                 get_db_func: Callable,
                 algorithm: str = "HS256",
                 access_token_lifetime: int = 30,
                 refresh_token_lifetime: int = 86400):
        self.user_model_class = user_model_class
        self.token_payload_fields = token_payload_fields
        self.access_token_lifetime = access_token_lifetime
        self.refresh_token_lifetime = refresh_token_lifetime
        self.algorithm = algorithm
        self.secret_key = secret_key
        self.auth_schema = auth_schema
        self.get_db = get_db_func

    def build_router(self, prefix: str = "/auth", *args, **kwargs):
        router = APIRouter(prefix=prefix, *args, **kwargs)
        router.add_api_route(
            path="/login",
            endpoint=self._create_login_endpoint(),
            methods=["POST"],
        )
        router.add_api_route(
            path="/refresh",
            endpoint=self._create_refresh_endpoint(),
            methods=["POST"],
        )
        return router

    def _generate_token(self, payload: dict, lifetime: int) -> str:
        payload["exp"] = time.time() + lifetime
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def generate_access_token(self, payload: dict) -> str:
        return self._generate_token(payload, self.access_token_lifetime)

    def generate_refresh_token(self, payload: dict) -> str:
        return self._generate_token(payload, self.refresh_token_lifetime)

    def generate_token_pair(self, payload: dict) -> dict:
        return {
            "access": self.generate_access_token(payload),
            "refresh": self.generate_refresh_token(payload),
        }

    def get_user_payload(self, user: Any) -> dict:
        return {
            field: getattr(
                user, field, None
            ) for field in self.token_payload_fields
        }

    def verify_user_credentials(self, db: Session, credentials: dict):
        """Returns user obj if verified. Else raises Exception"""
        qs = db.query(self.user_model_class).filter_by(**credentials).all()
        if not qs:
            raise NoResultFound("Failed to verify user credentials")
        elif len(qs) > 1:
            raise MultipleResultsFound("Failed to verify user credentials")
        return qs[0]

    def verify_token(self, token: str) -> dict:
        """Returns token payload if verified. Else raises an Exception"""
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

    def _create_login_endpoint(self):
        auth_schema = self.auth_schema

        def login(credentials: auth_schema,
                  response: Response,
                  db: Session = Depends(self.get_db)):
            try:
                user = self.verify_user_credentials(
                    db, credentials.model_dump()
                )
            except (NoResultFound, MultipleResultsFound) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e)
                )

            user_payload = self.get_user_payload(user)
            response.set_cookie(
                key="X-Access-Token",
                value=self.generate_access_token(user_payload),
                max_age=self.access_token_lifetime,
            )
            response.set_cookie(
                key="X-Refresh-Token",
                value=self.generate_refresh_token(user_payload),
                max_age=self.refresh_token_lifetime,
            )
            return {"detail": "success"}

        return login

    def _create_refresh_endpoint(self):
        def refresh(request: Request, response: Response):
            token = request.cookies.get("X-Refresh-Token")
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="X-Refresh-Token cookie not set"
                )

            try:
                payload = self.verify_token(token)
            except jwt.DecodeError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid X-Refresh-Token cookie. {e.__repr__()}"
                )

            response.set_cookie(
                key="X-Access-Token",
                value=self.generate_access_token(payload),
                max_age=self.access_token_lifetime,
            )
            return {"detail": "success"}

        return refresh
