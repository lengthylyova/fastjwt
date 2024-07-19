# FastJWTapi
## Installation
```commandline
pip install fastjwtapi
```

## Quick Guide
### JWTCore
`JWTCore` is the main class of the `fastjwtapi` package which allows
you to configure your JWT auth process.
```python
from fastjwtapi.core import JWTCore

jwt_core = JWTCore(
    user_model_class=User,
    auth_schema=UserLoginSchema,
    token_payload_fields=["id", "username", "is_active"],
    secret_key="your_insane_secret_key",
    get_db_func=get_db
    # you can also provide `algorithm`, `access_token_lifetime` and `refresh_token_lifetime`
)
```

### Router
Using the `JWTCore` instance you can build `fastapi.APIRouter` with pre-built
endpoints, such as `/login` and `/refresh`.
```python
from fastjwtapi.core import JWTCore
from fastapi import FastAPI

jwt_core = JWTCore(...)

app = FastAPI()
app.include_router(jwt_core.build_router("/auth"))
```

### Middleware
Using the middleware you can get from the token
the user fields specified in `JWTCore.token_payload_fields` using `request.user`.
```python
from fastapi import FastAPI
from fastapi.requests import Request
from fastjwtapi.core import JWTCore
from fastjwtapi.middlewares import JWTAuthenticationMiddleware

jwt_core = JWTCore(
    ...
    token_payload_fields=["id", "username"]
    ...
)

app = FastAPI()
app.add_middleware(JWTAuthenticationMiddleware, jwt_core=jwt_core)


@app.get("/")
def endpoint(request: Request):
    return {
        "id": request.user.id,
        "username": request.user.username,
    } 
```

## Customization example
For example: you store your users' passwords as a hash.
Your user model and authorization scheme might look like this:

```python
import datetime

from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, String, Integer, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
```

In this case, for the endpoints to work correctly, you need to customize the `JWTCore.verify_user_credentials` method.

```python
import hashlib

from fastapi import FastAPI
from fastjwtapi.core import JWTCore


def hash_example(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


class CustomJWTCore(JWTCore):
    def verify_user_credentials(self, db, credentials):
        credentials["hashed_password"] = hash_example(credentials["password"])
        del credentials["password"]
        return super().verify_user_credentials(db, credentials)

jwt_core = CustomJWTCore()

app = FastAPI()
app.include_router(jwt_core.build_router("/auth"))
```