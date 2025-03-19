from fastapi.requests import HTTPConnection
from starlette.authentication import AuthenticationBackend


class CustomJWTAuthenticationBackend(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        # Your authentication logic here
        return None
